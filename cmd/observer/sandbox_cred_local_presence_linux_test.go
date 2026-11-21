//go:build linux && !sbo_omit_capture_proxy && !sbo_omit_terminals_sandbox_credentials && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/proxy"
	"github.com/marmutapp/superbased-observer/internal/sandboxcred"
)

// credCountingStore counts reads of a key's value.
type credCountingStore struct {
	*credTestStore
	gets atomic.Int64
}

func (s *credCountingStore) Get(name string) (string, error) {
	s.gets.Add(1)
	return s.credTestStore.Get(name)
}

// TestCredKeyPresenceReadsNoKey (F-010 A6): the presence check, and a local
// lane's setup, re-open and hosted setup that use it, never read a key's
// value from the keystore; presence follows the add and remove verbs.
func TestCredKeyPresenceReadsNoKey(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	cs := &credCountingStore{credTestStore: ks}
	old := credKeysFn
	credKeysFn = func(string) keystore.Store { return cs }
	t.Cleanup(func() { credKeysFn = old })
	live := true
	credLocalHelperLive(t, &live)

	if credKeyStored(obs, "anthropic") {
		t.Fatal("present before any key was added")
	}
	if err := credAdd(obs, "anthropic", credTestKey); err != nil {
		t.Fatal(err)
	}
	if !credKeyStored(obs, "anthropic") || credKeyStored(obs, "openai") || credKeyStored("", "anthropic") {
		t.Fatal("presence does not follow the add verb")
	}
	rig := newCredLocalRig(t, obs, "run-a6-presence", "127.0.0.1:1")
	if env := credLocalBoxEnv(rig.h, []string{"ANTHROPIC_API_KEY=" + credTestKey}); !sandboxcred.IsSentinel(env[0][len("ANTHROPIC_API_KEY="):]) {
		t.Fatalf("no lane: %v", env)
	}
	credLocalLanes.Delete(rig.run)
	if why := credLocalReopen(rig.h); why != "" {
		t.Fatalf("re-open: %s", why)
	}
	credRelayRecord(t, obs, "run-a6-hosted")
	if err := credSetup(context.Background(), credPlan(obs, "run-a6-hosted")); err != nil {
		t.Fatal(err)
	}
	if n := cs.gets.Load(); n != 0 {
		t.Fatalf("the presence path read a key %d time(s)", n)
	}
	if err := credRemove(obs, "anthropic"); err != nil {
		t.Fatal(err)
	}
	if credKeyStored(obs, "anthropic") {
		t.Fatal("present after the remove verb")
	}
}

// TestCredKeyListUnreadable (audit FU3-A4): a list that exists but is
// refused (not owner-only, or not JSON) is not read as "no key": the local
// lane is not opened and a warning says so, the hosted home_relay setup is
// refused naming the list; an absent list is simply no key.
func TestCredKeyListUnreadable(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if _, err := credKeyPresence(obs, "anthropic"); err != nil {
		t.Fatalf("an absent list is no error: %v", err)
	}
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	live := true
	credLocalHelperLive(t, &live)
	var logs syncBuffer // the default logger is process-wide: a relay goroutine from another test may write it (L-4)
	oldLog := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(oldLog) })
	for name, spoil := range map[string]func(string) error{
		"group-readable": func(p string) error { return os.Chmod(p, 0o644) },
		"not JSON":       func(p string) error { return os.WriteFile(p, []byte("{"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			logs.Reset()
			if err := credMarkProvider(obs, "anthropic", true); err != nil {
				t.Fatal(err)
			}
			if err := spoil(credProvidersFile(obs)); err != nil {
				t.Fatal(err)
			}
			if _, err := credKeyPresence(obs, "anthropic"); err == nil {
				t.Fatal("a refused list read as readable")
			}
			run := "run-a4-" + strings.ReplaceAll(name, " ", "-")
			rig := newCredLocalRig(t, obs, run, "127.0.0.1:1")
			in := []string{"ANTHROPIC_API_KEY=" + credTestKey}
			if got := credLocalBoxEnv(rig.h, in); !slices.Equal(got, in) || credLocalStamp(run) != nil {
				t.Fatalf("a lane opened on an unreadable list: %v", got)
			}
			if !strings.Contains(logs.String(), "cannot be read") {
				t.Fatalf("no warning: %q", logs.String())
			}
			credRelayRecord(t, obs, run+"-h")
			err := credSetup(context.Background(), credPlan(obs, run+"-h"))
			if err == nil || !strings.Contains(err.Error(), "cannot be read") {
				t.Fatalf("hosted setup on an unreadable list: %v", err)
			}
		})
	}
}

// TestCredKeyListStale (audit FU3-A4): a list that says a key is stored
// while the keystore has none (removed behind the verbs' back) fails
// closed: the local lane opens and the hosted setup succeeds, but the
// injector finds no key, so the sentinel goes upstream unswapped (401).
func TestCredKeyListStale(t *testing.T) {
	obs, ks := credEnvForTest(t, true)
	if err := ks.Set(sandboxcred.KeyName("anthropic"), credTestKey); err != nil {
		t.Fatal(err)
	}
	if err := ks.MemStore.Delete(sandboxcred.KeyName("anthropic")); err != nil { // behind the list's back
		t.Fatal(err)
	}
	if !credKeyStored(obs, "anthropic") {
		t.Fatal("the stale list should still read as stored")
	}
	live := true
	credLocalHelperLive(t, &live)
	rig := newCredLocalRig(t, obs, "run-a4-stale", "127.0.0.1:1")
	env := credLocalBoxEnv(rig.h, []string{"ANTHROPIC_API_KEY=" + credTestKey})
	sentinel := strings.TrimPrefix(env[0], "ANTHROPIC_API_KEY=")
	if !sandboxcred.IsSentinel(sentinel) {
		t.Fatalf("no lane: %v", env)
	}
	h := http.Header{}
	credLocalStamp(rig.run)(h)
	inj := &credInjector{observerDir: obs}
	if _, _, ok := inj.Inject(context.Background(), proxy.CredentialRequest{RunID: rig.run, Token: h.Get(sandboxcred.TokenHeader), Host: "api.anthropic.com", XAPIKey: sentinel}); ok {
		t.Fatal("injected with no key in the keystore")
	}
	credRelayRecord(t, obs, "run-a4-stale-h")
	if err := credSetup(context.Background(), credPlan(obs, "run-a4-stale-h")); err != nil {
		t.Fatalf("hosted setup on a stale list: %v", err)
	}
}
