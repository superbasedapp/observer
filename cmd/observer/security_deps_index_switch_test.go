//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secfeed/online"
)

// security_deps_index_switch_test.go is the operator's ruling PT-19 (1),
// lane sec-deps4 item 1: the signed index download's off switch.

// switchConfig writes a config that selects security.deps with the switch
// at on.
func switchConfig(t *testing.T, path, db string, on bool) {
	t.Helper()
	body := "[observer]\ndb_path = " + strconv.Quote(db) + "\n[components]\nadd = [\"security.deps\"]\n[security.deps]\nonline = false\nindex_download = " + strconv.FormatBool(on) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestIndexDownloadSwitchOff: with the switch off a refresh fetches
// nothing from the feed and is not a failure, and every surface says the
// checks run with the index on disk; switched back on, the next refresh
// installs the index.
func TestIndexDownloadSwitchOff(t *testing.T) {
	srv, hits := feedServer(t, true)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	db := filepath.Join(dir, "observer.db")
	switchConfig(t, cfgPath, db, false)
	rt := &depsRuntime{configPath: cfgPath, client: func() *online.Client {
		eps := map[string]string{online.FeedHost: srv.URL, online.OSVHost: srv.URL}
		for _, e := range secfeed.Ecosystems() {
			eps[e.MetadataHost] = srv.URL
		}
		return online.New(online.Options{HTTP: srv.Client(), Endpoints: eps})
	}}
	if err := rt.feedOnce(context.Background()); err != nil {
		t.Fatalf("a refresh with the download off is not a failure: %v", err)
	}
	n := 0
	hits.Range(func(_, _ any) bool { n++; return true })
	if n != 0 {
		t.Fatalf("the download is off but the feed was asked %d path(s)", n)
	}
	st := depsContentStore(cfgPath)
	for _, k := range depsFeedKinds {
		if s, err := st.State(k.kind); err == nil && s.Accepted != nil {
			t.Errorf("%s installed with the download off", k.kind)
		}
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	writeDepsStatus(context.Background(), &b, cfg, cfgPath, filepath.Join(dir, "security"), true)
	if !strings.Contains(b.String(), "index download off") {
		t.Errorf("status does not say the download is off:\n%s", b.String())
	}
	dash := packageChecksDash(cfgPath, nil)
	if s, err := dash.Status(context.Background()); err != nil || s.IndexDownload {
		t.Errorf("card status %+v %v", s, err)
	}
	c := securityDepsDoctorCheck(context.Background(), cfgPath)
	if !strings.Contains(strings.Join(c.Details, "\n"), "index download off") || !strings.Contains(c.Message, "index download is off") {
		t.Errorf("doctor %+v", c)
	}

	switchConfig(t, cfgPath, db, true)
	if err := rt.feedOnce(context.Background()); err != nil {
		t.Fatalf("feed: %v", err)
	}
	for _, k := range depsFeedKinds {
		if s, err := st.State(k.kind); err != nil || s.Accepted == nil {
			t.Errorf("%s not installed once the download is on again: %v", k.kind, err)
		}
	}
	if s, _ := dash.Status(context.Background()); !s.IndexDownload {
		t.Error("card status still reads off")
	}
}

// TestIndexDownloadSwitchWakesTheLoop: a running feed loop that waits
// after a refresh with the switch off refreshes again soon after the
// switch is turned on, with no restart; while the switch stays off, or
// is turned off, it keeps waiting.
func TestIndexDownloadSwitchWakesTheLoop(t *testing.T) {
	old := depsFeedSwitchEvery
	depsFeedSwitchEvery = 10 * time.Millisecond
	t.Cleanup(func() { depsFeedSwitchEvery = old })
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	db := filepath.Join(dir, "observer.db")
	switchConfig(t, cfgPath, db, false)
	rt := &depsRuntime{configPath: cfgPath}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var woke atomic.Bool
	done := make(chan bool, 1)
	go func() {
		r := rt.waitFeed(ctx, time.Hour)
		woke.Store(true)
		done <- r
	}()
	time.Sleep(60 * time.Millisecond)
	if woke.Load() {
		t.Fatal("the loop woke with the switch still off")
	}
	// A change that keeps it off does not wake it.
	if err := os.WriteFile(cfgPath, append(mustRead(t, cfgPath), []byte("# touched\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if woke.Load() {
		t.Fatal("an unrelated change woke the loop")
	}
	switchConfig(t, cfgPath, db, true)
	select {
	case r := <-done:
		if !r {
			t.Fatal("waitFeed reported the context ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("turning the download on did not wake the loop")
	}
	// With the switch on, turning it off keeps the loop waiting (the next
	// refresh reads it before fetching).
	go func() { done <- rt.waitFeed(ctx, time.Hour) }()
	switchConfig(t, cfgPath, db, false)
	select {
	case <-done:
		t.Fatal("turning the download off woke the loop")
	case <-time.After(80 * time.Millisecond):
	}
	cancel()
	if r := <-done; r {
		t.Fatal("a cancelled wait reported a wake")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
