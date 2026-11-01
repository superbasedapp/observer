//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// hostedAdoptEnv registers a fake driver for provider (and E2B's key).
func hostedAdoptEnv(t *testing.T, provider string, env map[string]string) (string, *fakeBoxClient) {
	t.Helper()
	home := t.TempDir()
	setTestHome(t, home)
	obs := filepath.Join(home, ".observer")
	_ = os.MkdirAll(obs, 0o700)
	hostedTestEnv(t, env)
	c := newFakeBoxClient()
	old, had := hostedVendorRegs[provider]
	hostedVendorRegs[provider] = hostedVendorReg{vendor: provider, newClient: func(sandboxremote.Credential, string) (sandboxremote.Client, error) { return c, nil }}
	t.Cleanup(func() {
		if had {
			hostedVendorRegs[provider] = old
		} else {
			delete(hostedVendorRegs, provider)
		}
	})
	return obs, c
}

// stubAdoptSeams replaces the relay re-open and the guest PTY attach.
func stubAdoptSeams(t *testing.T) (reopened, attached *int) {
	t.Helper()
	r, a := 0, 0
	oldR, oldA := hostedAdoptReopen, hostedAdoptGuestPTY
	hostedAdoptReopen = func(context.Context, string, sandboxremote.Record, sandboxremote.Vendor, sandboxremote.Client, sandboxremote.Credential, io.Writer) (func(), string) {
		r++
		return func() {}, "the capture relay is re-opened with new keys"
	}
	hostedAdoptGuestPTY = func(context.Context, string, sandboxremote.Record, sandboxremote.Vendor, sandboxremote.Client, sandboxremote.Credential, io.Reader, io.Writer) (int, error) {
		a++
		return 0, nil
	}
	t.Cleanup(func() { hostedAdoptReopen, hostedAdoptGuestPTY = oldR, oldA })
	return &r, &a
}

// TestHostedGuestReattachHeldDark (SBX-UPD audit finding 2, orchestrator
// ruling): the Modal and Vercel rows hold GuestReattach false until REM-13 is
// checked live, so no run starts a keeper and a record saying the guest
// keeps the agent is not re-adopted.
func TestHostedGuestReattachHeldDark(t *testing.T) {
	for _, tc := range []struct {
		provider string
		env      map[string]string
	}{
		{sandboxremote.VendorModal, map[string]string{"MODAL_TOKEN_ID": "ak-fake", "MODAL_TOKEN_SECRET": "as-fake"}},
		{sandboxremote.VendorVercel, map[string]string{"VERCEL_TOKEN": "vt-fake", "VERCEL_TEAM_ID": "team_fake", "VERCEL_PROJECT_ID": "prj_fake"}},
	} {
		v, _ := sandboxremote.VendorFor(tc.provider)
		if v.GuestReattach || hostedGuestReattachOn(v) {
			t.Fatalf("%s: GuestReattach is on before REM-13", tc.provider)
		}
		obs, c := hostedAdoptEnv(t, tc.provider, tc.env)
		_, attached := stubAdoptSeams(t)
		ctx := context.Background()
		info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "g1"}})
		rec := sandboxremote.NewIntent("g1", tc.provider, v.DefaultEndpoint, "", "g1", time.Now(), time.Hour)
		rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
		rec.Extra = map[string]string{sandboxremote.ExtraGuestAttach: "1"}
		_ = hostedSaveRecord(obs, rec)
		if err := hostedAdopt(ctx, obs, "g1", strings.NewReader(""), &strings.Builder{}); err == nil || *attached != 0 {
			t.Fatalf("%s: re-adopted a run while the path is dark: %v", tc.provider, err)
		}
	}
}

// TestHostedAdoptGuestRowsBehindTheFlag (lane SBX-UPD, Modal and Vercel
// reattach, the dark path with the flag turned on): a guest PTY row's run is
// re-adopted only when its record says the guest helper keeps the agent;
// then the relay is re-opened, the PTY re-attached, the terminal says its
// scrollback is empty, and the box is deleted when the agent ends.
func TestHostedAdoptGuestRowsBehindTheFlag(t *testing.T) {
	saved := hostedGuestReattachOn
	hostedGuestReattachOn = func(v sandboxremote.Vendor) bool { return v.GuestPTY }
	t.Cleanup(func() { hostedGuestReattachOn = saved })
	for _, tc := range []struct {
		provider string
		env      map[string]string
	}{
		{sandboxremote.VendorModal, map[string]string{"MODAL_TOKEN_ID": "ak-fake", "MODAL_TOKEN_SECRET": "as-fake"}},
		{sandboxremote.VendorVercel, map[string]string{"VERCEL_TOKEN": "vt-fake", "VERCEL_TEAM_ID": "team_fake", "VERCEL_PROJECT_ID": "prj_fake"}},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			v, _ := sandboxremote.VendorFor(tc.provider)
			if !hostedGuestReattachOn(v) || !v.GuestPTY || v.Reattach {
				t.Fatalf("%s: guest reattach %v, guest PTY %v, vendor reattach %v", tc.provider, hostedGuestReattachOn(v), v.GuestPTY, v.Reattach)
			}
			obs, c := hostedAdoptEnv(t, tc.provider, tc.env)
			reopened, attached := stubAdoptSeams(t)
			ctx := context.Background()
			info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "g1"}})
			rec := sandboxremote.NewIntent("g1", tc.provider, v.DefaultEndpoint, "", "g1", time.Now(), time.Hour)
			rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
			_ = hostedSaveRecord(obs, rec)
			if err := hostedAdopt(ctx, obs, "g1", strings.NewReader(""), &strings.Builder{}); err == nil || *attached != 0 {
				t.Fatalf("adopted a run with no kept PTY: %v", err)
			}
			rec.Extra = map[string]string{sandboxremote.ExtraGuestAttach: "1"}
			_ = hostedSaveRecord(obs, rec)
			var out strings.Builder
			if err := hostedAdopt(ctx, obs, "g1", strings.NewReader(""), &out); err != nil {
				t.Fatal(err)
			}
			if *reopened != 1 || *attached != 1 {
				t.Fatalf("reopened %d, attached %d", *reopened, *attached)
			}
			for _, want := range []string{"scrollback before now is empty", "re-opened with new keys"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("notice %q lacks %q", out.String(), want)
				}
			}
			if !c.boxes[info.ID].deleted {
				t.Fatal("the box was not deleted when the agent ended")
			}
		})
	}
}

// TestHostedAdoptE2BReopensTheRelay: E2B adoption (native reattach) now
// re-opens the relay before it bridges the agent and says the scrollback is
// empty; it no longer says the relay is down.
func TestHostedAdoptE2BReopensTheRelay(t *testing.T) {
	obs, c := hostedAdoptEnv(t, sandboxremote.VendorE2B, map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_adopt"})
	reopened, _ := stubAdoptSeams(t)
	box, home := net.Pipe()
	c.reattach = func(id, pid string) (sandboxremote.Process, error) {
		done := make(chan int, 1)
		go func() {
			_, _ = box.Write([]byte("agent says hi\n"))
			_ = box.Close()
			done <- 0
		}()
		return &pipeProcess{c: home, done: done, pid: pid}, nil
	}
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "e1"}})
	rec := sandboxremote.NewIntent("e1", sandboxremote.VendorE2B, "https://api.e2b.app", "us-west-1", "e1", time.Now(), time.Hour)
	rec.VendorID, rec.State = info.ID, sandboxremote.StateRunning
	rec.Extra = map[string]string{"pty_pid": "42"}
	_ = hostedSaveRecord(obs, rec)
	var out strings.Builder
	if err := hostedAdopt(ctx, obs, "e1", strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	if *reopened != 1 || !strings.Contains(out.String(), "re-opened with new keys") || !strings.Contains(out.String(), "scrollback before now is empty") || !strings.Contains(out.String(), "agent says hi") {
		t.Fatalf("reopened %d, out %q", *reopened, out.String())
	}
	if strings.Contains(out.String(), "relay is down") {
		t.Fatalf("the old relay-down notice is still printed: %q", out.String())
	}
}

// TestHostedRekeyRelayRun: re-adoption re-keys the relay record (same run
// and attribution, new secrets), rebuilds it from the hosted record when
// the old one is gone, and refuses a record that names neither.
func TestHostedRekeyRelayRun(t *testing.T) {
	obs := t.TempDir()
	old, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: "k1", Tool: "claude-code", ProjectRoot: "/w", WorkspaceDir: "/w", Roots: []string{"/w"}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: "/w"})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, old); err != nil {
		t.Fatal(err)
	}
	rec := sandboxremote.Record{RunID: "k1"}
	fresh, err := hostedRekeyRelayRun(obs, rec)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.RunID != "k1" || fresh.Tool != "claude-code" || fresh.ProjectRoot != "/w" {
		t.Fatalf("fresh = %+v", fresh)
	}
	if bytes.Equal(fresh.BoxSecret, old.BoxSecret) || bytes.Equal(fresh.LinkSecret, old.LinkSecret) {
		t.Fatal("the relay was not re-keyed")
	}
	if got, err := sandboxrelayd.ReadRun(obs, "k1"); err != nil || !bytes.Equal(got.BoxSecret, fresh.BoxSecret) {
		t.Fatalf("stored record %v %v", got.RunID, err)
	}
	_ = sandboxrelayd.RemoveRun(obs, "k1")
	if _, err := hostedRekeyRelayRun(obs, rec); err == nil {
		t.Fatal("re-keyed a run whose records name no tool or workspace")
	}
	rec.Extra = map[string]string{sandboxremote.ExtraTool: "claude-code", sandboxremote.ExtraRoot: "/w"}
	if f, err := hostedRekeyRelayRun(obs, rec); err != nil || f.WorkspaceDir != "/w" {
		t.Fatalf("rebuilt = %+v %v", f, err)
	}
}

// TestHostedAdoptReopenAsksTheGuestToRekey: the real re-open re-keys the
// record, serves the run's host services and restarts the guest relay with
// --rekey; a relay that never comes up is said, never claimed; stopping
// it twice is safe and removes its relay record.
func TestHostedAdoptReopenAsksTheGuestToRekey(t *testing.T) {
	saved := hostedAdoptRelayWait
	hostedAdoptRelayWait = 300 * time.Millisecond
	t.Cleanup(func() { hostedAdoptRelayWait = saved })
	obs, c := hostedAdoptEnv(t, sandboxremote.VendorModal, map[string]string{"MODAL_TOKEN_ID": "ak-fake", "MODAL_TOKEN_SECRET": "as-fake"})
	ctx := context.Background()
	info, _ := c.Create(ctx, sandboxremote.BoxSpec{Labels: map[string]string{sandboxremote.LabelKey: "rk"}})
	v, _ := sandboxremote.VendorFor(sandboxremote.VendorModal)
	rec := sandboxremote.Record{
		RunID: "rk", Provider: sandboxremote.VendorModal, VendorID: info.ID,
		Extra: map[string]string{sandboxremote.ExtraTier: "none", sandboxremote.ExtraTool: "claude-code", sandboxremote.ExtraRoot: "/w"},
	}
	stop, note := hostedAdoptReopenLinux(ctx, obs, rec, v, c, sandboxremote.Credential{}, io.Discard)
	stop()
	stop()
	if !strings.Contains(note, "not re-opened") {
		t.Fatalf("note = %q, want the relay said not re-opened", note)
	}
	rekeyed := false
	for _, call := range c.calls {
		if strings.Contains(call, relayStdioFlag) && strings.Contains(call, guestRekeyFlag) {
			rekeyed = true
		}
	}
	if !rekeyed {
		t.Fatalf("no relay exec asked for --rekey: %v", c.calls)
	}
	// The adoption's relay record goes with its host services.
	if _, err := sandboxrelayd.ReadRun(obs, "rk"); err == nil {
		t.Fatal("the adoption left its relay record behind")
	}
}
