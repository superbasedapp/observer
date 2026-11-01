//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/relaymux"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// terminal_sandbox_hosted_adopt_linux.go is the home side of re-adopting a
// hosted run whose helper is gone (lane SBX-UPD, sandbox plan v2 section
// 5.5): the capture relay is re-opened with new keys (a new relay run
// record under the same run id, its box record replaced in the box through
// the guest relay's --rekey), and on a guest PTY row the agent's PTY is
// re-attached through the guest attach verb. The terminal starts with an
// empty scrollback, and says so.

// hostedAdoptRelayWait bounds the wait for the re-opened relay.
var hostedAdoptRelayWait = 60 * time.Second

// hostedRekeyRelayRun replaces the run's relay record with one carrying new
// secrets (same run id, same attribution), or builds one from the hosted
// record's tool and root when the old one is gone. It returns the new
// record.
func hostedRekeyRelayRun(observerDir string, rec sandboxremote.Record) (sandboxrelayd.RunRecord, error) {
	base, err := sandboxrelayd.ReadRun(observerDir, rec.RunID)
	if err != nil {
		root, tool := rec.Extra[sandboxremote.ExtraRoot], rec.Extra[sandboxremote.ExtraTool]
		if root == "" || tool == "" {
			return sandboxrelayd.RunRecord{}, errors.New("the run's relay record is gone and the hosted record names no tool and workspace (a run from before re-adoption)")
		}
		cfgPath, _ := config.ResolveGlobalPath(daemonConfigPath())
		base = sandboxrelayd.RunRecord{RunID: rec.RunID, Tool: tool, ProjectRoot: root, WorkspaceDir: root, Roots: []string{root}, Delivery: sandboxrelayd.DeliveryCopy, CopyHostPath: root, ConfigPath: cfgPath}
	}
	fresh, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{
		RunID: base.RunID, Tool: base.Tool, ProjectRoot: base.ProjectRoot, WorkspaceDir: base.WorkspaceDir,
		Roots: base.Roots, Delivery: base.Delivery, CopyHostPath: base.CopyHostPath, ConfigPath: base.ConfigPath,
		TerminalRunID: base.TerminalRunID,
	})
	if err != nil {
		return sandboxrelayd.RunRecord{}, err
	}
	if err := sandboxrelayd.RemoveRun(observerDir, rec.RunID); err != nil {
		return sandboxrelayd.RunRecord{}, err
	}
	if err := sandboxrelayd.WriteRun(observerDir, fresh); err != nil {
		return sandboxrelayd.RunRecord{}, err
	}
	return fresh, nil
}

// hostedAdoptRun builds the helper-side state a re-adoption drives.
func hostedAdoptRun(observerDir string, rec sandboxremote.Record, v sandboxremote.Vendor, c sandboxremote.Client, cred sandboxremote.Credential, h sandbox.HostArgs, t hostedTerm) *hostedRun {
	root := rec.Extra[sandboxremote.ExtraRoot]
	return &hostedRun{
		plan: hostedPlanFile{
			RunID: rec.RunID, Provider: rec.Provider, Endpoint: rec.Endpoint, Region: rec.Region,
			Tier: rec.Extra[sandboxremote.ExtraTier], ObserverDir: observerDir, Tool: rec.Extra[sandboxremote.ExtraTool], Root: root,
		},
		h: h, t: t, now: time.Now, vendor: v, client: c, layout: v.Layout(root), rec: rec, cred: cred, rekey: true,
	}
}

func init() {
	hostedAdoptReopen = hostedAdoptReopenLinux
	hostedAdoptGuestPTY = hostedAdoptGuestPTYLinux
}

// hostedAdoptReopenLinux re-opens and re-keys the run's capture relay: the
// relay record is re-keyed, this process serves the run's host services
// (the relay socket the box's relay connects home to, and the model proxy
// when the tier allows it), and the guest relay is restarted with --rekey.
// stop closes it all; note says what happened.
func hostedAdoptReopenLinux(ctx context.Context, observerDir string, rec sandboxremote.Record, v sandboxremote.Vendor, c sandboxremote.Client, cred sandboxremote.Credential, out io.Writer) (func(), string) {
	blocked := func(why string) (func(), string) {
		return func() {}, "the capture relay is not re-opened (" + why + "), so checked actions in the box stay blocked"
	}
	if rec.Extra[sandboxremote.ExtraRoot] == "" || rec.Extra[sandboxremote.ExtraTier] == "" {
		return blocked("the run's record predates re-adoption")
	}
	if _, err := hostedRekeyRelayRun(observerDir, rec); err != nil {
		return blocked(err.Error())
	}
	sock := filepath.Join(os.TempDir(), "observer-adopt-"+rec.RunID+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	h := sandbox.HostArgs{SockDir: sock, RelayRun: rec.RunID, ObserverDir: observerDir}
	if vocab.Tier(rec.Extra[sandboxremote.ExtraTier]) != vocab.TierNone {
		port := 8820
		if cfg, err := config.Load(config.LoadOptions{GlobalPath: daemonConfigPath()}); err == nil && cfg.Proxy.Port > 0 {
			port = cfg.Proxy.Port
		}
		h.ProxyAddr = "127.0.0.1:" + strconv.Itoa(port)
	}
	stopSvc, err := startHostServices(h)
	if err != nil {
		stopSvc()
		return blocked("the run's host services: " + err.Error())
	}
	record, err := os.ReadFile(filepath.Join(sock, sandboxrelayd.BoxRecordName)) //nolint:gosec // G304: this process's own socket dir
	if err != nil {
		stopSvc()
		return blocked("the new box record: " + err.Error())
	}
	run := hostedAdoptRun(observerDir, rec, v, c, cred, h, hostedTerm{out: out})
	rctx, cancel := context.WithCancel(ctx)
	done, first := run.keepRelay(rctx, record)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			<-done
			stopSvc()
		})
	}
	select {
	case err := <-first:
		if err != nil {
			stop()
			return blocked(err.Error())
		}
	case <-time.After(hostedAdoptRelayWait):
		stop()
		return blocked("it was not ready in time")
	}
	return stop, "the capture relay is re-opened with new keys"
}

// hostedAdoptGuestPTYLinux re-attaches the agent's PTY a guest helper keeps
// (sandbox_guest_attach_linux.go) and returns the agent's exit status.
func hostedAdoptGuestPTYLinux(ctx context.Context, observerDir string, rec sandboxremote.Record, v sandboxremote.Vendor, c sandboxremote.Client, cred sandboxremote.Credential, in io.Reader, out io.Writer) (int, error) {
	t := hostedTerm{in: in, out: out, size: func() (uint16, uint16) { return 24, 80 }}
	if f, ok := in.(*os.File); ok && f == os.Stdin {
		rt, restore := realHostedTerm()
		defer restore()
		t = rt
		defer t.raw()()
	}
	// The keeper's own key, kept at home when the run started, is handed to
	// the attach verb inside the mux (never through a file in the box).
	key, err := hostedReadKeeperKey(observerDir, rec.RunID)
	if err != nil {
		return 1, fmt.Errorf("the run's PTY keeper key: %w (a run started before the keeper key cannot be re-attached; delete it instead)", err)
	}
	run := hostedAdoptRun(observerDir, rec, v, c, cred, sandbox.HostArgs{}, t)
	return run.attachKeptPTY(ctx, hostedTermConn{in: t.in, out: t.out}, key, nil)
}

// attachKeptPTY starts `observer sandbox-guest attach` in the run's box,
// hands it the keeper key inside the authenticated mux, carries the terminal
// term and the terminal's resizes (the current size first), and returns the
// agent's exit status. setMux, when set, is told the new mux, so a caller
// that already forwards resizes sends them there (the in-run reattach, lane
// LEFT-SBX); with no setMux this function forwards r.t's resizes itself (a
// re-adoption).
func (r *hostedRun) attachKeptPTY(ctx context.Context, term io.ReadWriteCloser, key []byte, setMux func(*relaymux.Host)) (int, error) {
	secret, sp, err := r.uploadSecret(ctx, "attach."+strconv.FormatInt(time.Now().UnixNano(), 36))
	if err != nil {
		return 1, err
	}
	p, err := r.client.Exec(ctx, r.rec.VendorID, sandboxremote.ExecSpec{
		Argv: []string{r.layout.Binary, "sandbox-guest", guestAttachVerb, "--run", r.rec.RunID, "--secret-file", sp},
		Env:  r.boxEnv(), Stdin: true,
	})
	if err != nil {
		return 1, fmt.Errorf("start the attach: %w", err)
	}
	defer p.Close()
	hmux, err := relaymux.ServeHost(ctx, muxConn(p), relaymux.HostOptions{
		Options: relaymux.Options{RunID: r.rec.RunID, Secret: secret}, Rand: rand.Reader,
		Kinds: map[string]bool{}, PTY: term, AttachKey: key,
		Dial: func(context.Context, string) (io.ReadWriteCloser, error) {
			return nil, errors.New("no connections on the PTY stream")
		},
	})
	if err != nil {
		_ = p.Kill(context.WithoutCancel(ctx))
		return 1, fmt.Errorf("the PTY handshake: %w", err)
	}
	defer hmux.Close()
	if setMux != nil {
		setMux(hmux)
	} else if r.t.resized != nil {
		go func() {
			for range r.t.resized {
				rr, cc := r.t.size()
				_ = hmux.Resize(rr, cc)
			}
		}()
	}
	if r.t.size != nil {
		rr, cc := r.t.size()
		_ = hmux.Resize(rr, cc)
	}
	code, err := p.Wait(ctx)
	if err != nil {
		return 1, err
	}
	return code, nil
}
