//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// gatefixPacks is the active pack set the tests sign into the guard
// posture: the module root and the secrets child (S-721).
var gatefixPacks = []string{"security", "security.secrets"}

// writeGuardPosturePacks signs an active guard posture carrying packs.
func writeGuardPosturePacks(t *testing.T, cfgPath string, packs []string) {
	t.Helper()
	key, err := guardposture.LoadOrCreateKey(guardposture.KeyPath(cfgPath))
	if err != nil {
		t.Fatal(err)
	}
	p := guardposture.Posture{Source: "test", SecurityRecorded: true, SecurityActive: true, SecurityPacks: packs, WrittenAt: time.Now()}
	if _, err := guardposture.Write(guardposture.PosturePath(cfgPath), p, key); err != nil {
		t.Fatal(err)
	}
}

// gatefixNode is one test node: a config path, its security layout and a
// project root.
type gatefixNode struct {
	cfgPath string
	layout  secposture.Layout
	root    string
}

func newGatefixNode(t *testing.T) gatefixNode {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	resolved, err := config.ResolveGlobalPath(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	writeGuardPosturePacks(t, cfgPath, gatefixPacks)
	setInvocationHookContext(nil, "")
	t.Cleanup(func() { setInvocationHookContext(nil, "") })
	return gatefixNode{cfgPath: cfgPath, layout: secposture.LayoutFor(resolved), root: filepath.Join(dir, "project")}
}

// writeCleanPosture writes the project's verified, current, clean posture
// file (the daemon's normal output) and returns it with its key.
func (n gatefixNode) writeCleanPosture(t *testing.T, mut func(f *secposture.File)) {
	t.Helper()
	key, err := secposture.LoadOrCreateKey(n.layout.KeyPath())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	f := secposture.File{
		ProjectRootHash: secposture.ProjectRootHash(n.root), Packs: gatefixPacks, Sequence: 1,
		IssuedAt: now, ExpiresAt: now.Add(secposture.DefaultTTL), Trust: policy.TrustClean,
		QuickScanAvailable: true,
	}
	if mut != nil {
		mut(&f)
	}
	if _, err := secposture.Write(n.layout, f, key); err != nil {
		t.Fatal(err)
	}
}

// evaluate runs one event through the production enrich step and a guard
// built with the hook's composed pack, as `observer hook` does.
func (n gatefixNode) evaluate(t *testing.T, pe *policy.Event) policy.Verdict {
	t.Helper()
	securityToolGateEnrich(n.cfgPath, models.ToolClaudeCode, "PreToolUse", nil)(pe)
	g, err := guard.New(guard.Options{
		Config: config.GuardConfig{Enabled: true, Mode: "observe", RetentionDays: 365},
		Home:   t.TempDir(), KnownProjectRoots: []string{n.root},
		PackRules: securityHookPackRules(n.cfgPath),
	})
	if err != nil {
		t.Fatal(err)
	}
	v, err := g.Evaluate(*pe)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func (n gatefixNode) commit() *policy.Event {
	return &policy.Event{Kind: policy.KindShellExec, ActionType: models.ActionRunCommand, Target: "git commit -m wip", ProjectRoot: n.root, Cwd: n.root}
}

func (n gatefixNode) secretWrite() *policy.Event {
	return &policy.Event{
		Kind: policy.KindFileAccess, ActionType: models.ActionWriteFile, Target: filepath.Join(n.root, "cfg.py"),
		ProjectRoot: n.root, Cwd: n.root,
		Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: "k = \"" + fakeSecretAWSKeyID + "\"\n"}},
	}
}

// TestSecurityGateFailsClosedOnUnusablePosture (lane SEC-GATEFIX milestone
// 1a, end to end through the composed pack): whenever the project's own
// posture file cannot be used, the commit gate asks (S-794) and a write
// adding a secret is flagged (S-721), because the event carries the pack
// set signed into the guard posture. A clean, current file is the control:
// the commit proceeds.
func TestSecurityGateFailsClosedOnUnusablePosture(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, n gatefixNode)
		clean bool
	}{
		{"control: clean and current", func(t *testing.T, n gatefixNode) { n.writeCleanPosture(t, nil) }, true},
		{"no posture file (deleted)", func(*testing.T, gatefixNode) {}, false},
		{"deleted after it was written", func(t *testing.T, n gatefixNode) {
			n.writeCleanPosture(t, nil)
			if err := os.Remove(n.layout.PosturePath(secposture.ProjectRootHash(n.root))); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"corrupted", func(t *testing.T, n gatefixNode) {
			n.writeCleanPosture(t, nil)
			if err := os.WriteFile(n.layout.PosturePath(secposture.ProjectRootHash(n.root)), []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"tampered (a field edited after signing)", func(t *testing.T, n gatefixNode) {
			n.writeCleanPosture(t, func(f *secposture.File) { f.Blocking = []string{"k1"} })
			path := n.layout.PosturePath(secposture.ProjectRootHash(n.root))
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			data = []byte(strings.Replace(string(data), `"k1"`, `"k2"`, 1))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"over the size cap", func(t *testing.T, n gatefixNode) {
			n.writeCleanPosture(t, nil)
			big := make([]byte, secposture.MaxFileBytes+10)
			for i := range big {
				big[i] = ' '
			}
			if err := os.WriteFile(n.layout.PosturePath(secposture.ProjectRootHash(n.root)), big, 0o600); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"key removed (unverified)", func(t *testing.T, n gatefixNode) {
			n.writeCleanPosture(t, nil)
			if err := os.Remove(n.layout.KeyPath()); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"expired (daemon stopped past the TTL)", func(t *testing.T, n gatefixNode) {
			n.writeCleanPosture(t, func(f *secposture.File) {
				f.IssuedAt = time.Now().Add(-secposture.DefaultTTL - time.Minute)
				f.ExpiresAt = time.Now().Add(-time.Minute)
			})
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n := newGatefixNode(t)
			tc.setup(t, n)
			commit := n.commit()
			v := n.evaluate(t, commit)
			if tc.clean {
				if v.RuleID == "S-794" || v.RuleID == "S-793" {
					t.Fatalf("clean control: commit verdict %+v", v)
				}
			} else if v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
				t.Fatalf("commit verdict %+v (security %+v), want S-794 ask", v, commit.Security)
			}
			write := n.secretWrite()
			if v := n.evaluate(t, write); v.RuleID != "S-721" || v.Decision != policy.DecisionFlag {
				t.Fatalf("secret write verdict %+v (security %+v), want S-721 flag", v, write.Security)
			}
		})
	}
}

// TestSecurityGateFailsClosedWhenTheSidecarFails (milestone 1b): a Sidecar
// provider that errors or overruns leaves an unknown state, and the event
// still carries the signed pack set, so S-794 asks and S-721 fires.
func TestSecurityGateFailsClosedWhenTheSidecarFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sidecar hookctx.SecuritySource
	}{
		{"error", func(context.Context, hookctx.Request) (hookctx.Security, error) {
			return hookctx.Security{}, errors.New("read failed")
		}},
		{"overrun", func(ctx context.Context, _ hookctx.Request) (hookctx.Security, error) {
			<-ctx.Done()
			return hookctx.Security{Posture: policy.SecurityPostureClean, Packs: gatefixPacks}, nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newGatefixNode(t)
			prov := hookctx.HostProviders{Sidecar: tc.sidecar, Limits: hookctx.Limits{Security: 20 * time.Millisecond}}
			setInvocationHookContext(hookctx.Host(context.Background(), hookctx.Request{}, hookctx.Source{}, prov), "")
			commit := n.commit()
			if v := n.evaluate(t, commit); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
				t.Fatalf("commit verdict %+v (security %+v), want S-794 ask", v, commit.Security)
			}
			write := n.secretWrite()
			if v := n.evaluate(t, write); v.RuleID != "S-721" {
				t.Fatalf("secret write verdict %+v (security %+v), want S-721", v, write.Security)
			}
		})
	}
}

// TestSecurityUnknownPacksFromAnOlderDaemon: an active guard posture with
// no pack set (a daemon from before the field) keeps the root's rows, so
// the commit gate still asks on an unknown state.
func TestSecurityUnknownPacksFromAnOlderDaemon(t *testing.T) {
	n := newGatefixNode(t)
	writeGuardPosture(t, n.cfgPath, true)
	commit := n.commit()
	if v := n.evaluate(t, commit); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
		t.Fatalf("commit verdict %+v, want S-794 ask", v)
	}
}

// TestSecurityHookHonoursQuickScanAvailable (milestone 2g): while the
// project's current posture says the quick-scan service is not serving,
// the hook does not ask it (the verdict stays unknown); a file that says
// it serves lets the request through to the endpoint.
func TestSecurityHookHonoursQuickScanAvailable(t *testing.T) {
	n := newGatefixNode(t)
	n.writeCleanPosture(t, func(f *secposture.File) { f.QuickScanAvailable = false })
	p := securityHostProviders(n.cfgPath)
	ctx := context.Background()
	if _, err := p.Sidecar(ctx, hookctx.Request{ProjectRoot: n.root}); err != nil {
		t.Fatal(err)
	}
	req := hookctx.QuickScanRequest{ProjectRoot: n.root, Form: policy.GitWrite{Form: policy.GitWriteCommit}}
	if _, err := p.QuickScan(ctx, req); !errors.Is(err, errQuickScanOff) {
		t.Fatalf("not serving: err %v, want errQuickScanOff", err)
	}
	n.writeCleanPosture(t, func(f *secposture.File) { f.Sequence = 2 })
	if _, err := p.Sidecar(ctx, hookctx.Request{ProjectRoot: n.root}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.QuickScan(ctx, req); errors.Is(err, errQuickScanOff) {
		t.Fatal("a serving posture must let the request through")
	}
}
