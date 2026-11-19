//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// No test reaches the network: the anonymous listing that decides auto
// answers "anyone can read it" unless a test says otherwise (so the
// box-side clone tests of lane CLONE keep their box), through
// setHostedAnon.
func init() {
	hostedAnonLsRemote = func(context.Context, string) error { return nil }
}

// setHostedAnon stands the listing in for one test and clears the cache.
func setHostedAnon(t *testing.T, fn func(context.Context, string) error) {
	t.Helper()
	old := hostedAnonLsRemote
	hostedAnonLsRemote = fn
	clearHostedAnonCache()
	t.Cleanup(func() {
		hostedAnonLsRemote = old
		clearHostedAnonCache()
	})
}

func clearHostedAnonCache() {
	hostedAnonCache.Range(func(k, _ any) bool {
		hostedAnonCache.Delete(k)
		return true
	})
}

var errAnonRefused = errors.New("fatal: could not read Username for 'https://github.com': terminal prompts disabled")

// TestHostedSourceDeliveryCloneWhere (lane CLONE2, decision SBXD-5): the
// clone location's table on a vendor row and the org row, the launch's own
// choice, and each way's gates.
func TestHostedSourceDeliveryCloneWhere(t *testing.T) {
	daytona, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
	org, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	const gh = "https://github.com/acme/app.git"
	with := func(where string, hosts ...string) config.TerminalSandboxConfig {
		c := config.TerminalSandboxConfig{AllowRemoteClone: true, RemoteAllowedHosts: hosts}
		c.Hosted.CloneWhere = where
		return c
	}
	public := func(context.Context, string) error { return nil }
	private := func(context.Context, string) error { return errAnonRefused }
	net := vocab.TierInternet
	cases := []struct {
		name    string
		v       sandboxremote.Vendor
		url     string
		tier    vocab.Tier
		cfg     config.TerminalSandboxConfig
		launch  string
		anon    func(context.Context, string) error
		where   workspace.CloneWhere
		reason  string
		refusal string
	}{
		{"auto, public -> box", daytona, gh, net, with("auto", "github.com"), "", public, workspace.CloneWhereBox, workspace.ReasonPublic, ""},
		{"auto, the listing refused -> home", daytona, gh, net, with("auto", "github.com"), "", private, workspace.CloneWhereHome, workspace.ReasonNeedsLogin, ""},
		{"auto, tier none -> home", daytona, gh, vocab.TierNone, with("auto", "github.com"), "", public, workspace.CloneWhereHome, workspace.ReasonBoxCannotClone, ""},
		{"auto, proxy_only -> home", daytona, gh, vocab.TierProxyOnly, with("auto", "github.com"), "", public, workspace.CloneWhereHome, workspace.ReasonBoxCannotClone, ""},
		{"auto, no hosts -> home", daytona, gh, net, with("auto"), "", public, workspace.CloneWhereHome, workspace.ReasonBoxCannotClone, ""},
		{"auto, an ssh address -> home", daytona, "git@github.com:acme/app.git", net, with("auto", "github.com"), "", public, workspace.CloneWhereHome, workspace.ReasonBoxCannotClone, ""},
		{"auto, the default (unset) is auto", daytona, gh, net, with("", "github.com"), "", private, workspace.CloneWhereHome, workspace.ReasonNeedsLogin, ""},
		{"home, public, tier none", daytona, gh, vocab.TierNone, with("home", "github.com"), "", public, workspace.CloneWhereHome, workspace.ReasonSetHome, ""},
		{"home, any host with no list", daytona, "https://gitlab.com/acme/app.git", net, with("home"), "", public, workspace.CloneWhereHome, workspace.ReasonSetHome, ""},
		{"home, a token in the URL", daytona, "https://x:ghp_t@github.com/acme/app.git", net, with("home"), "", public, "", "", "clone_url_invalid"},
		{"home, a host not listed", daytona, "https://gitlab.com/acme/app.git", net, with("home", "github.com"), "", public, "", "", "clone_url_invalid"},
		{"home, ext transport", daytona, "ext::sh -c x", net, with("home"), "", public, "", "", "clone_url_invalid"},
		{"home, switch off", daytona, gh, net, config.TerminalSandboxConfig{RemoteAllowedHosts: []string{"github.com"}, Hosted: config.TerminalSandboxHostedConfig{CloneWhere: "home"}}, "", public, "", "", "allow_remote_clone"},
		{"box, private -> the box (and its clone fails there)", daytona, gh, net, with("box", "github.com"), "", private, workspace.CloneWhereBox, workspace.ReasonSetBox, ""},
		{"box, tier none refused", daytona, gh, vocab.TierNone, with("box", "github.com"), "", public, "", "", "remote_clone_needs_egress"},
		{"auto, the launch chooses home", daytona, gh, net, with("auto", "github.com"), "home", public, workspace.CloneWhereHome, workspace.ReasonSetHome, ""},
		{"auto, the launch chooses box", daytona, gh, net, with("auto", "github.com"), "box", private, workspace.CloneWhereBox, workspace.ReasonSetBox, ""},
		{"home set, the launch may not choose box", daytona, gh, net, with("home", "github.com"), "box", public, "", "", "clone_where_fixed"},
		{"home set, the launch may restate it", daytona, gh, net, with("home", "github.com"), "home", public, workspace.CloneWhereHome, workspace.ReasonSetHome, ""},
		{"an unknown launch value", daytona, gh, net, with("auto", "github.com"), "elsewhere", public, "", "", "clone_where_invalid"},
		{"org row, home set: its own clone in the box", org, "https://github.com/acme/app.git", net, with("home", "github.com"), "", private, workspace.CloneWhereBox, workspace.ReasonRowClonesInBox, ""},
	}
	for _, tc := range cases {
		setHostedAnon(t, tc.anon)
		req := termsvc.PrepareRequest{WorkspaceSource: string(workspace.SourceCloneRemote), WorkspaceRemote: tc.url, WorkspaceCloneWhere: tc.launch, ProjectRoot: "/home/dev/app"}
		got, err := hostedSourceDelivery(context.Background(), tc.v, req, tc.tier, tc.cfg)
		if tc.refusal != "" {
			var step *dashapi.SandboxStepRefusal
			if err == nil || !strings.Contains(err.Error(), tc.refusal) || !errors.As(err, &step) || step.Message == "" || strings.Contains(step.Message, "_") {
				t.Errorf("%s: err %v, want a plain %q refusal", tc.name, err, tc.refusal)
			}
			continue
		}
		if err != nil || got.Where != tc.where || got.WhereReason != tc.reason || got.CloneURL != tc.url {
			t.Errorf("%s: %+v %v, want %s %s", tc.name, got, err, tc.where, tc.reason)
			continue
		}
		home := tc.where == workspace.CloneWhereHome
		if got.HomeClone != home || got.uploads() != home || (home && got.Delivery != workspace.DeliveryUploadSnapshot) || (!home && got.Delivery != workspace.DeliveryRemoteClone) {
			t.Errorf("%s: delivery %+v", tc.name, got)
		}
		if want := sandboxremote.RemoteCloneScopeKey(tc.url); !home && hostedCloneScope(got) != want {
			t.Errorf("%s: box scope %q", tc.name, hostedCloneScope(got))
		}
		if want := sandboxremote.HomeCloneScopeKey(tc.url); home && hostedCloneScope(got) != want {
			t.Errorf("%s: home scope %q", tc.name, hostedCloneScope(got))
		}
	}
}

// TestHostedAnonAnswerCached: one listing per URL within the cache window,
// and a refused or timed-out listing reads as refused.
func TestHostedAnonAnswerCached(t *testing.T) {
	calls := 0
	setHostedAnon(t, func(context.Context, string) error { calls++; return errAnonRefused })
	for range 3 {
		if got := hostedAnonAnswer(context.Background(), "https://github.com/acme/a.git"); got != workspace.AnonRefused {
			t.Fatalf("answer %q", got)
		}
	}
	if calls != 1 {
		t.Errorf("%d listings, want 1", calls)
	}
	oldTimeout := hostedAnonListTimeout
	hostedAnonListTimeout = 20 * time.Millisecond
	t.Cleanup(func() { hostedAnonListTimeout = oldTimeout })
	setHostedAnon(t, func(ctx context.Context, _ string) error { <-ctx.Done(); return ctx.Err() })
	if got := hostedAnonAnswer(context.Background(), "https://github.com/acme/slow.git"); got != workspace.AnonRefused {
		t.Errorf("a listing past its bound answered %q", got)
	}
}

// TestHostedAcceptedSourcesMatchTheLaunchCloneWhere (lane CLONE2): for
// every clone_where value, every tier and both listing answers, the dialog's
// list and the launch agree on the clone-remote source of every vendor row.
func TestHostedAcceptedSourcesMatchTheLaunchCloneWhere(t *testing.T) {
	for _, where := range []string{"auto", "box", "home"} {
		for _, hosts := range [][]string{{"github.com"}, nil} {
			cfg := config.Default().Terminal.Sandbox
			cfg.AllowRemoteClone, cfg.RemoteAllowedHosts = true, hosts
			cfg.Hosted.CloneWhere = where
			for _, anon := range []error{nil, errAnonRefused} {
				setHostedAnon(t, func(context.Context, string) error { return anon })
				for _, tier := range []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone} {
					for _, id := range sandboxremote.VendorIDs() {
						v, _ := sandboxremote.VendorFor(id)
						listed, _, _ := hostedAcceptedSources(id, tier, cfg)
						req := termsvc.PrepareRequest{WorkspaceSource: "clone-remote", WorkspaceRemote: "https://github.com/example/repo.git", ProjectRoot: "/home/dev/app"}
						_, err := hostedSourceDelivery(context.Background(), v, req, tier, cfg)
						if (err == nil) != slices.Contains(listed, "clone-remote") {
							t.Errorf("%s, hosts %v, anon %v, %s, %s: listed %v, launch %v", where, hosts, anon, tier, id, listed, err)
						}
					}
				}
			}
		}
	}
}

// TestHostedCloneWhereView: the dialog's facts follow the setting: auto
// offers every place the row can take now (with the box's reason when it
// cannot), a pinned value offers only itself, and a row that clones only
// in its box gets none.
func TestHostedCloneWhereView(t *testing.T) {
	cfg := config.Default().Terminal.Sandbox
	cfg.AllowRemoteClone, cfg.RemoteAllowedHosts = true, []string{"github.com"}
	v := hostedCloneWhereView(sandboxremote.VendorDaytona, vocab.TierInternet, cfg)
	if v == nil || v.Setting != "auto" || v.Fixed || !slices.Equal(v.Choices, []string{"auto", "box", "home"}) || v.Rule == "" {
		t.Fatalf("auto on internet: %+v", v)
	}
	v = hostedCloneWhereView(sandboxremote.VendorDaytona, vocab.TierNone, cfg)
	if !slices.Equal(v.Choices, []string{"auto", "home"}) || !strings.Contains(v.Notes["box"], "internet") {
		t.Errorf("auto on none: %+v", v)
	}
	cfg.Hosted.CloneWhere = "home"
	v = hostedCloneWhereView(sandboxremote.VendorDaytona, vocab.TierNone, cfg)
	if !v.Fixed || v.Setting != "home" || !slices.Equal(v.Choices, []string{"home"}) {
		t.Errorf("home pinned: %+v", v)
	}
	if hostedCloneWhereView(sandboxremote.VendorOpenShellOrg, vocab.TierInternet, cfg) != nil {
		t.Error("the org row got clone location choices")
	}
	if hostedCloneWhereView("bwrap", vocab.TierInternet, cfg) != nil {
		t.Error("a local row got clone location choices")
	}
}

// TestHostedHomeCloneDaemonSide (lane CLONE2): the daemon's clone runs the
// local rows' own clone-remote plan (git clone -- <url> <dest>, with the
// work branch) into the run's directory under the hosted clone root, and
// plans the upload of the clone's tracked files (a credential-shaped one
// left out); a failed clone is a plain refusal and leaves nothing behind.
func TestHostedHomeCloneDaemonSide(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git on this host")
	}
	obs := t.TempDir()
	if r, err := filepath.EvalSymlinks(obs); err == nil {
		obs = r
	}
	cfg := config.Default().Terminal.Sandbox
	cfg.AllowRemoteClone = true
	d := &hostedDriver{r: &sandboxRuntime{cfg: cfg, observerDir: obs}, now: time.Now}
	var steps [][]string
	old := hostedHomeCloneStep
	t.Cleanup(func() { hostedHomeCloneStep = old })
	hostedHomeCloneStep = func(_ context.Context, _ *sandboxRuntime, step workspace.Step) error {
		steps = append(steps, step.Argv)
		if step.Argv[1] != "clone" {
			return nil
		}
		dest := step.Argv[len(step.Argv)-1]
		for _, a := range [][]string{{"init", "-q", dest}} {
			if out, err := exec.Command("git", a...).CombinedOutput(); err != nil {
				return fmt.Errorf("%w %s", err, out)
			}
		}
		for p, body := range map[string]string{"README.md": "hi\n", ".env": "K=1\n"} {
			if err := os.WriteFile(filepath.Join(dest, p), []byte(body), 0o644); err != nil {
				return err
			}
		}
		for _, a := range [][]string{{"-C", dest, "add", "-A"}, {"-C", dest, "-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "init"}} {
			if out, err := exec.Command("git", a...).CombinedOutput(); err != nil {
				return fmt.Errorf("%w %s", err, out)
			}
		}
		return nil
	}
	const url = "git@github.com:acme/private.git"
	res, err := d.homeClone(context.Background(), "run-c1", hostedDelivery{CloneURL: url, CloneBranch: "work", HomeClone: true})
	if err != nil {
		t.Fatal(err)
	}
	root := hostedHomeCloneRoot(obs)
	if filepath.Dir(filepath.Dir(res.Dir)) != root || filepath.Base(filepath.Dir(res.Dir)) != "run-c1" {
		t.Errorf("clone dir %s, not a run directory under %s", res.Dir, root)
	}
	if len(steps) != 2 || !slices.Equal(steps[0][:4], []string{"git", "clone", "--", url}) || !slices.Contains(steps[1], "checkout") {
		t.Errorf("steps %v", steps)
	}
	if res.Manifest.Count != 1 || res.Manifest.Files[0].Path != "README.md" || len(res.Manifest.Excluded) != 1 || res.Manifest.Excluded[0].Path != ".env" {
		t.Errorf("manifest %+v", res.Manifest)
	}
	hostedHomeCloneStep = func(context.Context, *sandboxRuntime, workspace.Step) error {
		return errors.New("git clone failed: Permission denied (publickey)")
	}
	_, err = d.homeClone(context.Background(), "run-c2", hostedDelivery{CloneURL: url, HomeClone: true})
	var step *dashapi.SandboxStepRefusal
	if !errors.As(err, &step) || step.Code != "home_clone_failed" || strings.Contains(step.Message, "_") {
		t.Errorf("a failed clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "run-c2")); !os.IsNotExist(err) {
		t.Error("a failed clone left its directory")
	}
}

// TestHostedHomeCloneRemoval: only a run directory under the clone root is
// removed, and the sweep removes only stale run directories.
func TestHostedHomeCloneRemoval(t *testing.T) {
	obs := t.TempDir()
	root := hostedHomeCloneRoot(obs)
	clone := filepath.Join(root, "run-a", "app")
	if err := os.MkdirAll(clone, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hostedRemoveHomeCloneDir(obs, clone); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "run-a")); !os.IsNotExist(err) {
		t.Error("the run's clone directory is still there")
	}
	elsewhere := filepath.Join(t.TempDir(), "run-b", "app")
	_ = os.MkdirAll(elsewhere, 0o700)
	if err := hostedRemoveHomeCloneDir(obs, elsewhere); err == nil {
		t.Error("a directory outside the clone root was removed")
	}
	if _, err := os.Stat(elsewhere); err != nil {
		t.Error("a directory outside the clone root is gone")
	}
	for _, name := range []string{"run-old", "run-new"} {
		_ = os.MkdirAll(filepath.Join(root, name, "app"), 0o700)
	}
	past := time.Now().Add(-2 * hostedHomeCloneStaleAfter)
	_ = os.Chtimes(filepath.Join(root, "run-old"), past, past)
	hostedSweepHomeClones(root, time.Now())
	if _, err := os.Stat(filepath.Join(root, "run-old")); !os.IsNotExist(err) {
		t.Error("a stale clone was kept")
	}
	if _, err := os.Stat(filepath.Join(root, "run-new")); err != nil {
		t.Error("a fresh clone was swept")
	}
}
