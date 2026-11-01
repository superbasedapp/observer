//go:build !sbo_omit_agentaccess_relay

package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/coverage"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/policystate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// mcpRelayTestSpec is a two-grant tools.mcp_access body: allow call
// create_issue on vs-gh, deny call delete_repo on vs-gh; slack is unknown.
func mcpRelayTestSpec(t *testing.T, mode string) famcp.PolicySpec {
	t.Helper()
	b := famcp.Body{Mode: mode, Registry: mcpaccess.Registry{
		Issuer: "https://auth.acme", Org: "acme", GatewayBaseURI: "https://gw.acme", PolicyGen: 5,
		VServers: []mcpaccess.VServer{{
			ID: "vs-gh", Slug: "github", SenderConstraint: "bearer",
			Servers: []mcpaccess.Server{{ID: "gh", Target: "https://mcp.github.com/mcp", CredentialMode: "service"}},
		}},
	}, Grants: []mcpaccess.Grant{
		{
			ID: "g-allow", Ord: 1, Subject: mcpaccess.Subject{Kind: mcpaccess.SubjectAny},
			Resource: mcpaccess.Resource{VServer: "vs-gh", Name: "create_issue"}, Action: mcpaccess.ActionCall,
			Effect: mcpaccess.EffectAllow, Enabled: true,
		},
		{
			ID: "g-deny", Ord: 2, Subject: mcpaccess.Subject{Kind: mcpaccess.SubjectAny},
			Resource: mcpaccess.Resource{VServer: "vs-gh", Name: "delete_repo"}, Action: mcpaccess.ActionCall,
			Effect: mcpaccess.EffectDeny, Enabled: true,
		},
	}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	spec, _, err := famcp.CompileBody(raw, famcp.DefaultMaxBytes)
	if err != nil {
		t.Fatalf("CompileBody: %v", err)
	}
	return spec
}

func mcpRelayTestCfg(t *testing.T, enabled bool) config.Config {
	t.Helper()
	var cfg config.Config
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.MCPRelay.Enabled = enabled
	cfg.MCPRelay.Mode = config.MCPRelayModeStdioWrapper
	cfg.MCPRelay.AuditMode = config.MCPRelayAuditAsync
	return cfg
}

func appliedHandle(t *testing.T, cfg config.Config, mode string, orgAuth bool) *mcpRelayHandle {
	t.Helper()
	h := newMCPRelayHandle(cfg, nil, nil, slog.New(slog.DiscardHandler))
	h.orgAuthoritative = func() bool { return orgAuth }
	h.Apply(orgclient.PolicyResourceResult{
		Status: orgclient.PRApplied, Version: 3, BodyHash: strings.Repeat("b", 64),
		OrgKey: "org", Generation: 1, EnforceAllowed: true, Spec: mcpRelayTestSpec(t, mode),
	})
	if h.Table() == nil {
		t.Fatalf("table not applied: %+v", h.State())
	}
	return h
}

// TestMCPRelay_FactsEnumOnlyAndResolve pins the effective-state ACK row
// (doc3 §12.8): enum-only fields, a 64-hex effective hash, and the closed
// statuses effective / accepted_inert / none through the real resolver.
func TestMCPRelay_FactsEnumOnlyAndResolve(t *testing.T) {
	cases := []struct {
		name       string
		build      func(t *testing.T) *mcpRelayHandle
		wantStatus string
		wantReason string
		wantMode   string
	}{
		{"enforce table + projection applied = effective/enforce", func(t *testing.T) *mcpRelayHandle {
			h := appliedHandle(t, mcpRelayTestCfg(t, true), "enforce", false)
			h.SetProjectionApplied(true)
			return h
		}, "effective", "ok", "enforce"},
		{"enforce table, projection NOT applied (point ineffective) = accepted_inert/mode_observe, never effective", func(t *testing.T) *mcpRelayHandle {
			return appliedHandle(t, mcpRelayTestCfg(t, true), "enforce", false)
		}, "accepted_inert", "mode_observe", "observe"},
		{"observe table = accepted_inert/mode_observe", func(t *testing.T) *mcpRelayHandle {
			return appliedHandle(t, mcpRelayTestCfg(t, true), "observe", false)
		}, "accepted_inert", "mode_observe", "observe"},
		{"enforce body not preauthorized = accepted_inert/not_preauthorized", func(t *testing.T) *mcpRelayHandle {
			h := newMCPRelayHandle(mcpRelayTestCfg(t, true), nil, nil, slog.New(slog.DiscardHandler))
			h.Apply(orgclient.PolicyResourceResult{
				Status: orgclient.PRAppliedInert, Version: 4, BodyHash: strings.Repeat("c", 64),
				InertReason: "not_preauthorized", EnforceAllowed: false, Spec: mcpRelayTestSpec(t, "enforce"),
			})
			return h
		}, "accepted_inert", "not_preauthorized", "observe"},
		{"no table = none/no_policy", func(t *testing.T) *mcpRelayHandle {
			return newMCPRelayHandle(mcpRelayTestCfg(t, true), nil, nil, slog.New(slog.DiscardHandler))
		}, "none", "no_policy", "off"},
		{"nil handle (disabled) = none/no_policy", func(*testing.T) *mcpRelayHandle { return nil }, "none", "no_policy", "off"},
	}
	// Coverage honesty: an enforce table on a node whose projection has
	// not been applied is NOT an effective point (projection.applied is a
	// required capability), so the ACK never claims enforce.
	if h := appliedHandle(t, mcpRelayTestCfg(t, true), "enforce", false); true {
		if st, missing := coverage.Status(coverage.PointRelay, h.pointCapabilities()); st != coverage.StatusIneffective || strings.Join(missing, ",") != "projection.applied" {
			t.Fatalf("status without projection = %s missing %v", st, missing)
		}
		if f, _ := h.Facts(); f.EnforceMode != "observe" {
			t.Fatalf("enforce mode claimed without a projection: %+v", f)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.build(t)
			f, _ := h.Facts()
			if f.EffectiveHash != "" && len(f.EffectiveHash) != 64 {
				t.Errorf("effective hash %q not 64 hex", f.EffectiveHash)
			}
			row := policystate.Resolve(policystate.PointNodeMCPRelay, policystate.FamilyToolsMCPAccess, f)
			if row.Status != tc.wantStatus || row.Reason != tc.wantReason || row.Mode != tc.wantMode {
				t.Errorf("row = %s/%s/%s, want %s/%s/%s (facts %+v)", row.Status, row.Reason, row.Mode, tc.wantStatus, tc.wantReason, tc.wantMode, f)
			}
			if row.AcceptedAuthority != nil || row.DroppedClasses != nil || row.EffectivePins != nil {
				t.Errorf("row carries node-dashboard-only fields: %+v", row)
			}
			if tc.wantStatus == "effective" && (row.RunningVersion != 3 || row.DesiredVersion != 3) {
				t.Errorf("versions = %d/%d, want 3/3", row.RunningVersion, row.DesiredVersion)
			}
		})
	}
}

// TestMCPRelay_HookLookupReadsDaemonCache pins the hook-process binding: the
// daemon's Apply wrote the compiled table beside the DB; a fresh
// hookMCPAccessLookup on the same config answers from it without a DB or an
// org fetch, and a cleared cache yields nil (fail-open).
func TestMCPRelay_HookLookupReadsDaemonCache(t *testing.T) {
	cfg := mcpRelayTestCfg(t, true)
	h := appliedHandle(t, cfg, "enforce", false)
	if h.cache.Path != localpdp.SiblingPath("", cfg.Observer.DBPath) {
		t.Fatalf("cache path = %s", h.cache.Path)
	}
	fn := hookMCPAccessLookup(cfg)
	if fn == nil {
		t.Fatal("hook lookup nil after the daemon cached a table")
	}
	if v := fn("github", "delete_repo"); !v.Known || !v.OrgDenied {
		t.Errorf("hook lookup delete_repo = %+v, want org-denied", v)
	}
	if v := fn("github", "create_issue"); !v.Known || !v.Allowed {
		t.Errorf("hook lookup create_issue = %+v, want allowed", v)
	}
	h.Clear()
	if hookMCPAccessLookup(cfg) != nil {
		t.Error("hook lookup survived a cleared cache")
	}
}

// TestMCPRelay_ApplyBadSpecKeepsPreviousTable pins the apply error path.
func TestMCPRelay_ApplyBadSpecKeepsPreviousTable(t *testing.T) {
	h := appliedHandle(t, mcpRelayTestCfg(t, true), "enforce", false)
	h.Apply(orgclient.PolicyResourceResult{Status: orgclient.PRApplied, Version: 9, Spec: "not a spec"})
	if h.Table() == nil || h.Table().Meta.Version != 3 {
		t.Error("bad spec replaced the live table")
	}
	if st := h.State(); st.LastApplyErr == "" || st.Version != 9 {
		t.Errorf("state = %+v, want the apply error recorded at version 9", st)
	}
}

// TestMCPRelayCmd_Registered pins the CLI surface and the --help restart note.
func TestMCPRelayCmd_Registered(t *testing.T) {
	root := newRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() != "mcp-relay" {
			continue
		}
		found = true
		subs := map[string]bool{}
		for _, s := range c.Commands() {
			subs[s.Name()] = true
		}
		for _, want := range []string{"status", "enable", "disable", "restore", "wrap"} {
			if !subs[want] {
				t.Errorf("mcp-relay missing subcommand %s", want)
			}
		}
		if !strings.Contains(c.Long, "route OFF -> stop -> relaunch") {
			t.Error("mcp-relay --help lacks the daemon-restart route-OFF order note")
		}
	}
	if !found {
		t.Fatal("mcp-relay command not registered")
	}
}

// fakeLaunchStore is an in-memory launchSpecStore.
type fakeLaunchStore struct{ rows []record.LaunchSpec }

func (f *fakeLaunchStore) key(c, p, k string) int {
	for i, r := range f.rows {
		if r.Client == c && r.ConfigPath == p && r.EntryKey == k {
			return i
		}
	}
	return -1
}

func (f *fakeLaunchStore) PutLaunchSpec(_ context.Context, spec record.LaunchSpec, expected int64) error {
	if i := f.key(spec.Client, spec.ConfigPath, spec.EntryKey); i >= 0 {
		if f.rows[i].ConfigGeneration != expected {
			return record.ErrConflict
		}
		f.rows[i] = spec
		return nil
	}
	if expected != 0 {
		return record.ErrConflict
	}
	f.rows = append(f.rows, spec)
	return nil
}

func (f *fakeLaunchStore) GetLaunchSpec(_ context.Context, c, p, k string) (record.LaunchSpec, error) {
	if i := f.key(c, p, k); i >= 0 {
		return f.rows[i], nil
	}
	return record.LaunchSpec{}, record.ErrNotFound
}

func (f *fakeLaunchStore) ListLaunchSpecs(context.Context) ([]record.LaunchSpec, error) {
	return append([]record.LaunchSpec(nil), f.rows...), nil
}

func (f *fakeLaunchStore) DeleteLaunchSpec(_ context.Context, c, p, k string) error {
	if i := f.key(c, p, k); i >= 0 {
		f.rows = append(f.rows[:i], f.rows[i+1:]...)
	}
	return nil
}

// TestMCPRelay_LaunchSpecEnvOverlay pins Sol P3+P4 finding 6's env
// contract: the child's environment is the wrapper's WHOLE environment
// (PATH / HOME survive) with the journaled secret-reference KEYS overlaid
// from that environment; an unresolvable ref adds nothing; a remote
// sentinel row is never a launch spec; --client disambiguates one key
// journaled by two clients.
func TestMCPRelay_LaunchSpecEnvOverlay(t *testing.T) {
	st := &fakeLaunchStore{rows: []record.LaunchSpec{
		{Client: "cursor", ConfigPath: "/h/.cursor/mcp.json", EntryKey: "gh", OrigCommand: "npx", OrigArgs: []string{"-y", "gh"}, OrigCwd: "/repo", OrigEnvRefs: []string{"GITHUB_TOKEN", "MISSING_REF"}, VServer: "vs-gh", RegistryServerID: "gh"},
		{Client: "codex", ConfigPath: "/h/.codex/config.toml", EntryKey: "gh", OrigCommand: "/opt/other", VServer: "vs-gh", RegistryServerID: "gh"},
		{Client: "cursor", ConfigPath: "/h/.cursor/mcp.json", EntryKey: "superbased-github", OrigCommand: project.RemoteOrigCommand},
		// A pre-133 row: no approved binding journaled.
		{Client: "cline", ConfigPath: "/h/.cline/mcp.json", EntryKey: "legacy", OrigCommand: "/opt/legacy"},
	}}
	l := launchSpecsFromJournal{
		st: st,
		environ: func() []string {
			return []string{"PATH=/usr/bin:/bin", "HOME=/home/dev", "LANG=C.UTF-8", "GITHUB_TOKEN=stale"}
		},
		lookupEnv: func(k string) (string, bool) {
			return map[string]string{"GITHUB_TOKEN": "ghp_live"}[k], k == "GITHUB_TOKEN"
		},
	}
	spec, err := l.Lookup(context.Background(), "cursor", "gh")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Command != "npx" || spec.Cwd != "/repo" || strings.Join(spec.Args, " ") != "-y gh" {
		t.Fatalf("%+v", spec)
	}
	// Sol P3+P4 fold finding 2: the journaled approved binding rides the
	// launch spec (the local PDP keys on the vserver ID).
	if spec.VServer != "vs-gh" || spec.ServerID != "gh" {
		t.Fatalf("binding not populated: vserver=%q server=%q", spec.VServer, spec.ServerID)
	}
	if _, err := l.Lookup(context.Background(), "cline", "legacy"); !errors.Is(err, errMCPRelayUnbound) {
		t.Fatalf("pre-133 unbound row must be refused, never guessed: %v", err)
	}
	env := strings.Join(spec.Env, "\n")
	for _, want := range []string{"PATH=/usr/bin:/bin", "HOME=/home/dev", "LANG=C.UTF-8", "GITHUB_TOKEN=ghp_live"} {
		if !strings.Contains(env, want) {
			t.Errorf("env lost %q: %v", want, spec.Env)
		}
	}
	if strings.Contains(env, "stale") || strings.Contains(env, "MISSING_REF") || len(spec.Env) != 4 {
		t.Errorf("overlay wrong: %v", spec.Env)
	}
	if spec, err := l.Lookup(context.Background(), "codex", "gh"); err != nil || spec.Command != "/opt/other" {
		t.Fatalf("--client did not disambiguate: %+v %v", spec, err)
	}
	if _, err := l.Lookup(context.Background(), "cursor", "superbased-github"); !errors.Is(err, record.ErrNotFound) {
		t.Fatalf("remote sentinel row must not be a launch spec: %v", err)
	}
	if _, err := l.Lookup(context.Background(), "claude-code", "gh"); !errors.Is(err, record.ErrNotFound) {
		t.Fatalf("foreign client: %v", err)
	}
	if spec, err := l.Lookup(context.Background(), "", "gh"); err != nil || spec.Command != "npx" {
		t.Fatalf("empty client = first match: %+v %v", spec, err)
	}
}

// fakeAAKeys is an in-memory agent-access key slot.
type fakeAAKeys struct {
	key orgclient.AgentAccessKey
	err error
}

func (f fakeAAKeys) LoadAgentAccessKey() (orgclient.AgentAccessKey, error) { return f.key, f.err }
func (fakeAAKeys) SaveAgentAccessKey(orgclient.AgentAccessKey) error       { return nil }
func (fakeAAKeys) ClearAgentAccessKey() error                              { return nil }

func testAAKey(t *testing.T) orgclient.AgentAccessKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return orgclient.AgentAccessKey{Alg: orgclient.DefaultAgentAccessKeyAlg, Signer: crypto.Signer(priv)}
}

func openMCPRelayTestStore(t *testing.T, cfg config.Config) *store.Store {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// TestMCPRelay_TokenClientFromRegistration pins decision B9's node half:
// the DPoP token client is built from a REAL registration (credential id +
// machine fp + cred gen + the enrolment member id) and never from nothing;
// resolveMCPRelayRemote reports the honest reason for every way forwarding
// can be off, and remote_forwarding is TRUE exactly when the client was
// built.
func TestMCPRelay_TokenClientFromRegistration(t *testing.T) {
	reg := orgclient.AgentAccessRegistration{CredentialID: "cred_1", MachineFP: "fp_abc", CredGen: 2, CreatedAt: "2026-09-24T10:00:00Z"}
	keys := fakeAAKeys{key: testAAKey(t)}
	bearer := func() (string, error) { return "bearer", nil }
	logger := slog.New(slog.DiscardHandler)
	if tc, err := buildMCPRelayTokenClient(reg, "usr_1", "https://auth.acme", keys, bearer, http.DefaultClient, logger); err != nil || tc == nil {
		t.Fatalf("full registration must build a client: %v", err)
	}
	for name, bad := range map[string]orgclient.AgentAccessRegistration{
		"empty registration": {},
		"no credential id":   {MachineFP: "fp"},
		"no machine fp":      {CredentialID: "c"},
	} {
		if tc, err := buildMCPRelayTokenClient(bad, "usr_1", "https://auth.acme", keys, bearer, http.DefaultClient, logger); err == nil || tc != nil {
			t.Errorf("%s built a client: %v", name, tc)
		}
	}
	if _, err := buildMCPRelayTokenClient(reg, "", "https://auth.acme", keys, bearer, http.DefaultClient, logger); err == nil {
		t.Error("no member id accepted")
	}
	if _, err := buildMCPRelayTokenClient(reg, "usr_1", "", keys, bearer, http.DefaultClient, logger); err == nil {
		t.Error("no issuer accepted")
	}

	ctx := context.Background()
	cfg := mcpRelayTestCfg(t, true)
	st := openMCPRelayTestStore(t, cfg)
	okDeps := func(regErr error, keysErr error, loadErr error) mcpRelayRemoteDeps {
		return mcpRelayRemoteDeps{
			keys: func() (orgclient.AgentAccessKeyStore, error) {
				if keysErr != nil {
					return nil, keysErr
				}
				return fakeAAKeys{key: keys.key, err: loadErr}, nil
			},
			register: func(context.Context, orgclient.AgentAccessKeyStore) (orgclient.AgentAccessRegistration, error) {
				return reg, regErr
			},
			bearer: bearer,
			egress: func(string, *store.Enrolment) *http.Client { return http.DefaultClient },
		}
	}
	// Not enrolled.
	h := appliedHandle(t, cfg, "enforce", false)
	if tc, _, r := resolveMCPRelayRemote(ctx, cfg, st, h, okDeps(nil, nil, nil), logger); tc != nil || r.Wired || r.Reason != "not enrolled" {
		t.Fatalf("not enrolled: %+v", r)
	}
	if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "acme", OrgServerURL: "https://org.acme", UserID: "usr_1"}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		deps   mcpRelayRemoteDeps
		handle *mcpRelayHandle
		wired  bool
		reason string
	}{
		{"keychain unavailable", okDeps(nil, orgclient.ErrAgentAccessKeychainUnavailable, nil), h, false, "OS keychain unavailable"},
		// No key yet: registration mints it (EnsureAgentAccessKey), so this
		// is the first-start path, not a refusal.
		{"no key yet: registration mints it", okDeps(nil, nil, orgclient.ErrNoSecret), h, true, ""},
		{"key unreadable", okDeps(nil, nil, errors.New("keyring: locked")), h, false, "agent-access key unreadable"},
		// A handle on its OWN config: newMCPRelayHandle loads the table cached
		// beside the DB, and this case needs a node with none.
		{"no table (issuer unknown)", okDeps(nil, nil, nil), newMCPRelayHandle(mcpRelayTestCfg(t, true), nil, nil, logger), false, "issuer unknown"},
		{"registration refused: unsupported", okDeps(orgclient.ErrAgentAccessUnsupported, nil, nil), h, false, "does not serve agent-access registration"},
		{"registration refused: revoked", okDeps(orgclient.ErrAgentAccessDeviceRevoked, nil, nil), h, false, "revoked"},
		{"registration refused: auth", okDeps(orgclient.ErrAuthFailed, nil, nil), h, false, "bearer rejected"},
		{"STS unreachable", okDeps(errors.New("dial tcp: refused"), nil, nil), h, false, "unreachable"},
		{"registered", okDeps(nil, nil, nil), h, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, httpc, r := resolveMCPRelayRemote(ctx, cfg, st, tc.handle, tc.deps, logger)
			if r.Wired != tc.wired || (client != nil) != tc.wired || (httpc != nil) != tc.wired {
				t.Fatalf("wired=%v client=%v http=%v reason=%q", r.Wired, client != nil, httpc != nil, r.Reason)
			}
			if !tc.wired && !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("reason %q, want %q", r.Reason, tc.reason)
			}
			if tc.wired && (r.CredentialID != "cred_1" || r.CredGen != 2 || r.MachineFP != "fp_abc" || r.RegisteredAt == "" || r.Issuer != "https://auth.acme" || r.GatewayURL != "https://gw.acme") {
				t.Fatalf("registration not reported: %+v", r)
			}
		})
	}
	// The gateway URL follows [mcp_relay].gateway_url when set.
	cfg2 := cfg
	cfg2.MCPRelay.GatewayURL = "https://gw.override"
	if _, _, r := resolveMCPRelayRemote(ctx, cfg2, st, h, okDeps(nil, nil, nil), logger); r.GatewayURL != "https://gw.override" {
		t.Fatalf("%+v", r)
	}
	// Egress guard: private ranges are admitted only for the enrolled org host.
	if sameHost("https://auth.acme/x", "https://org.acme") || !sameHost("http://127.0.0.1:9443/oauth2/token", "http://127.0.0.1:9443") {
		t.Fatal("sameHost")
	}
}

const projTestCursor = `{
  "theme": "dark",
  "mcpServers": {
    "gh": {"command": "npx", "args": ["-y", "gh-mcp"], "env": {"GITHUB_TOKEN": "ghp_SECRET"}},
    "observer": {"command": "/usr/local/bin/observer", "args": ["serve"]}
  }
}
`

const projTestCodex = `# keep me
model = "gpt-5"

[mcp_servers.fs]
command = "/opt/fs"
args = ["--root", "/repo"]
`

const projTestOpenCode = `{"$schema": "x", "mcp": {"gh": {"type": "local", "command": ["npx", "-y", "gh-mcp"], "enabled": true}}}`

// TestMCPRelay_ProjectionEndToEnd runs THE installation path (Sol P3+P4
// finding 2) against a migrated node DB and the real per-format writer in
// a private home: three clients (shared JSON, codex TOML, opencode) are
// wrapped with their originals journaled FIRST (env KEYS only, an owned-
// entry digest and never a whole-file digest or a backup: T-397), every
// other byte of each credential-bearing config is kept (a TOML comment
// included) and so is its mode, the relay remote entry lands where the
// loopback listener is configured, a re-apply is a no-op, a legacy row's
// backup file is removed at the next projection, the coverage matrix flips
// to mediated ONLY after the apply, and disable reverses only the
// relay-owned entries (an operator edit made in between is preserved) and
// leaves no backup anywhere.
func TestMCPRelay_ProjectionEndToEnd(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	mcpRelayHomeOverride = home
	t.Cleanup(func() { mcpRelayHomeOverride = "" })
	write := func(rel, body string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cursorPath := write(".cursor/mcp.json", projTestCursor)
	codexPath := write(".codex/config.toml", projTestCodex)
	opencodePath := write(".config/opencode/opencode.json", projTestOpenCode)

	cfg := mcpRelayTestCfg(t, true)
	cfg.MCPRelay.Listen = "127.0.0.1:8858"
	st := openMCPRelayTestStore(t, cfg)
	database, err := dbtemplate.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	_ = st
	rs := record.NewSQLStore(database, "")
	h := appliedHandle(t, cfg, "enforce", false)

	// Before: nothing applied, the matrix never claims mediation.
	before := coverage.Matrix(mcpRelayCoverageLive(ctx, cfg, rs, h, true))
	if coverage.Summary(before)[coverage.Mediated] != 0 {
		t.Fatal("matrix claims mediation before any projection")
	}
	if h.projectionApplied.Load() {
		t.Fatal("projection applied before running")
	}

	rep, remoteSkip, err := runMCPRelayProjection(ctx, cfg, "/cfg/observer.toml", rs, h, true)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	if remoteSkip != "" {
		t.Fatalf("remote entries skipped: %s", remoteSkip)
	}
	got := map[string]project.Receipt{}
	for _, r := range rep.Receipts {
		got[r.Client.Tool] = r
	}
	for _, tool := range []string{"cursor", "codex", "opencode"} {
		r, ok := got[tool]
		if !ok || !r.Changed || r.Err != "" {
			t.Fatalf("%s receipt %+v", tool, r)
		}
		if strings.Join(r.Remote, ",") != "superbased-github" {
			t.Fatalf("%s remote entries %v", tool, r.Remote)
		}
	}
	// codex's `fs` binds to no approved server (the table approves only
	// vs-gh / gh): it is NOT wrapped, stays direct, and is reported (Sol
	// P3+P4 fold finding 2 - never a guessed binding).
	if strings.Join(got["cursor"].Wrapped, ",") != "gh" || len(got["codex"].Wrapped) != 0 || strings.Join(got["opencode"].Wrapped, ",") != "gh" {
		t.Fatalf("wrapped %v / %v / %v", got["cursor"].Wrapped, got["codex"].Wrapped, got["opencode"].Wrapped)
	}
	if rf := got["codex"].Refused; len(rf) != 1 || rf[0] != (project.EntryRefusal{Key: "fs", Reason: project.RefuseNoBinding}) {
		t.Fatalf("codex refusal %+v", rf)
	}
	if !h.projectionApplied.Load() {
		t.Fatal("projection applied flag not set")
	}
	// Journal rows: originals, env KEYS only, no backup, and an applied
	// digest that is NOT a digest of the (credential-bearing) file.
	rows, err := rs.ListLaunchSpecs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("rows %d: %+v", len(rows), rows)
	}
	for _, r := range rows {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "ghp_SECRET") {
			t.Fatalf("secret value journaled: %s", raw)
		}
		if r.BackupPath != "" || r.BackupSHA256 != "" {
			t.Fatalf("a config backup was journaled: %+v", r)
		}
		cur, _ := os.ReadFile(r.ConfigPath)
		whole := sha256.Sum256(cur)
		if r.AppliedSHA256 == "" || r.AppliedSHA256 == hex.EncodeToString(whole[:]) || r.ConfigGeneration != 1 {
			t.Fatalf("applied digest / generation wrong for %+v", r)
		}
		if r.Client == "cursor" && r.EntryKey == "gh" && (r.OrigCommand != "npx" || strings.Join(r.OrigEnvRefs, ",") != "GITHUB_TOKEN") {
			t.Fatalf("cursor gh row %+v", r)
		}
		// Every stdio row carries the approved binding; a remote row none.
		isRemote := r.OrigCommand == project.RemoteOrigCommand
		if (!isRemote && (r.VServer != "vs-gh" || r.RegistryServerID != "gh")) || (isRemote && (r.VServer != "" || r.RegistryServerID != "")) {
			t.Fatalf("binding on %+v", r)
		}
	}
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	var cursorDoc map[string]any
	curBytes, _ := os.ReadFile(cursorPath)
	if err := json.Unmarshal(curBytes, &cursorDoc); err != nil {
		t.Fatal(err)
	}
	servers := cursorDoc["mcpServers"].(map[string]any)
	gh := servers["gh"].(map[string]any)
	if gh["command"] != exe || gh["env"].(map[string]any)["GITHUB_TOKEN"] != "ghp_SECRET" {
		t.Fatalf("cursor gh: %v", gh)
	}
	if args := gh["args"].([]any); args[0] != "mcp-relay" || args[1] != "wrap" || args[3] != "cursor" || args[5] != "gh" || args[7] != "/cfg/observer.toml" {
		t.Fatalf("wrap args %v", args)
	}
	if obs := servers["observer"].(map[string]any); obs["command"] != "/usr/local/bin/observer" {
		t.Fatalf("observer's own server wrapped: %v", obs)
	}
	if rel := servers["superbased-github"].(map[string]any); rel["url"] != "http://127.0.0.1:8858/mcp/github" {
		t.Fatalf("remote entry %v", rel)
	}
	if cursorDoc["theme"] != "dark" {
		t.Fatal("unrelated key lost")
	}
	// Surgical: the sibling env block keeps its exact bytes, the codex
	// comment and keys survive, every mode is kept, and no backup exists.
	if !strings.Contains(string(curBytes), `"env": {"GITHUB_TOKEN": "ghp_SECRET"}`) || !strings.Contains(string(curBytes), `"theme": "dark",`) {
		t.Fatalf("cursor config re-rendered:\n%s", curBytes)
	}
	if b, _ := os.ReadFile(codexPath); !strings.HasPrefix(string(b), "# keep me\nmodel = \"gpt-5\"\n") || !strings.Contains(string(b), "[mcp_servers.fs]\ncommand = \"/opt/fs\"\nargs = [\"--root\", \"/repo\"]\n") {
		t.Fatalf("codex config re-rendered:\n%s", b)
	}
	for _, p := range []string{cursorPath, codexPath, opencodePath} {
		if fi, err := os.Stat(p); err != nil || (posixModes && fi.Mode().Perm() != 0o644) {
			t.Fatalf("%s mode not kept: %v %v", p, fi, err)
		}
	}
	if _, err := os.Stat(mcpRelayBackupDir(cfg)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a config backup directory was created: %v", err)
	}

	// The matrix: mediated for the projected clients, stdio AND remote.
	after := coverage.Matrix(mcpRelayCoverageLive(ctx, cfg, rs, h, true))
	find := func(rows []coverage.Row, tool string, tr coverage.Transport) coverage.Coverage {
		for _, r := range rows {
			if r.Client == tool && r.Transport == tr && r.Method == coverage.MethodGoverned {
				return r.Coverage
			}
		}
		return ""
	}
	for _, tool := range []string{"cursor", "opencode"} {
		if c := find(after, tool, coverage.TransportStdio); c != coverage.Mediated {
			t.Errorf("%s stdio after apply = %s", tool, c)
		}
	}
	// codex holds only a REMOTE row: its stdio is not mediated (finding 3),
	// its remote entry is.
	if c := find(after, "codex", coverage.TransportStdio); c == coverage.Mediated {
		t.Errorf("codex stdio mediated by a remote-only row: %s", c)
	}
	if c := find(after, "codex", coverage.TransportRemoteHTTP); c != coverage.Mediated {
		t.Errorf("codex remote after apply + token = %s", c)
	}
	for _, tool := range []string{"cursor", "codex", "opencode"} {
		if c := find(before, tool, coverage.TransportStdio); c == coverage.Mediated {
			t.Errorf("%s stdio before apply = %s", tool, c)
		}
	}
	if c := find(after, "cursor", coverage.TransportRemoteHTTP); c != coverage.Mediated {
		t.Errorf("cursor remote after apply + token = %s", c)
	}
	if c := find(coverage.Matrix(mcpRelayCoverageLive(ctx, cfg, rs, h, false)), "cursor", coverage.TransportRemoteHTTP); c == coverage.Mediated {
		t.Errorf("cursor remote mediated without a token client: %s", c)
	}
	if c := find(after, "claude-code", coverage.TransportStdio); c == coverage.Mediated {
		t.Errorf("claude-code (not installed here) mediated: %s", c)
	}

	// Idempotent re-apply: nothing changes, no new rows.
	rep2, _, err := runMCPRelayProjection(ctx, cfg, "/cfg/observer.toml", rs, h, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rep2.Receipts {
		if r.Changed || r.Err != "" {
			t.Fatalf("re-apply changed %+v", r)
		}
	}
	if rows2, _ := rs.ListLaunchSpecs(ctx); len(rows2) != 5 {
		t.Fatalf("re-apply added rows: %d", len(rows2))
	}

	// A row an older build wrote (whole-file digest + a backup file): the
	// next projection converts it and removes the backup file, never
	// reading it.
	legacyBackup := filepath.Join(mcpRelayBackupDir(cfg), "legacy-cursor.bak")
	if err := os.MkdirAll(filepath.Dir(legacyBackup), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacyBackup, []byte("synthetic legacy backup"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Client == "cursor" && r.EntryKey == "gh" {
			old := r
			r.BackupPath, r.BackupSHA256, r.AppliedSHA256 = legacyBackup, "00", "11"
			if err := rs.PutLaunchSpec(ctx, r, old.ConfigGeneration); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, _, err := runMCPRelayProjection(ctx, cfg, "/cfg/observer.toml", rs, h, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(legacyBackup); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy backup not removed after conversion: %v", err)
	}
	conv, _ := rs.ListLaunchSpecs(ctx)
	for _, r := range conv {
		if r.BackupPath != "" || r.AppliedSHA256 == "11" {
			t.Fatalf("legacy row not converted: %+v", r)
		}
	}
	if a := mcpRelayAppliedState(ctx, rs); !a.StdioApplied("cursor") {
		t.Fatalf("converted row does not verify: %+v", a)
	}

	// Operator edits cursor's config after the projection; opencode and
	// codex are untouched. Disable reverses only the relay-owned entries.
	edited := strings.Replace(string(curBytes), `"theme": "dark"`, `"theme": "light"`, 1)
	if edited == string(curBytes) {
		t.Fatal("fixture edit")
	}
	if err := os.WriteFile(cursorPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	recs, rerr := restoreMCPRelayProjection(ctx, cfg, rs, h)
	if rerr != nil {
		t.Fatalf("restore: %v %+v", rerr, recs)
	}
	for _, r := range recs {
		if !r.Restored || r.Mode != project.RestoreReversal {
			t.Fatalf("%s %+v", r.Client.Tool, r)
		}
	}
	var ocWant, ocGot any
	_ = json.Unmarshal([]byte(projTestOpenCode), &ocWant)
	ocBytes, _ := os.ReadFile(opencodePath)
	if err := json.Unmarshal(ocBytes, &ocGot); err != nil || fmt.Sprint(ocGot) != fmt.Sprint(ocWant) {
		t.Fatalf("opencode values not restored:\n%s", ocBytes)
	}
	curAfter, _ := os.ReadFile(cursorPath)
	var afterDoc map[string]any
	_ = json.Unmarshal(curAfter, &afterDoc)
	if afterDoc["theme"] != "light" {
		t.Fatal("post-projection edit lost on restore")
	}
	aServers := afterDoc["mcpServers"].(map[string]any)
	if aServers["gh"].(map[string]any)["command"] != "npx" || aServers["superbased-github"] != nil || len(aServers) != 2 {
		t.Fatalf("cursor not reversed: %v", aServers)
	}
	if !strings.Contains(string(curAfter), `"env": {"GITHUB_TOKEN": "ghp_SECRET"}`) {
		t.Fatalf("restore re-rendered the sibling env block:\n%s", curAfter)
	}
	if b, _ := os.ReadFile(codexPath); !strings.HasPrefix(string(b), projTestCodex) || strings.TrimSpace(string(b)) != strings.TrimSpace(projTestCodex) {
		t.Fatalf("codex not restored (only the relay remote table was added, and only it may go):\n%s", b)
	}
	if left, _ := rs.ListLaunchSpecs(ctx); len(left) != 0 {
		t.Fatalf("rows after restore %d: %+v", len(left), left)
	}
	if h.projectionApplied.Load() {
		t.Fatal("nothing is projected; flag must clear")
	}
	if _, err := os.Stat(mcpRelayBackupDir(cfg)); err == nil {
		if ents, _ := os.ReadDir(mcpRelayBackupDir(cfg)); len(ents) != 0 {
			t.Fatalf("backup files left behind: %v", ents)
		}
	}
}
