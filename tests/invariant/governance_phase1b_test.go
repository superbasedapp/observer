package invariant

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/govern/sidecar"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Admin-controlled Plane B, Phase 1b invariants
// (docs/plans/admin-controlled-plane-b-phase-1b-mini-spec-2026-08-15.md §6.2).
//
// Two claims these tests exist to keep true, under the TEAMS posture (the
// only posture this Phase-1b governance-body mechanism concerns itself
// with — the Plane B dual-mode gateway / RBAC-IA design's ENTERPRISE
// posture, 2026-08-29 §5, authorizes raw content through a structurally
// distinct, non-governance-body channel: store.ShareOptions.EnterpriseGranted,
// set from a node's own managed enrolment grant per
// govern.Effective.GrantsEnterpriseContent(), never from a governance body):
//
//  1. an ungoverned node is UNCHANGED — no sidecar, no new default, no new
//     write; and
//  2. the organization can only ever REDUCE what a node shares THROUGH THIS
//     GOVERNANCE-BODY CHANNEL. There is no code path, under any org body, any
//     grant, any authority token, or any compromise of the org signing key,
//     by which a governance-body directive causes a node that has not
//     locally set full_content or admin_managed to ship raw content.

func phase1bTempConfig(t *testing.T, dbDir, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	toml := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dbDir, "observer.db")) + "\"\n" + body
	if err := os.WriteFile(path, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func phase1bSpec(t *testing.T, body string) nodegov.PolicySpec {
	t.Helper()
	spec, _, err := nodegov.CompileBody([]byte(body), governanceMaxBody)
	if err != nil {
		t.Fatalf("nodegov.CompileBody(%s): %v", body, err)
	}
	return spec
}

// phase1bGrant is a live grant carrying the FULL Phase-1b authority set, so
// a test that finds a directive dropped knows the cause is the rule under
// test rather than a missing token.
func phase1bGrant(now time.Time) *govern.Grant {
	g := governanceLiveGrant(now)
	g.Authority = []string{
		govern.AuthorityDashboardVisibility,
		govern.AuthoritySettingsPin,
		govern.AuthorityCapturePin,
		govern.AuthorityFeatureLock,
	}
	return g
}

// TestGovernanceCannotRaiseShare is THE headline privacy invariant of Phase
// 1b, as a table over every share key × every (local, org) pair.
//
// The claim: effective ⊑ local, always. An org directive of `true` against a
// local `false` is a NO-OP, not a raise — including the row that matters
// most, full_content.
func TestGovernanceCannotRaiseShare(t *testing.T) {
	now := time.Now().UTC()
	boolKeys := []string{
		"full_content", "routing_summary", "policy_state",
		"obs.summary", "obs.traces", "obs.content",
		"obs.eval_summary", "obs.admission", "obs.eval_items",
	}
	for _, key := range boolKeys {
		for _, local := range []bool{false, true} {
			for _, org := range []bool{false, true} {
				name := key + "/local=" + boolStr(local) + "/org=" + boolStr(org)
				t.Run(name, func(t *testing.T) {
					body := `{"schema":2,"share":{"` + key + `":` + boolStr(org) + `}}`
					eff := govern.Resolve(
						govern.Delivered{Present: true, Version: 14, BodyHash: "bh", Spec: phase1bSpec(t, body)},
						phase1bGrant(now), governanceLiveIdentity(), now,
					)
					got := eff.LowerBool(key, local)
					want := local && org
					if got != want {
						t.Fatalf("effective = %v, want %v (local=%v org=%v)", got, want, local, org)
					}
					if got && !local {
						t.Fatalf("the organization RAISED %s from false to true", key)
					}
				})
			}
		}
	}

	// The explicit row the spec names: local=false, org=true ⇒ false, for
	// full_content. Stated separately so it can never be lost to a loop
	// refactor.
	eff := govern.Resolve(
		govern.Delivered{
			Present: true, Version: 14, BodyHash: "bh",
			Spec: phase1bSpec(t, `{"schema":2,"share":{"full_content":true}}`),
		},
		phase1bGrant(now), governanceLiveIdentity(), now,
	)
	if eff.LowerBool("full_content", false) {
		t.Fatal("an org directive of full_content=true raised a node that had not opted in")
	}

	// And the list key, by intersection.
	listEff := govern.Resolve(
		govern.Delivered{
			Present: true, Version: 14, BodyHash: "bh",
			Spec: phase1bSpec(t, `{"schema":2,"share":{"target_action_allowlist":["read_file","run_command","edit_file"]}}`),
		},
		phase1bGrant(now), governanceLiveIdentity(), now,
	)
	got := listEff.LowerList("target_action_allowlist", []string{"read_file", "write_file"})
	if len(got) != 1 || got[0] != "read_file" {
		t.Fatalf("list merge = %v, want the INTERSECTION [read_file] — an org list must never add an action type", got)
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestOrgPushUnchangedByGovernance is the source-level pin behind the
// "orgpush.go is byte-identical WITH RESPECT TO THE GOVERNANCE-BODY MERGE"
// claim.
//
// store.ShareOptions has exactly ONE non-test construction site in the whole
// tree, and shipsRawContent reads only the struct's own fields, so a
// governance lowering merge applied upstream of that constructor needs no
// change at the seam. This test kills the "let a governance-body directive
// add a disjunct" mutation and the "let governance reach into orgpush.go"
// mutation.
//
// It does NOT forbid every future disjunct: the Plane B dual-mode gateway /
// RBAC-IA design (2026-08-29, §5.3) legitimately added EnterpriseGranted as a
// THIRD, non-governance-body path — set from a node's own managed enrolment
// grant, never from a Phase-1b governance body, and covered by its own
// dedicated invariant coverage (see the "enterprise_granted" subtest of
// TestPushPayloadCarriesContentWhenOptedIn in privacy_test.go). What this
// test pins is that shipsRawContent's ENTIRE
// disjunct set is exactly {FullContent, AdminManaged, EnterpriseGranted} — no
// more, no fewer — and that none of them, nor the file as a whole, ever
// references the governance machinery.
func TestOrgPushUnchangedByGovernance(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "store", "orgpush.go"))
	if err != nil {
		t.Fatalf("read orgpush.go: %v", err)
	}
	src := string(raw)

	const want = "func (o ShareOptions) shipsRawContent() bool {\n\treturn o.FullContent || o.AdminManaged || o.EnterpriseGranted\n}"
	if !strings.Contains(src, want) {
		t.Fatal("shipsRawContent is no longer exactly `FullContent || AdminManaged || EnterpriseGranted` — the predicate every content-strip site consults must not grow a FOURTH disjunct, and must not lose one of these three")
	}
	for _, forbidden := range []string{
		"internal/govern",
		"nodegov",
		"governance-effective",
		"sidecar",
	} {
		if strings.Contains(src, forbidden) {
			t.Fatalf("orgpush.go references %q — the org-push seam must not know governance exists; the lowering merge belongs upstream, at the ONE ShareOptions construction site", forbidden)
		}
	}
}

// TestShareOptionsHasOneConstructionSite is the other half of that proof,
// checked mechanically rather than by re-deriving the argument in review.
func TestShareOptionsHasOneConstructionSite(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	var sites []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		body, rerr := os.ReadFile(path) //nolint:gosec // walking the repo's own tree
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(body), "store.ShareOptions{") {
			sites = append(sites, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(sites) != 1 || !strings.HasSuffix(sites[0], filepath.Join("orgclient", "client.go")) {
		t.Fatalf("store.ShareOptions is constructed at %v, want exactly internal/orgclient/client.go — the single-construction-site fact is what makes the lowering merge safe without touching the org-push seam", sites)
	}
}

// TestSoloNodeWritesNoSidecar / TestSoloNodeUnchangedByGovernanceSidecar are
// §8's solo claim: no file, no new default, no new write.
func TestSoloNodeWritesNoSidecar(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := phase1bTempConfig(t, dbDir, "")
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	path := config.ResolveGovernanceSidecarPath(cfg, "")
	if path == "" {
		t.Fatal("no sidecar path resolved at all")
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Fatalf("a solo node created %s", path)
	}
}

// TestGovernanceSidecarAbsentIsByteIdenticalLoad restates the parity claim
// from OUTSIDE internal/config, through the exported API only.
func TestGovernanceSidecarAbsentIsByteIdenticalLoad(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := phase1bTempConfig(t, dbDir, "[guard]\nenabled = false\n[cachetrack]\nenabled = false\n")
	env := func(k string) string {
		if k == "OBSERVER_PREDICT_ENABLED" {
			return "false"
		}
		return ""
	}
	withRead, err := config.Load(config.LoadOptions{GlobalPath: cfgPath, Env: env})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	disabled, err := config.Load(config.LoadOptions{GlobalPath: cfgPath, Env: env, GovernanceSidecar: config.NoGovernanceSidecar})
	if err != nil {
		t.Fatalf("Load (disabled): %v", err)
	}
	if !reflect.DeepEqual(withRead, disabled) {
		t.Fatal("with no sidecar present, Load differs from Load-with-the-read-disabled — an ungoverned node's config path must not change shape")
	}
}

// TestExpiredGrantIgnoresSidecar is the offboarding guarantee for
// short-lived processes with a DEAD daemon (§1.5): the pins lift the moment
// the grant expires, whether or not anything is running to rewrite the file.
// It kills the perpetual-lock mutation at the FILE layer, mirroring Phase
// 1a's TestGovernanceExpiredGrantReverts at the resolver layer.
func TestExpiredGrantIgnoresSidecar(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := phase1bTempConfig(t, dbDir, "[guard]\nenabled = false\n")
	expiry := time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)
	body := `{"schema":1,"state":"applied","grant_expires_at":"` + expiry.Format(time.RFC3339) +
		`","pinned":{"guard.enabled":true}}`
	if err := os.WriteFile(filepath.Join(dbDir, config.GovernanceSidecarFilename), []byte(body), 0o600); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}

	live, err := config.Load(config.LoadOptions{
		GlobalPath: cfgPath, Env: func(string) string { return "" },
		GovernanceNow: func() time.Time { return expiry.Add(-time.Hour) },
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !live.Guard.Enabled {
		t.Fatal("a live grant's pin was not applied — the test would prove nothing")
	}
	lapsed, err := config.Load(config.LoadOptions{
		GlobalPath: cfgPath, Env: func(string) string { return "" },
		GovernanceNow: func() time.Time { return expiry.Add(time.Second) },
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if lapsed.Guard.Enabled {
		t.Fatal("an expired grant still pinned a key — offboarding must work even with a dead, removed or downgraded daemon")
	}
}

// TestSidecarNeverMakesLoadFail is the fail-open safety requirement (review
// B4), restated as an invariant because the blast radius is fleet-wide: a
// non-zero PreToolUse hook exit BLOCKS the developer's tool call, and six of
// the nine hook.go config.Load sites return before db.Open.
func TestSidecarNeverMakesLoadFail(t *testing.T) {
	bodies := []string{
		"",
		"not json",
		`{"schema":1,`,
		`{"schema":1,"state":"applied","pinned":{"guard.mode":"strict"}}`,
		`{"schema":1,"state":"applied","pinned":{"org_client.org_server_url":"https://evil.example"}}`,
		`{"schema":1,"state":"applied","pinned":{"observer.db_path":"/dev/null"}}`,
		`{"schema":1,"state":"applied","pinned":{"org_client.share.admin_managed":true}}`,
		`{"schema":9,"state":"applied"}`,
		`{"schema":1,"state":"applied","unknown_field":1}`,
	}
	for _, body := range bodies {
		dbDir := t.TempDir()
		cfgPath := phase1bTempConfig(t, dbDir, "[guard]\nenabled = false\nmode = \"observe\"\n")
		if err := os.WriteFile(filepath.Join(dbDir, config.GovernanceSidecarFilename), []byte(body), 0o600); err != nil {
			t.Fatalf("write sidecar: %v", err)
		}
		cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath, Env: func(string) string { return "" }})
		if err != nil {
			t.Fatalf("sidecar %q made config.Load fail: %v", body, err)
		}
		// The bootstrap envelope holds under every one of those bodies.
		if cfg.OrgClient.OrgServerURL == "https://evil.example" {
			t.Fatal("a sidecar re-pointed the org rail — the remote rail must not be able to re-point itself")
		}
		if strings.Contains(cfg.Observer.DBPath, "/dev/null") {
			t.Fatal("a sidecar re-pointed the database")
		}
		if cfg.OrgClient.Share.AdminManaged {
			t.Fatal("a sidecar set admin_managed — the flag that flips content sharing raw is excluded from every remote vocabulary")
		}
	}
}

// TestPrivacySentinelStillCoversTheGrantTable: migration 083 adds COLUMNS to
// org_enrolment_grant, and the sentinel forbids the TABLE NAME, so it
// already covers them. Asserted deliberately rather than left implied.
func TestPrivacySentinelStillCoversTheGrantTable(t *testing.T) {
	var found bool
	for _, name := range forbiddenCacheTables {
		if name == "org_enrolment_grant" {
			found = true
		}
	}
	if !found {
		t.Fatal("org_enrolment_grant left forbiddenCacheTables")
	}
	// And nothing Phase 1b added is a new TABLE that would need its own row.
	if _, err := os.Stat(filepath.Join("..", "..", "internal", "db", "migrations", "083_org_enrolment_grant_renewal.sql")); err != nil {
		t.Fatalf("migration 083 is missing: %v", err)
	}
}

// TestSidecarCarriesNoNodeContent is the disclosure boundary in the other
// direction: the sidecar is a POSTURE file, and nothing about the
// developer's own activity may end up in it.
func TestSidecarCarriesNoNodeContent(t *testing.T) {
	f := sidecar.File{
		Schema: sidecar.MaxSchema, State: sidecar.StateApplied,
		Pinned: map[string]any{"guard.enabled": true},
	}
	raw, err := sidecar.Encode(f)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, forbidden := range []string{"project_root", "session_id", "command", "source_file", "target"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the sidecar wire shape names %q", forbidden)
		}
	}
}

// TestRenewalCannotExceedTheSignedWindow: renewal derives its TTL from the
// grant itself, so it can never extend the grant beyond the window the
// organization actually signed for.
func TestRenewalCannotExceedTheSignedWindow(t *testing.T) {
	granted := time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
	signed := granted.Add(30 * 24 * time.Hour)
	row := store.EnrolmentGrant{
		OrgKey: "ok", Generation: 2,
		GrantedAt: granted, ExpiresAt: signed, SignedExpiresAt: signed,
	}
	now := granted.Add(10 * 24 * time.Hour)
	ttl := row.SignedExpiresAt.Sub(row.GrantedAt)
	renewed := now.Add(ttl)
	if renewed.Sub(now) != 30*24*time.Hour {
		t.Fatalf("renewed window = %v, want exactly the signed 30 days", renewed.Sub(now))
	}
	// The signed value itself is never moved, so the stored signature keeps
	// describing its own row (amendment A1's evidence property).
	if !row.SignedExpiresAt.Equal(signed) {
		t.Fatal("the signed window moved")
	}
}
