package invariant

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestSandboxPostureCarriesNoRunIdentity pins the sandbox posture aggregate
// (sandbox plan v2 section 8.4): under terminal_detail WITHOUT raw content
// it ships per-day counts by the closed enums only. The seeded run's tool,
// run id, session, project hash, digest and producer inputs never appear,
// and SandboxPostureRow has no field that could carry them.
func TestSandboxPostureCarriesNoRunIdentity(t *testing.T) {
	const secret = "SECRET_SBXPOSTURE_obstreperous_zz"
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	if err := st.InsertTerminalRun(ctx, store.TerminalRun{
		RunID: secret, Tool: secret, Kind: "fresh", SourceSessionID: secret,
		ProjectRootHash: secret, CorrelationTokenHash: secret,
		Isolation: store.TerminalRunIsolation{
			Class: "process", Stack: []string{"bwrap"}, CaptureLevel: "full", CaptureOrigin: "sandboxed",
			Verification: "live", KeyCustody: "host_bound", EvidenceDigest: secret,
			EvidenceProducer: "terminal_run", EvidenceComponent: secret, EvidenceComponentVersion: secret,
			// A seccomp value outside the closed vocabulary never leaves
			// the node (lane FU4: it counts as not recorded).
			Seccomp: secret,
		},
	}); err != nil {
		t.Fatalf("InsertTerminalRun: %v", err)
	}
	st.SetSandboxCapabilityProvider(func() (orgcontract.SandboxCapabilityRow, bool) {
		return orgcontract.SandboxCapabilityRow{Backends: []string{"bwrap"}, MaxClass: "process", FullCapture: true}, true
	})
	batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x",
		store.ShareOptions{TerminalDetail: true}, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(batch.SandboxPosture) != 1 || batch.SandboxPosture[0].Runs != 1 {
		t.Fatalf("posture %+v, want one bucket of one run", batch.SandboxPosture)
	}
	// The terminal summaries of the same tier carry the tool by design; the
	// check is on what the posture adds.
	raw, err := json.Marshal(struct {
		Posture    []orgcontract.SandboxPostureRow
		Capability *orgcontract.SandboxCapabilityRow
	}{batch.SandboxPosture, batch.SandboxCapability})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Errorf("a run identity, hash or digest leaked into the sandbox posture: %s", raw)
	}
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true, "Day": true, "IsolationClass": true, "CaptureLevel": true,
		"CaptureOrigin": true, "Verification": true, "NativeSandboxState": true, "KeyCustody": true, "Runs": true,
		// Seccomp (lane FU4, tracker F-002): run counts keyed by the closed
		// sandboxvocab.SeccompRun vocabulary, filtered on the node and
		// clamped at ingest; the seeded out-of-vocabulary value above
		// proves an unknown key never ships.
		"Seccomp": true,
	}
	rt := reflect.TypeOf(orgcontract.SandboxPostureRow{})
	for i := 0; i < rt.NumField(); i++ {
		if !allowed[rt.Field(i).Name] {
			t.Errorf("SandboxPostureRow.%s is not in the reviewed enum-and-count field set", rt.Field(i).Name)
		}
	}
	// The capability row is pinned the same way (P-017 (g)): closed backend
	// ids, one class enum and two booleans, beside the forced attribution.
	// It ships from every node where the module resolves active, which
	// includes an install with no [components] block, so it must stay
	// content-free.
	// ManagedRefused (lane sbx-p2e) is a list of closed (key, reason) pairs,
	// pinned below to two string fields and clamped at ingest.
	capAllowed := map[string]reflect.Kind{
		"OrgID": reflect.String, "UserEmail": reflect.String, "Backends": reflect.Slice,
		"MaxClass": reflect.String, "FullCapture": reflect.Bool, "Beta": reflect.Bool,
		"ManagedRefused": reflect.Slice,
	}
	ct := reflect.TypeOf(orgcontract.SandboxCapabilityRow{})
	if ct.NumField() != len(capAllowed) {
		t.Errorf("SandboxCapabilityRow has %d fields, the reviewed set has %d", ct.NumField(), len(capAllowed))
	}
	for i := 0; i < ct.NumField(); i++ {
		f := ct.Field(i)
		if k, ok := capAllowed[f.Name]; !ok || k != f.Type.Kind() {
			t.Errorf("SandboxCapabilityRow.%s (%s) is not in the reviewed enum-and-boolean field set", f.Name, f.Type.Kind())
		}
	}
	if ct.NumField() > 0 {
		if b, ok := ct.FieldByName("Backends"); ok && b.Type.Elem().Kind() != reflect.String {
			t.Errorf("SandboxCapabilityRow.Backends must stay a list of closed ids")
		}
		if m, ok := ct.FieldByName("ManagedRefused"); ok {
			et := m.Type.Elem()
			if et.Kind() != reflect.Struct || et.NumField() != 2 {
				t.Errorf("SandboxCapabilityRow.ManagedRefused must stay a list of (key, reason) pairs")
			} else {
				for i := 0; i < et.NumField(); i++ {
					if f := et.Field(i); (f.Name != "Key" && f.Name != "Reason") || f.Type.Kind() != reflect.String {
						t.Errorf("SandboxCapabilityRow.ManagedRefused.%s is not a closed key or reason", f.Name)
					}
				}
			}
		}
	}
}

// TestSandboxEgressCountsCarryNoHost pins the sandbox egress refusal counts
// (audit CG-15, decision D-11): a MANAGED node ships per (day, tier, closed
// rule) counts and nothing else, even with every content tier on; the seeded
// refusal's host, port, deciding key, project root, run id and an
// out-of-vocabulary rule never appear; an individual node ships none in any
// posture; and SandboxEgressRefusalDayRow has no field that could carry one.
func TestSandboxEgressCountsCarryNoHost(t *testing.T) {
	const secret = "SECRET_SBXEGRESS_quixotic_zz"
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	for i, rule := range []string{"allow-list-miss", secret} {
		if _, err := st.InsertSandboxEgressRefusal(ctx, store.SandboxEgressRefusal{
			RunID: secret, ProjectRoot: "/home/dev/" + secret, Backend: "bwrap", Tier: "proxy_only",
			Host: secret + "-" + string(rune('a'+i)) + ".example", Port: 31337, Rule: rule, Key: "terminal.sandbox." + secret,
		}); err != nil {
			t.Fatalf("InsertSandboxEgressRefusal: %v", err)
		}
	}
	if err := st.AddSandboxEgressRefusalDrops(ctx, secret, 2, 0, time.Time{}); err != nil {
		t.Fatalf("AddSandboxEgressRefusalDrops: %v", err)
	}
	wide := store.ShareOptions{FullContent: true, AdminManaged: true, EnterpriseGranted: true, FullToolBodies: true, TerminalDetail: true}
	ind, err := store.New(database).SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", wide, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	if len(ind.SandboxEgressRefusals) != 0 {
		t.Fatalf("an individual node shipped refusal counts: %+v", ind.SandboxEgressRefusals)
	}
	wide.Managed = true
	batch, err := store.New(database).SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", wide, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	var refusals, dropped int64
	for _, r := range batch.SandboxEgressRefusals {
		refusals += r.Refusals
		dropped += r.Dropped
	}
	if refusals != 2 || dropped != 2 {
		t.Fatalf("counts %+v, want 2 refusals and 2 dropped", batch.SandboxEgressRefusals)
	}
	raw, err := json.Marshal(batch.SandboxEgressRefusals)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leak := range []string{secret, "31337", "bwrap", "/home/dev"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("%q leaked into the sandbox egress counts: %s", leak, raw)
		}
	}
	allowed := map[string]reflect.Kind{
		"OrgID": reflect.String, "UserEmail": reflect.String, "Day": reflect.String,
		"Tier": reflect.String, "Rule": reflect.String, "Refusals": reflect.Int64, "Dropped": reflect.Int64,
	}
	rt := reflect.TypeOf(orgcontract.SandboxEgressRefusalDayRow{})
	if rt.NumField() != len(allowed) {
		t.Errorf("SandboxEgressRefusalDayRow has %d fields, the reviewed set has %d", rt.NumField(), len(allowed))
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if k, ok := allowed[f.Name]; !ok || k != f.Type.Kind() {
			t.Errorf("SandboxEgressRefusalDayRow.%s (%s) is not in the reviewed enum-and-count field set", f.Name, f.Type.Kind())
		}
	}
}

// TestSecurityWireCanaries is the security plan 7.4 per-field canary test
// (lane SEC-E2, revision 2.4 [JSP-1]: tag-driven). A canary is planted in
// every content-bearing source column of the node-local sec_* tables,
// including the ones that must never ship; the push is composed through the
// SecurityOrgProviders seam (bound to the store's own reads, as the cmd
// layer binds them) at the findings level and captured in the three share
// modes: metadata only, shipsRawContent(), and the full-tool-bodies tier
// alone. Each canary must appear only where its 7.4 class allows. Every
// canary is shaped to pass the wire normalization, so an absence proves the
// gate, not the normalizer.
func TestSecurityWireCanaries(t *testing.T) {
	if !securityInBuild {
		t.Skip("the security module is compiled out (sbo_omit_security): no sec_* read exists to plant canaries behind")
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	type canary struct{ col, value, class string }
	hex := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	cols := []canary{
		// never: node-local identity, location-free key, per-node root hash,
		// rendered text.
		{"id", "CANARYIDneverq9", "never"},
		{"local_key", "CANARYLOCALKEYneverq9", "never"},
		{"project_root_hash", "CANARYROOTHASHneverq9", "never"},
		{"message", "CANARY_MESSAGE_never AKIAIOSFODNN7EXAMPLE", "never"},
		{"fix_hint", "CANARY_FIXHINT_never", "never"},
		// raw: only under shipsRawContent().
		{"rel_path", "src/CANARYRELPATHraw.go", "raw"},
		{"path_aliases_json", `["old/CANARYALIASraw.go"]`, "raw"},
		{"evidence_redacted", "CANARY_EVIDENCE_raw", "raw"},
		{"commit_sha", hex('c', 40), "raw"},
		{"patch_fp", hex('d', 64), "raw"},
		{"baseline_ref_json", `{"Kind":"commit","Ref":"CANARYBASEREFraw","PackVersion":"CANARYPACKVERalways","PolicyVersion":"CANARYPOLVERalways"}`, "raw"},
		// always.
		{"org_key", hex('e', 64), "always"},
		{"rule_id", "CANARY-RULE-always", "always"},
		{"rule_version", "CANARYRULEVERalways", "always"},
		{"rule_pack", "CANARYRULEPACKalways", "always"},
		{"rule_pack_version", "CANARYPACKVERSIONalways", "always"},
		{"driver", "CANARYDRIVERalways", "always"},
		{"driver_version", "CANARYDRIVERVERalways", "always"},
		{"engine_digest", hex('a', 64), "always"},
		{"database_epoch", "CANARYEPOCHalways", "always"},
		{"refs_json", `{"CWE":["CWE-CANARY"]}`, "always"},
		{"project_identity_hash", hex('1', 64), "always"},
		{"org_project_id", "CANARYORGPROJECTalways", "always"},
		{"evidence_hash", hex('2', 64), "always"},
		{"attribution_method", "CANARYMETHODalways", "always"},
		{"session_id", "CANARYSESSIONalways", "always"},
		{"action_id", "CANARYACTIONalways", "always"},
		{"prompt_action_id", "CANARYPROMPTACTIONalways", "always"},
		{"tool", "CANARYTOOLalways", "always"},
		{"tool_version", "CANARYTOOLVERalways", "always"},
		{"model", "CANARYMODELalways", "always"},
		{"surface", "CANARYSURFACEalways", "always"},
		{"taint_origin_class", "CANARYTAINTCLASSalways", "always"},
		{"exception_id", "CANARYEXCEPTIONalways", "always"},
		{"verdict_ids_json", `["CANARYVERDICTalways"]`, "always"},
	}
	names := []string{"category", "severity", "confidence", "status", "baseline", "first_seen", "last_seen"}
	args := []any{"secret", "high", "high", "open", "new", time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano)}
	for _, c := range cols {
		names, args = append(names, c.col), append(args, c.value)
	}
	q := "INSERT INTO sec_findings (" + strings.Join(names, ", ") + ") VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(names)), ",") + ")"
	if _, err := database.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("seed sec_findings: %v", err)
	}
	// The sightings, commits and scan runs never ship in any form.
	for _, seed := range []struct {
		q    string
		args []any
	}{
		{`INSERT INTO sec_finding_sightings (finding_id, rel_path, last_seen) VALUES (?, ?, ?)`, []any{"CANARYIDneverq9", "sight/CANARYSIGHTINGnever.go", "2026-10-21T00:00:00Z"}},
		{`INSERT INTO sec_finding_commits (finding_id, commit_sha, last_seen) VALUES (?, ?, ?)`, []any{"CANARYIDneverq9", hex('9', 40), "2026-10-21T00:00:00Z"}},
		{`INSERT INTO sec_scan_runs (project_root_hash, driver, scope, target_json, outcome, started_at) VALUES (?, ?, ?, ?, ?, ?)`, []any{"CANARYROOTHASHneverq9", "CANARYSCANDRIVERnever", "manual", `{"path":"CANARYSCANTARGETnever"}`, "clean", time.Now().UTC().Format(time.RFC3339Nano)}},
	} {
		if _, err := database.ExecContext(ctx, seed.q, seed.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	never := []string{"CANARYSIGHTINGnever", hex('9', 40), "CANARYSCANDRIVERnever", "CANARYSCANTARGETnever", "AKIAIOSFODNN7EXAMPLE"}

	modes := []struct {
		name  string
		share store.ShareOptions
		raw   bool
	}{
		{"metadata_only", store.ShareOptions{}, false},
		{"raw_content", store.ShareOptions{FullContent: true}, true},
		{"tool_bodies_only", store.ShareOptions{FullToolBodies: true}, false},
	}
	for _, m := range modes {
		st := store.New(database)
		st.SetSecurityOrgProviders(store.SecurityOrgProviders{
			Level: func(context.Context, store.ShareOptions) store.SecurityShare {
				return store.SecurityShare{Level: orgcontract.SecurityShareFindings, HoldsOrgKey: true}
			},
			Posture: func(ctx context.Context, day string, scope store.SecurityScope) (orgcontract.SecurityPostureRow, bool, error) {
				r, err := st.SecurityPostureFacts(ctx, day, time.Now().UTC(), scope)
				return r, err == nil, err
			},
			Findings: st.SelectSecurityFindingRows,
		})
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 4<<20, "org-1", "dev@x", m.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: SelectUnpushedSince: %v", m.name, err)
		}
		if len(batch.SecurityFindings) != 1 || len(batch.SecurityPosture) != 1 {
			t.Fatalf("%s: want one finding and one posture row, got %d and %d", m.name, len(batch.SecurityFindings), len(batch.SecurityPosture))
		}
		raw, err := json.Marshal(orgcontract.PushEnvelope{SecurityFindings: batch.SecurityFindings, SecurityPosture: batch.SecurityPosture})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range cols {
			// The canary as it reaches the wire: inside a JSON column it is
			// the inner value.
			v := c.value
			for _, inner := range []string{"old/CANARYALIASraw.go", "CANARYBASEREFraw", "CWE-CANARY", "CANARYVERDICTalways"} {
				if strings.Contains(v, inner) {
					v = inner
				}
			}
			present := bytes.Contains(raw, []byte(v))
			want := c.class == "always" || (c.class == "raw" && m.raw)
			if present != want {
				t.Errorf("%s: %s (%s) present=%v, want %v", m.name, c.col, c.class, present, want)
			}
		}
		for _, v := range append(never, "CANARYPACKVERalways", "CANARYPOLVERalways") {
			present := bytes.Contains(raw, []byte(v))
			if want := strings.HasSuffix(v, "always"); present != want {
				t.Errorf("%s: %s present=%v, want %v", m.name, v, present, want)
			}
		}
	}
	// The tags drive the strip: every security wire row is fully classified.
	for _, rt := range orgcontract.SecurityWireRowTypes() {
		if err := orgcontract.CheckSecurityWireTags(rt); err != nil {
			t.Error(err)
		}
	}
}

// TestSecurityWireSecretCanary is ruling P-055's canary (lane SEC-E2 audit
// finding 4): known secrets of several detector types are planted in every
// text a security wire row is built from (the redacted evidence, a clipped
// evidence window ending in a piece of a secret, the path, a path alias, the
// baseline reference, an always-class field, and the AI change record's
// paths and model list); every security wire row is built in the three share
// modes (metadata only, an individual's full_content, a managed node's
// enterprise grant) plus the tool-bodies tier; the test fails if any secret
// value, or any 8 or more character piece of one, appears in any row. A row
// with no secret must still ship, so a pass is never vacuous.
func TestSecurityWireSecretCanary(t *testing.T) {
	if !securityInBuild {
		t.Skip("the security module is compiled out (sbo_omit_security)")
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()

	// One value per detector type; each is checked to be detected before use.
	// The fake key values are split so GitHub push protection on the public
	// mirror does not read them as real credentials (same runtime bytes).
	secrets := map[string]string{
		"aws_access_key":    "AKIA" + "QWRTYPLMNBVCXZ23",
		"github_pat":        "ghp_Zq8mWv3TnR6yKp2LsX9uBd4HjF7cGe1NwQ",
		"gcp_api_key":       "AIza" + "SyQ7vN2mK8pL4wR1tX6yU3oZ9cB5dF0gHjK",
		"private_key_block": "MIIEowIBAAKCAQEA" + "zq9vXk7Lp2Rw4Tm8Ny6Hb3Qj",
		"secret_assignment": "Hunter2CorrectHorseBatteryStaple",
	}
	contexts := map[string]string{
		"aws_access_key":    "aws = " + secrets["aws_access_key"],
		"github_pat":        "token " + secrets["github_pat"],
		"gcp_api_key":       "key: " + secrets["gcp_api_key"],
		"private_key_block": "-----BEGIN RSA PRIVATE KEY----- " + secrets["private_key_block"] + " -----END RSA PRIVATE KEY-----",
		"secret_assignment": "password=" + secrets["secret_assignment"],
	}
	for typ, c := range contexts {
		found := false
		for _, f := range scrub.DetectSecrets(c) {
			if f.Type == typ {
				found = true
			}
		}
		if !found {
			t.Fatalf("canary precondition: %s is not detected in %q", typ, c)
		}
	}
	evidence := ""
	for _, typ := range []string{"aws_access_key", "github_pat", "gcp_api_key", "private_key_block", "secret_assignment"} {
		evidence += contexts[typ] + " ; "
	}
	evidence = strings.TrimSuffix(evidence, " ; ")
	// A window clipped at the 240-rune cap whose last token is the first 16
	// characters of a token no detector recognises on its own.
	clipped := strings.Repeat("y", 240-len(" config ")-16) + " config " + secrets["github_pat"][:16]
	hex := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	now := time.Now().UTC().Format(time.RFC3339Nano)
	seed := func(id, evidence, relPath, aliases, baseRef, model string) {
		t.Helper()
		if _, err := database.ExecContext(ctx, `INSERT INTO sec_findings (id, project_root_hash, local_key, rule_id, category, severity,
			confidence, status, baseline, first_seen, last_seen, rel_path, path_aliases_json, evidence_redacted, evidence_hash,
			baseline_ref_json, model) VALUES (?, 'r1', ?, 'S-721', 'secret', 'high', 'high', 'open', 'new', ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, "k-"+id, now, now, relPath, aliases, evidence, hex('2', 64), baseRef, model); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	seed("f-masked", evidence, "keys/"+secrets["aws_access_key"]+".txt",
		`["old/`+secrets["github_pat"]+`.env","old/clean.go"]`, `{"Kind":"commit","Ref":"`+secrets["aws_access_key"]+`"}`, "claude-opus")
	seed("f-clipped", clipped, "src/clean.go", "", "", "claude-opus")
	seed("f-always", "nothing here", "src/other.go", "", "", secrets["aws_access_key"])

	changeRecords := func(context.Context, int, store.SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
		return []orgcontract.AIChangeRecordRow{
			{CommitIdentityHash: hex('c', 64), Paths: []string{"deploy/" + secrets["gcp_api_key"] + ".yml", "src/ok.go"}, Models: []string{"claude-opus"}},
			{CommitIdentityHash: hex('d', 64), Models: []string{secrets["aws_access_key"]}},
		}, nil
	}
	modes := []struct {
		name  string
		share store.ShareOptions
		raw   bool
	}{
		{"individual_metadata_only", store.ShareOptions{}, false},
		{"individual_full_content", store.ShareOptions{FullContent: true}, true},
		{"managed_enterprise_grant", store.ShareOptions{EnterpriseGranted: true}, true},
		{"tool_bodies_only", store.ShareOptions{FullToolBodies: true}, false},
	}
	for _, m := range modes {
		st := store.New(database)
		st.SetSecurityOrgProviders(store.SecurityOrgProviders{
			Level: func(context.Context, store.ShareOptions) store.SecurityShare {
				return store.SecurityShare{Level: orgcontract.SecurityShareFindings, HoldsOrgKey: true}
			},
			Posture: func(ctx context.Context, day string, scope store.SecurityScope) (orgcontract.SecurityPostureRow, bool, error) {
				r, err := st.SecurityPostureFacts(ctx, day, time.Now().UTC(), scope)
				return r, err == nil, err
			},
			Findings:      st.SelectSecurityFindingRows,
			ChangeRecords: changeRecords,
		})
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 4<<20, "org-1", "dev@x", m.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: SelectUnpushedSince: %v", m.name, err)
		}
		wire, err := json.Marshal(orgcontract.PushEnvelope{SecurityFindings: batch.SecurityFindings, SecurityPosture: batch.SecurityPosture, AIChangeRecords: batch.AIChangeRecords})
		if err != nil {
			t.Fatal(err)
		}
		for typ, v := range secrets {
			for i := 0; i+8 <= len(v); i++ {
				if piece := v[i : i+8]; bytes.Contains(wire, []byte(piece)) {
					t.Errorf("%s: an 8-character piece %q of the %s secret reached the wire", m.name, piece, typ)
					break
				}
			}
		}
		// Not vacuous: the two clean findings and the clean change record ship,
		// and under raw content the masked excerpt and the clean alias ship.
		if len(batch.SecurityFindings) != 2 || len(batch.AIChangeRecords) != 1 || len(batch.SecurityPosture) != 1 {
			t.Fatalf("%s: shipped %d findings, %d change records, %d posture rows; want 2, 1, 1", m.name, len(batch.SecurityFindings), len(batch.AIChangeRecords), len(batch.SecurityPosture))
		}
		if m.raw {
			for _, want := range []string{"[REDACTED:aws_access_key]", "old/clean.go", "src/ok.go"} {
				if !bytes.Contains(wire, []byte(want)) {
					t.Errorf("%s: %q missing from a raw-content push: %s", m.name, want, wire)
				}
			}
		} else if bytes.Contains(wire, []byte("REDACTED")) || bytes.Contains(wire, []byte("old/clean.go")) {
			t.Errorf("%s: a metadata-only push carried an excerpt or a path: %s", m.name, wire)
		}
	}
}

// TestSecurityWireDefaultIsPostureOnly pins the individual default (Q7 as
// amended by ruling R1 of lane CODESEC-ORG, 2026-11-03): with the seam
// unbound (the module inactive) or bound at an explicit "off", an envelope
// carries no security key at all; bound at the default (the key unset) it
// carries the posture row and never a finding or a change record.
func TestSecurityWireDefaultIsPostureOnly(t *testing.T) {
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx, `INSERT INTO sec_findings (id, project_root_hash, local_key, rule_id, category, severity, confidence, first_seen, last_seen)
		VALUES ('f1', 'r1', 'k1', 'S-721', 'secret', 'high', 'high', ?, ?)`, now, now); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		bind    bool
		local   string
		posture bool
	}{
		{"unbound", false, "", false},
		{"explicit off", true, "off", false},
		{"default", true, "", true},
	}
	for _, c := range cases {
		st := store.New(database)
		if c.bind {
			local := c.local
			st.SetSecurityOrgProviders(store.SecurityOrgProviders{
				Level: func(context.Context, store.ShareOptions) store.SecurityShare {
					return store.ResolveSecurityShare(store.ResolveSecurityShareFacts{LocalLevel: local})
				},
				Posture: func(ctx context.Context, day string, scope store.SecurityScope) (orgcontract.SecurityPostureRow, bool, error) {
					r, err := st.SecurityPostureFacts(ctx, day, time.Now().UTC(), scope)
					return r, err == nil, err
				},
				Findings: st.SelectSecurityFindingRows,
			})
		}
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 1<<20, "org-1", "dev@x", store.ShareOptions{FullContent: true}, store.ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(orgcontract.PushEnvelope{SecurityFindings: batch.SecurityFindings, SecurityPosture: batch.SecurityPosture, AIChangeRecords: batch.AIChangeRecords})
		for _, key := range []string{"security_findings", "ai_change_records"} {
			if bytes.Contains(raw, []byte(key)) {
				t.Errorf("%s: %s on the wire: %s", c.name, key, raw)
			}
		}
		if got := bytes.Contains(raw, []byte("security_posture")); got != c.posture {
			t.Errorf("%s: posture row on the wire = %v, want %v: %s", c.name, got, c.posture, raw)
		}
	}
}

// secTableLiteral matches a sec_* table name inside a Go string literal.
var secTableLiteral = regexp.MustCompile(`\bsec_[a-z_]+`)

// TestOrgPushNamesNoSecTable is the prefix half of the source-name sentinel
// for the security pillar (security plan 7.4, spike JSP-1): the security
// wire is composed through SecurityOrgProviders, so no string literal in
// orgpush.go may name any sec_* table, including one added after this test.
func TestOrgPushNamesNoSecTable(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "store", "orgpush.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	ast.Inspect(file, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if m := secTableLiteral.FindString(lit.Value); m != "" {
				t.Errorf("%s: orgpush.go names the node-local security table %q; compose it through SecurityOrgProviders", fset.Position(lit.Pos()), m)
			}
		}
		return true
	})
}

// TestSecurityPostureFactsH2Canary (lane SEC-H2): the posture row's new
// facts carry enums and counts only. A commit-gate event and two launch
// trust events whose reason, target and session text hold canaries yield
// gate_outcomes and trust_verdicts on the wire in every share mode, and no
// canary reaches it. The two daemon facts (database_ages and platform_gaps,
// composed in cmd/observer's posture provider, added here the same way)
// also reach the wire in every share mode, and a canary in their closed
// vocabularies never does (SEC-H2 merge, audit finding 7).
func TestSecurityPostureFactsH2Canary(t *testing.T) {
	if !securityInBuild {
		t.Skip("the security module is compiled out (sbo_omit_security)")
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	st := store.New(database)
	now := time.Now().UTC()
	var rows []store.GuardEventRow
	for i, rule := range []string{"S-793", "S-701", "S-705"} {
		rows = append(rows, store.GuardEventRow{
			TS: now.Add(time.Duration(-i-1) * time.Minute), SessionID: "CANARYSESSIONnever", Tool: "claude-code",
			EventKind: "git_commit", RuleID: rule, Category: "code_security", Severity: "warn", Decision: "ask",
			Source: "builtin", Reason: "CANARYREASONnever", TargetHash: "CANARYTARGETHASHnever", TargetExcerpt: "CANARYEXCERPTnever",
		})
	}
	if _, err := st.InsertGuardEvents(ctx, rows); err != nil {
		t.Fatal(err)
	}
	never := []string{
		"CANARYSESSIONnever", "CANARYREASONnever", "CANARYTARGETHASHnever", "CANARYEXCERPTnever",
		"CANARYDBKINDnever", "CANARYBUCKETnever", "CANARYSUPPORTnever",
	}
	for _, share := range []store.ShareOptions{{}, {FullContent: true}, {FullToolBodies: true}} {
		s := store.New(database)
		s.SetSecurityOrgProviders(store.SecurityOrgProviders{
			Level: func(context.Context, store.ShareOptions) store.SecurityShare {
				return store.SecurityShare{Level: orgcontract.SecuritySharePosture}
			},
			Posture: func(ctx context.Context, day string, scope store.SecurityScope) (orgcontract.SecurityPostureRow, bool, error) {
				r, err := s.SecurityPostureFacts(ctx, day, time.Now().UTC(), scope)
				// The daemon facts, as securityPostureDaemonFacts adds them.
				r.DatabaseAges = append(r.DatabaseAges,
					orgcontract.SecurityDatabaseAge{Kind: "osv_export", Bucket: "over_7d"},
					orgcontract.SecurityDatabaseAge{Kind: "CANARYDBKINDnever", Bucket: "never"},
					orgcontract.SecurityDatabaseAge{Kind: "popular_names", Bucket: "CANARYBUCKETnever"})
				r.PlatformGaps = append(r.PlatformGaps,
					orgcontract.SecurityPlatformGap{Driver: "scalibr", Support: "untested"},
					orgcontract.SecurityPlatformGap{Driver: "osv", Support: "CANARYSUPPORTnever"})
				r.Reported = append(r.Reported, "database_ages", "platform_gaps")
				return r, err == nil, err
			},
		})
		batch, err := s.SelectUnpushedSince(ctx, store.PushCursor{}, 4<<20, "org-1", "dev@x", share, store.ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(orgcontract.PushEnvelope{SecurityPosture: batch.SecurityPosture})
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{
			`"gate_outcomes"`, `"trust_verdicts"`, `"waited"`, `"untrusted"`, `"flagged"`,
			`"database_ages"`, `"platform_gaps"`, `"over_7d"`, `"untested"`, `"scalibr"`,
		} {
			if !bytes.Contains(raw, []byte(key)) {
				t.Errorf("%+v: %s missing from %s", share, key, raw)
			}
		}
		for _, v := range never {
			if bytes.Contains(raw, []byte(v)) {
				t.Errorf("%+v: %s reached the wire", share, v)
			}
		}
	}
}

// TestChangeRecordEnvelopeCanary (lane SEC-F2B): the AI change record's
// signed envelope is a raw-class field. A canary planted in it reaches the
// wire only under raw content (an individual node's own full_content, a
// managed node's grant) and never in the metadata-only or the
// tool-bodies-only push.
func TestChangeRecordEnvelopeCanary(t *testing.T) {
	if !securityInBuild {
		t.Skip("the security module is compiled out (sbo_omit_security)")
	}
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	const canary = "sbo-envelope-canary"
	envelope := `{"payloadType":"` + canary + `","payload":"e30=","signatures":[{"keyid":"k","sig":"AA=="}]}`
	changeRecords := func(context.Context, int, store.SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
		return []orgcontract.AIChangeRecordRow{{CommitIdentityHash: strings.Repeat("c", 64), RecordDigest: strings.Repeat("d", 64), Envelope: envelope}}, nil
	}
	for _, m := range []struct {
		name  string
		share store.ShareOptions
		raw   bool
	}{
		{"individual_metadata_only", store.ShareOptions{}, false},
		{"individual_full_content", store.ShareOptions{FullContent: true}, true},
		{"managed_enterprise_grant", store.ShareOptions{EnterpriseGranted: true}, true},
		{"tool_bodies_only", store.ShareOptions{FullToolBodies: true}, false},
	} {
		st := store.New(database)
		st.SetSecurityOrgProviders(store.SecurityOrgProviders{
			Level: func(context.Context, store.ShareOptions) store.SecurityShare {
				return store.SecurityShare{Level: orgcontract.SecurityShareFindings, HoldsOrgKey: true}
			},
			ChangeRecords: changeRecords,
		})
		batch, err := st.SelectUnpushedSince(ctx, store.PushCursor{}, 4<<20, "org-1", "dev@x", m.share, store.ScopeOptions{})
		if err != nil {
			t.Fatalf("%s: SelectUnpushedSince: %v", m.name, err)
		}
		if len(batch.AIChangeRecords) != 1 {
			t.Fatalf("%s: %d change records shipped, want 1 (the canary would pass vacuously)", m.name, len(batch.AIChangeRecords))
		}
		wire, _ := json.Marshal(orgcontract.PushEnvelope{AIChangeRecords: batch.AIChangeRecords})
		if got := bytes.Contains(wire, []byte(canary)); got != m.raw {
			t.Errorf("%s: envelope canary on the wire = %v, want %v", m.name, got, m.raw)
		}
	}
}
