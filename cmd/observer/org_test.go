package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Agent Access P4 W4f (rulings R9.5 / R11.10, robustness finding PR-014):
// `observer org enroll` writes the capture posture the enrolment's TENANCY
// implies, and an already-enrolled managed node is raised to full content by
// the org-SIGNED extract.managed grant — shown to the developer, never a
// silent config rewrite — with an intentional admin lowering preserved and a
// grant that does not verify ignored.

// TestEnrolWritesFullContentByTenancy pins the two-row table: a managed
// (teams/enterprise) enrolment writes full_content = true, an individual one
// writes false, and in both cases the appended block parses back through
// config.Load to exactly that value.
func TestEnrolWritesFullContentByTenancy(t *testing.T) {
	cases := []struct {
		name    string
		managed bool
		want    bool
	}{
		{name: "managed (teams/enterprise) enrolment ships full content", managed: true, want: true},
		{name: "individual enrolment keeps the node-side opt-in", managed: false, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			seed := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n"
			if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
				t.Fatalf("seed config: %v", err)
			}
			added, err := ensureOrgClientBlock(path, "https://org.acme.example", tc.managed)
			if err != nil || !added {
				t.Fatalf("ensureOrgClientBlock = (%v, %v), want (true, nil)", added, err)
			}
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			wantLine := "full_content = false\n"
			if tc.want {
				wantLine = "full_content = true\n"
			}
			if !strings.Contains(string(body), wantLine) {
				t.Fatalf("block does not carry %q:\n%s", strings.TrimSpace(wantLine), body)
			}
			// The comment must tell the operator WHY, not just what.
			if tc.managed && !strings.Contains(string(body), "ORGANISATION-MANAGED") {
				t.Fatalf("managed block does not explain the posture:\n%s", body)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
			if err != nil {
				t.Fatalf("config.Load on appended block: %v", err)
			}
			if cfg.OrgClient.Share.FullContent != tc.want {
				t.Fatalf("loaded full_content = %v, want %v", cfg.OrgClient.Share.FullContent, tc.want)
			}
			if cfg.OrgClient.Share.AdminManaged {
				t.Fatal("enrol must never write admin_managed — that is the provisioning-template knob, not the enrolment's")
			}
		})
	}
}

// TestEnrolShareDefaultsTable pins the table itself: exactly one row per
// tenancy class, managed = true / individual = false, and an unmatched
// lookup falls back to the individual row (never INTO full content).
func TestEnrolShareDefaultsTable(t *testing.T) {
	if len(enrolShareDefaults) != 2 {
		t.Fatalf("enrolShareDefaults has %d rows, want 2 (one per tenancy class)", len(enrolShareDefaults))
	}
	if got := enrolShareDefaultFor(true); got.name != "managed" || !got.fullContent {
		t.Fatalf("managed row = %+v", got)
	}
	if got := enrolShareDefaultFor(false); got.name != "individual" || got.fullContent {
		t.Fatalf("individual row = %+v", got)
	}
	if last := enrolShareDefaults[len(enrolShareDefaults)-1]; last.fullContent {
		t.Fatal("the fallback (last) row must be the metadata-only one")
	}
	for _, row := range enrolShareDefaults {
		if row.summary == "" || row.comment == "" || !strings.HasSuffix(row.comment, "\n") {
			t.Errorf("row %q must carry a summary and a newline-terminated comment", row.name)
		}
	}
}

// signedGrantFixture stands up an enrolled node exactly as enrolment does
// (enrolment row, generation, pinned org policy key, key MATERIAL row, a
// SIGNED grant) under the given tenancy and authority, and returns the store
// plus the private key so a test can forge a non-verifying variant.
func signedGrantFixture(t *testing.T, tenancy string, authority []string) (*store.Store, *sql.DB, string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	const orgID = "org-w4f"
	const orgURL = "https://org.w4f.example"
	orgKey := orgclient.OrgKey(orgURL, orgID)
	if err := st.WriteEnrolment(ctx, store.Enrolment{
		OrgID: orgID, OrgName: "W4F Org", OrgServerURL: orgURL,
		UserID: "member-1", Tenancy: tenancy,
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	generation, err := st.BumpEnrolmentGeneration(ctx, orgKey, false)
	if err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	pinHash := orgcontract.PublicKeyPinHash(pub)
	if _, _, err := st.EstablishOrgPolicyKeyPin(ctx, orgURL+"#policy-key", pinHash, "enrolment"); err != nil {
		t.Fatalf("EstablishOrgPolicyKeyPin: %v", err)
	}
	if _, err := st.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer: "org", Path: orgURL + orgclient.OrgKeyMaterialSuffix,
		Version: base64.StdEncoding.EncodeToString(pub), ContentHash: pinHash,
		LoadedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordGuardPolicyState: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	consent := govern.ConsentInteractive
	if tenancy == orgcontract.TenancyManaged {
		consent = govern.ConsentManaged
	}
	// The consent evidence is part of the SIGNED document (StoredGrantDocument
	// binds ConsentMode/ConsentActor), so it must be on the wire grant before
	// signing or the runtime re-verification rightly reports the stored row
	// as altered.
	wire := orgcontract.EnrolmentGrant{
		OrgID: orgID, OrgServerURL: orgURL, KeyPinSHA256: pinHash,
		Authority:   orgcontract.CanonicalAuthority(authority),
		GrantedAt:   now.Format(time.RFC3339),
		ExpiresAt:   now.Add(30 * 24 * time.Hour).Format(time.RFC3339),
		ConsentMode: consent, ConsentActor: "test",
	}
	wire.Signature = orgcontract.SignEnrolmentGrant(priv, wire)
	if err := st.WriteEnrolmentGrant(ctx, store.EnrolmentGrant{
		OrgKey: orgKey, Generation: generation, OrgID: orgID, OrgName: "W4F Org",
		OrgServerURL: orgURL, KeyPinSHA256: pinHash, Authority: wire.Authority,
		ConsentMode: consent, ConsentActor: "test",
		GrantedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
		Signature: wire.Signature, ReceiptHash: orgcontract.EnrolmentGrantReceiptHash(wire),
	}); err != nil {
		t.Fatalf("WriteEnrolmentGrant: %v", err)
	}
	return st, database, orgKey
}

// w4fMetadataOnlyConfig writes a config whose [org_client.share] block is the
// pre-W4f shape an already-enrolled node still carries (full_content = false)
// and returns the path plus the exact bytes, so a test can assert the file
// was not rewritten.
func w4fMetadataOnlyConfig(t *testing.T) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n" +
		"[org_client]\nenabled = true\norg_server_url = \"https://org.w4f.example\"\n" +
		"[org_client.share]\nfull_content = false\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path, []byte(body)
}

// TestAlreadyEnrolledNodeRaisedBySignedGrant is the R11.10 / PR-014 proof:
// a node enrolled BEFORE the managed default (config still says
// full_content = false) that holds an org-SIGNED grant carrying
// extract.managed on a MANAGED enrolment resolves to full content in force,
// `observer org status` names the grant as the reason, `observer org grant
// show` says FULL (L2), and the config file is byte-identical afterwards. A
// re-run of the enrolment block writer on that file is a no-op too — the
// raise never rides a config rewrite.
func TestAlreadyEnrolledNodeRaisedBySignedGrant(t *testing.T) {
	ctx := context.Background()
	st, _, _ := signedGrantFixture(t, orgcontract.TenancyManaged, []string{govern.AuthorityExtractManaged})
	path, before := w4fMetadataOnlyConfig(t)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.OrgClient.Share.FullContent {
		t.Fatal("fixture must start at the metadata-only floor")
	}

	eff := enterpriseContentEffective(ctx, cfg, st, nil)
	if !eff.Managed || !eff.GrantsEnterpriseContent() || !eff.EnterpriseContentInForce() {
		t.Fatalf("signed umbrella grant on a managed node did not raise; Effective=%+v", eff)
	}
	if !enterpriseContentGranted(ctx, cfg, st, nil) {
		t.Fatal("enterpriseContentGranted = false under a verified extract.managed grant")
	}
	// Shown to the developer, on both CLI surfaces.
	line := shareModeLine(cfg.OrgClient.Share.FullContent, cfg.OrgClient.Share.AdminManaged, enterpriseContentGranted(ctx, cfg, st, nil))
	if !strings.Contains(line, "FULL CONTENT") || !strings.Contains(line, "extract.managed") {
		t.Fatalf("org status share-mode line does not name the grant raise: %q", line)
	}
	if got := enterpriseContentLine(ctx, cfg, st, nil); !strings.Contains(got, "FULL (L2)") || !strings.Contains(got, "not rewritten") {
		t.Fatalf("grant show content line = %q, want FULL (L2) + not rewritten", got)
	}
	// No silent config rewrite: same bytes, and the block writer is a no-op.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(after) != string(before) {
		t.Fatalf("config file changed under the grant raise:\n--- before\n%s\n--- after\n%s", before, after)
	}
	if added, err := ensureOrgClientBlock(path, "https://org.w4f.example", true); err != nil || added {
		t.Fatalf("ensureOrgClientBlock on an enrolled config = (%v, %v), want (false, nil)", added, err)
	}
	// The push seam agrees with the surfaces: the raise rides
	// EnterpriseGranted, the node's own FullContent stays false.
	share := lowerShareOptions(orgclient.ShareOptionsFromConfig(cfg.OrgClient), eff)
	if !share.EnterpriseGranted || !share.ShipsRawContent() || share.FullContent {
		t.Fatalf("push seam ShareOptions = %+v, want EnterpriseGranted raw-content posture with FullContent untouched", share)
	}
}

// TestSignedGrantRaiseIsInertOnIndividualEnrolment: the identical
// extract.managed grant on an INDIVIDUAL enrolment grants nothing — the
// individual plane keeps the node-side opt-in — and grant show says so.
func TestSignedGrantRaiseIsInertOnIndividualEnrolment(t *testing.T) {
	ctx := context.Background()
	st, _, _ := signedGrantFixture(t, orgcontract.TenancyIndividual, []string{govern.AuthorityExtractManaged})
	path, _ := w4fMetadataOnlyConfig(t)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if enterpriseContentGranted(ctx, cfg, st, nil) {
		t.Fatal("an individual enrolment was raised by extract.managed")
	}
	if got := enterpriseContentLine(ctx, cfg, st, nil); !strings.Contains(got, "INDIVIDUAL") {
		t.Fatalf("grant show content line = %q, want the individual-inert explanation", got)
	}
	line := shareModeLine(false, false, enterpriseContentGranted(ctx, cfg, st, nil))
	if !strings.Contains(line, "metadata-only") {
		t.Fatalf("org status share-mode line = %q, want metadata-only", line)
	}
}

// TestTamperedGrantDoesNotRaise: a stored grant whose authority list was
// widened to carry extract.managed WITHOUT a matching signature is refused
// by the runtime re-verification (govern.StateGrantSignatureInvalid) and
// raises nothing — the raise is an org-SIGNED act or it is not one.
func TestTamperedGrantDoesNotRaise(t *testing.T) {
	ctx := context.Background()
	// Signed for dashboard.visibility only.
	st, database, orgKey := signedGrantFixture(t, orgcontract.TenancyManaged, []string{govern.AuthorityDashboardVisibility})
	path, before := w4fMetadataOnlyConfig(t)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if enterpriseContentGranted(ctx, cfg, st, nil) {
		t.Fatal("a grant without extract.managed raised content")
	}
	// Widen the node-local row to claim the umbrella: no root, no patched
	// binary, and no signature.
	widened, _ := json.Marshal([]string{govern.AuthorityDashboardVisibility, govern.AuthorityExtractManaged})
	if _, err := database.ExecContext(ctx,
		`UPDATE org_enrolment_grant SET authority_json = ? WHERE org_key = ?`, string(widened), orgKey); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	eff := enterpriseContentEffective(ctx, cfg, st, nil)
	if eff.State != govern.StateGrantSignatureInvalid {
		t.Fatalf("tampered grant resolved %q, want grant_signature_invalid", eff.State)
	}
	if eff.GrantsEnterpriseContent() || eff.EnterpriseContentInForce() || enterpriseContentGranted(ctx, cfg, st, nil) {
		t.Fatalf("a grant that does not verify raised content; Effective=%+v", eff)
	}
	if got := enterpriseContentLine(ctx, cfg, st, nil); strings.Contains(got, "FULL (L2)") {
		t.Fatalf("grant show claimed a raise under a non-verifying grant: %q", got)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("config file changed")
	}
}

// TestEnterpriseContentLineRules pins the grant-show table: every row is
// named, the fallback is last, and each posture maps to its own line
// (raised / lowered / individual-inert / not granted).
func TestEnterpriseContentLineRules(t *testing.T) {
	want := []string{"raised", "lowered", "inert_individual", "not_granted"}
	if len(enterpriseContentRules) != len(want) {
		t.Fatalf("enterpriseContentRules has %d rows, want %d", len(enterpriseContentRules), len(want))
	}
	for i, name := range want {
		if enterpriseContentRules[i].name != name {
			t.Errorf("row %d = %q, want %q", i, enterpriseContentRules[i].name, name)
		}
	}
	if !enterpriseContentRules[len(enterpriseContentRules)-1].match(govern.Effective{}) {
		t.Error("the last row must be the total fallback")
	}
	umbrella := []string{govern.AuthorityCapturePin, govern.AuthorityExtractManaged}
	cases := []struct {
		name string
		eff  govern.Effective
		want string
	}{
		{"managed + umbrella: raised", govern.Effective{Managed: true, Authority: umbrella}, "FULL (L2)"},
		{"managed + umbrella + org lowers: lowered", govern.Effective{Managed: true, Authority: umbrella, Share: map[string]any{"full_content": false}}, "LOWERED"},
		{"individual + umbrella: inert", govern.Effective{Managed: false, Authority: umbrella}, "INDIVIDUAL"},
		{"managed, no umbrella: not granted", govern.Effective{Managed: true, Authority: []string{govern.AuthorityCapturePin}}, "carries no extract.managed"},
		{"zero value: not granted", govern.Effective{}, "carries no extract.managed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := enterpriseContentLineFor(tc.eff); !strings.Contains(got, tc.want) {
				t.Fatalf("line = %q, want it to contain %q", got, tc.want)
			}
		})
	}
}
