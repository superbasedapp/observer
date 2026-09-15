package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestQuotedTomlStringList pins the TOML array rendering ensureManagedPolicyBlock
// and printGrantOffer's W-5 disclosure both depend on.
func TestQuotedTomlStringList(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{name: "nil", in: nil, want: "[]"},
		{name: "empty", in: []string{}, want: "[]"},
		{name: "single", in: []string{"admission.input"}, want: `["admission.input"]`},
		{
			name: "multiple, order preserved",
			in:   []string{"admission.input", "node.governance"},
			want: `["admission.input", "node.governance"]`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := quotedTomlStringList(tc.in); got != tc.want {
				t.Errorf("quotedTomlStringList(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestEnsureManagedPolicyBlock_WritesAcceptAndPreauthorize is the W-5 core
// case: a fresh config gets accept_families and preauthorize_enforce set to
// the SAME family list, and the appended TOML round-trips through the real
// loader with validateOrgClientPolicy's subset check satisfied (the two
// lists are always equal, so the subset check can never fail on our own
// output).
func TestEnsureManagedPolicyBlock_WritesAcceptAndPreauthorize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	seed := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(dir, "observer.db")) + "\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	families := []string{"admission.input", "node.governance"}
	added, err := ensureManagedPolicyBlock(path, families)
	if err != nil || !added {
		t.Fatalf("ensureManagedPolicyBlock = (%v, %v), want (true, nil)", added, err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(body), `accept_families = ["admission.input", "node.governance"]`) {
		t.Fatalf("block missing accept_families:\n%s", body)
	}
	if !strings.Contains(string(body), `preauthorize_enforce = ["admission.input", "node.governance"]`) {
		t.Fatalf("block missing preauthorize_enforce:\n%s", body)
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatalf("config.Load on appended block: %v", err)
	}
	if got := cfg.OrgClient.Policy.AcceptFamilies; !equalStrSlices(got, families) {
		t.Fatalf("loaded AcceptFamilies = %v, want %v", got, families)
	}
	if got := cfg.OrgClient.Policy.PreauthorizeEnforce; !equalStrSlices(got, families) {
		t.Fatalf("loaded PreauthorizeEnforce = %v, want %v", got, families)
	}
}

// TestEnsureManagedPolicyBlock_NoFamiliesNoWrite: an accepted grant whose
// authority governs nothing (e.g. only the retired capture.raise token, or
// an authority list this build does not recognise) must never produce an
// empty or vacuous [org_client.policy] block — GovernedFamilies already
// returns nil for that input, and ensureManagedPolicyBlock must respect a
// nil/empty families argument as "nothing to write."
func TestEnsureManagedPolicyBlock_NoFamiliesNoWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	added, err := ensureManagedPolicyBlock(path, nil)
	if err != nil || added {
		t.Fatalf("ensureManagedPolicyBlock(nil) = (%v, %v), want (false, nil)", added, err)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("expected no file to be created, stat err = %v", statErr)
	}
}

// TestEnsureManagedPolicyBlock_Idempotent: a second call — the shape of a
// second `observer enroll` on an already-enrolled, already-consented
// machine, or a renewal — must never duplicate the block, and must leave a
// hand-edited (including hand-emptied) block alone. This is the same
// idempotence contract ensureOrgClientBlock already gives the [org_client]
// block, applied to [org_client.policy].
func TestEnsureManagedPolicyBlock_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	families := []string{"admission.input"}

	added, err := ensureManagedPolicyBlock(path, families)
	if err != nil || !added {
		t.Fatalf("first call = (%v, %v), want (true, nil)", added, err)
	}
	before, _ := os.ReadFile(path)

	// A second write attempt, even with a DIFFERENT family set (as if a
	// later grant governed more), must not touch the file: the node's own
	// current state — including a hand-edit — always wins.
	added, err = ensureManagedPolicyBlock(path, []string{"admission.input", "gateway.providers"})
	if err != nil || added {
		t.Fatalf("second call = (%v, %v), want (false, nil)", added, err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("existing [org_client.policy] block was modified by a second call")
	}
	if got := strings.Count(string(after), "\n[org_client.policy]\n"); got != 1 {
		t.Fatalf("block count = %d, want 1", got)
	}
}

// TestEnsureManagedPolicyBlock_IgnoresCommentMentions mirrors
// TestEnsureOrgClientBlockIgnoresCommentMentions for the "is there a real
// table" half of the check: only a real TOML table header counts, not a
// comment mentioning the table name.
//
// The other two cases exercise decision-table row 3 (see
// ensureManagedPolicyBlock's doc comment): a real header whose section is
// missing one or both keys is no longer treated as "already handled" the
// way it was before the 2026-09-13 live finding - the missing key(s) are
// inserted, so both now expect added=true. TestEnsureManagedPolicyBlock_
// Idempotent (below) is what still proves a header with BOTH keys already
// present is left alone.
func TestEnsureManagedPolicyBlock_IgnoresCommentMentions(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantAdded bool
	}{
		{
			name:      "comment mention only: no real table, whole block appended",
			body:      "# enrol appends its [org_client.policy] block here\n[proxy]\nport = 8820\n",
			wantAdded: true,
		},
		{
			name:      "real header, both keys missing: both inserted",
			body:      "[org_client.policy]\n",
			wantAdded: true,
		},
		{
			name:      "indented real header, preauthorize_enforce missing: only it is inserted",
			body:      "  [org_client.policy]\naccept_families = []\n",
			wantAdded: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			added, err := ensureManagedPolicyBlock(path, []string{"admission.input"})
			if err != nil {
				t.Fatal(err)
			}
			if added != tc.wantAdded {
				t.Fatalf("added = %v, want %v", added, tc.wantAdded)
			}
		})
	}
}

// TestEnsureManagedPolicyBlock_FourShapes is the table-driven pin for the
// full decision table ensureManagedPolicyBlock now implements: no table at
// all, a table with both keys, a table with neither key, and a table with
// only preauthorize_enforce missing. Each case asserts the returned
// (added, err), that the untouched parts of a pre-existing file survive
// byte for byte, and - for the two "table exists" shapes - that the
// resulting file still round-trips through config.Load with
// AcceptFamilies/PreauthorizeEnforce coming back as expected.
func TestEnsureManagedPolicyBlock_FourShapes(t *testing.T) {
	families := []string{"admission.input", "node.governance"}

	cases := []struct {
		name string
		// seed is the config.toml body BEFORE the call, or "" for no file
		// at all.
		seed string
		// wantAdded and wantAccept/wantEnforce are what the call and the
		// reloaded config should report afterward.
		wantAdded   bool
		wantAccept  []string
		wantEnforce []string
		// wantContains lists substrings that must survive in the file
		// after the call, e.g. an unrelated key or a later table header -
		// proof that only the missing key line(s) were inserted, nothing
		// else was rewritten.
		wantContains []string
	}{
		{
			name:        "no [org_client.policy] table at all: whole block appended",
			seed:        "[observer]\nenabled = true\n",
			wantAdded:   true,
			wantAccept:  families,
			wantEnforce: families,
			wantContains: []string{
				"[observer]\nenabled = true\n",
				`accept_families = ["admission.input", "node.governance"]`,
			},
		},
		{
			name: "table exists, both keys already present: no-op, existing values kept",
			seed: "[org_client.policy]\n" +
				"accept_families = [\"admission.input\"]\n" +
				"preauthorize_enforce = [\"admission.input\"]\n",
			wantAdded:   false,
			wantAccept:  []string{"admission.input"},
			wantEnforce: []string{"admission.input"},
			wantContains: []string{
				`accept_families = ["admission.input"]`,
				`preauthorize_enforce = ["admission.input"]`,
			},
		},
		{
			name: "table exists, neither key present: both inserted before the next table",
			seed: "[org_client.policy]\n" +
				"node_workspace = \"acme-web\"\n" +
				"node_environment = \"prod\"\n" +
				"\n" +
				"[guard]\n" +
				"enabled = true\n",
			wantAdded:   true,
			wantAccept:  families,
			wantEnforce: families,
			wantContains: []string{
				"node_workspace = \"acme-web\"",
				"node_environment = \"prod\"",
				"[guard]\nenabled = true\n",
			},
		},
		{
			name: "table exists, only preauthorize_enforce missing: only it is inserted",
			seed: "[org_client.policy]\n" +
				"accept_families = [\"admission.input\", \"node.governance\"]\n" +
				"\n" +
				"[guard]\n" +
				"enabled = true\n",
			wantAdded:   true,
			wantAccept:  []string{"admission.input", "node.governance"},
			wantEnforce: families,
			wantContains: []string{
				`accept_families = ["admission.input", "node.governance"]`,
				"[guard]\nenabled = true\n",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if tc.seed != "" {
				if err := os.WriteFile(path, []byte(tc.seed), 0o600); err != nil {
					t.Fatalf("seed config: %v", err)
				}
			}

			added, err := ensureManagedPolicyBlock(path, families)
			if err != nil {
				t.Fatalf("ensureManagedPolicyBlock: %v", err)
			}
			if added != tc.wantAdded {
				t.Fatalf("added = %v, want %v", added, tc.wantAdded)
			}

			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read back: %v", err)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(string(body), want) {
					t.Fatalf("result missing %q, got:\n%s", want, body)
				}
			}

			cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
			if err != nil {
				t.Fatalf("config.Load on result: %v\nbody:\n%s", err, body)
			}
			if got := cfg.OrgClient.Policy.AcceptFamilies; !equalStrSlices(got, tc.wantAccept) {
				t.Fatalf("loaded AcceptFamilies = %v, want %v", got, tc.wantAccept)
			}
			if got := cfg.OrgClient.Policy.PreauthorizeEnforce; !equalStrSlices(got, tc.wantEnforce) {
				t.Fatalf("loaded PreauthorizeEnforce = %v, want %v", got, tc.wantEnforce)
			}
		})
	}
}

// TestManagedPolicyFamiliesToWrite exercises the REAL W-5 gate function
// org.go's RunE calls (managedPolicyFamiliesToWrite), not a re-derivation
// of its condition — so a future edit that loosens any of the three parts
// (accepted / managed / authority governs something) fails THIS test
// directly, rather than a copy of the logic living only in a test file.
// Table-driven over every case a real enrolment can produce: declined,
// accepted-but-individual, accepted-managed-with-no-authority,
// accepted-managed-with-only-the-retired-token, and the two writing cases.
func TestManagedPolicyFamiliesToWrite(t *testing.T) {
	cases := []struct {
		name    string
		outcome grantOutcome
		want    []string
	}{
		{
			name:    "declined grant: not accepted",
			outcome: grantOutcome{Accepted: false, Managed: true, Authority: []string{govern.AuthorityDashboardVisibility}},
			want:    nil,
		},
		{
			name:    "accepted, individual tenancy: not managed",
			outcome: grantOutcome{Accepted: true, Managed: false, Authority: []string{govern.AuthorityDashboardVisibility}},
			want:    nil,
		},
		{
			name:    "accepted, managed, but authority is empty",
			outcome: grantOutcome{Accepted: true, Managed: true, Authority: nil},
			want:    nil,
		},
		{
			name:    "accepted, managed, but authority governs nothing (retired token only)",
			outcome: grantOutcome{Accepted: true, Managed: true, Authority: []string{govern.AuthorityCaptureRaise}},
			want:    nil,
		},
		{
			name:    "accepted, managed, authority governs a family: writes",
			outcome: grantOutcome{Accepted: true, Managed: true, Authority: []string{govern.AuthorityDashboardVisibility}},
			want:    []string{"node.governance"},
		},
		{
			name: "accepted, managed, mixed authority including a retired token plus a real one",
			outcome: grantOutcome{
				Accepted: true, Managed: true,
				Authority: []string{govern.AuthorityCaptureRaise, govern.AuthorityEnforceAdmission},
			},
			want: []string{"admission.input"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := managedPolicyFamiliesToWrite(tc.outcome); !equalStrSlices(got, tc.want) {
				t.Fatalf("managedPolicyFamiliesToWrite(%+v) = %v, want %v", tc.outcome, got, tc.want)
			}
		})
	}
}

// TestManagedPolicyFamiliesToWrite_DrivesTheActualWrite checks the gate end
// to end with ensureManagedPolicyBlock, the same two calls org.go's RunE
// makes in sequence: when the gate returns families, a block is written for
// exactly those families; when it returns nil, no file is created at all.
func TestManagedPolicyFamiliesToWrite_DrivesTheActualWrite(t *testing.T) {
	write := grantOutcome{Accepted: true, Managed: true, Authority: []string{govern.AuthorityDashboardVisibility}}
	path := filepath.Join(t.TempDir(), "config.toml")
	if families := managedPolicyFamiliesToWrite(write); len(families) > 0 {
		added, err := ensureManagedPolicyBlock(path, families)
		if err != nil || !added {
			t.Fatalf("ensureManagedPolicyBlock = (%v, %v), want (true, nil)", added, err)
		}
	} else {
		t.Fatalf("expected families to write for a managed, accepted, node-governance grant, got none")
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("expected file to be written: %v", statErr)
	}

	noWrite := grantOutcome{Accepted: true, Managed: false, Authority: []string{govern.AuthorityDashboardVisibility}}
	path2 := filepath.Join(t.TempDir(), "config.toml")
	if families := managedPolicyFamiliesToWrite(noWrite); len(families) > 0 {
		t.Fatalf("individual tenancy must not produce families to write, got %v", families)
	}
	if _, statErr := os.Stat(path2); !os.IsNotExist(statErr) {
		t.Fatalf("expected no file for a gate that should not write, stat err = %v", statErr)
	}
}

// TestPrintGovernedFamilies covers the W-7 rendering: for a grant's
// governed families, the three possible per-family states relative to
// THIS node's current [org_client.policy] — missing from accept_families,
// accepted but not preauthorized for enforcement, and fully present.
func TestPrintGovernedFamilies(t *testing.T) {
	authority := []string{govern.AuthorityDashboardVisibility, govern.AuthorityEnforceAdmission}
	// GovernedFamilies([dashboard.visibility, enforce.admission])
	//   = [admission.input, node.governance] (sorted).

	cases := []struct {
		name   string
		policy config.OrgClientPolicyConfig
		want   []string // substrings that must all appear
	}{
		{
			name:   "no [org_client.policy] at all: both families MISSING",
			policy: config.OrgClientPolicyConfig{},
			want: []string{
				"admission.input          accept_families: MISSING",
				"node.governance          accept_families: MISSING",
			},
		},
		{
			name: "accept_families present, preauthorize_enforce missing",
			policy: config.OrgClientPolicyConfig{
				AcceptFamilies: []string{"admission.input", "node.governance"},
			},
			want: []string{
				"admission.input          accept_families: present; preauthorize_enforce: MISSING",
				"node.governance          accept_families: present; preauthorize_enforce: MISSING",
			},
		},
		{
			name: "fully present: both families flow",
			policy: config.OrgClientPolicyConfig{
				AcceptFamilies:      []string{"admission.input", "node.governance"},
				PreauthorizeEnforce: []string{"admission.input", "node.governance"},
			},
			want: []string{
				"admission.input          accept_families: present; preauthorize_enforce: present",
				"node.governance          accept_families: present; preauthorize_enforce: present",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			printGovernedFamilies(&buf, authority, tc.policy)
			got := buf.String()
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Errorf("output missing %q\ngot:\n%s", want, got)
				}
			}
		})
	}
}

// TestPrintGovernedFamilies_NoGovernedFamilies: an authority list that maps
// to no family (e.g. only the retired capture.raise token, or an empty
// grant) must say so honestly, never render an empty/misleading list.
func TestPrintGovernedFamilies_NoGovernedFamilies(t *testing.T) {
	var buf bytes.Buffer
	printGovernedFamilies(&buf, []string{govern.AuthorityCaptureRaise}, config.OrgClientPolicyConfig{})
	got := buf.String()
	if !strings.Contains(got, "(none - nothing in this grant's authority maps to an [org_client.policy] family)") {
		t.Fatalf("expected the honest 'none' line, got:\n%s", got)
	}
}

// TestPrintGrantOffer_W5Disclosure pins the consent-screen disclosure text
// itself: it must appear for a managed offer whose authority governs a
// family, and must NOT appear for an individual-tenancy offer (nothing gets
// auto-written there, so disclosing a write would be a lie) or for a
// managed offer whose authority governs nothing.
func TestPrintGrantOffer_W5Disclosure(t *testing.T) {
	const disclosure = "Accepting will also write to this machine's config.toml"

	managedOffer := testGrantOffer(t, true, []string{govern.AuthorityDashboardVisibility})
	var buf bytes.Buffer
	printGrantOffer(&buf, managedOffer)
	if !strings.Contains(buf.String(), disclosure) {
		t.Errorf("managed offer with governed authority: expected disclosure, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), `accept_families = ["node.governance"]`) {
		t.Errorf("managed offer disclosure missing the family list, got:\n%s", buf.String())
	}

	individualOffer := testGrantOffer(t, false, []string{govern.AuthorityDashboardVisibility})
	buf.Reset()
	printGrantOffer(&buf, individualOffer)
	if strings.Contains(buf.String(), disclosure) {
		t.Errorf("individual offer must not disclose a write that never happens, got:\n%s", buf.String())
	}

	noFamilyOffer := testGrantOffer(t, true, []string{govern.AuthorityCaptureRaise})
	buf.Reset()
	printGrantOffer(&buf, noFamilyOffer)
	if strings.Contains(buf.String(), disclosure) {
		t.Errorf("managed offer with no governed family must not disclose a write, got:\n%s", buf.String())
	}
}

// testGrantOffer builds a minimal *orgclient.GrantOffer for
// TestPrintGrantOffer_W5Disclosure: managed controls Tenancy, authority is
// carried through unfiltered exactly as confirmAndStoreGrant reads it.
func testGrantOffer(t *testing.T, managed bool, authority []string) *orgclient.GrantOffer {
	t.Helper()
	tenancy := orgcontract.TenancyIndividual
	if managed {
		tenancy = orgcontract.TenancyManaged
	}
	return &orgclient.GrantOffer{
		Grant: orgcontract.EnrolmentGrant{
			OrgID:        "acme",
			OrgServerURL: "https://org.acme.example",
			Authority:    authority,
		},
		Tenancy: tenancy,
	}
}

// equalStrSlices is a small order-sensitive comparison helper for the
// config round-trip assertions above.
func equalStrSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// quotedTomlStringListStdlibEquivalent double-checks quotedTomlStringList
// against strconv.Quote directly, to catch a future refactor that changes
// the quoting rules for a token containing something quote-worthy.
func quotedTomlStringListStdlibEquivalent(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = strconv.Quote(s)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func TestQuotedTomlStringList_MatchesStrconvQuote(t *testing.T) {
	in := []string{"admission.input", "node.governance", `has"quote`}
	if got, want := quotedTomlStringList(in), quotedTomlStringListStdlibEquivalent(in); got != want {
		t.Errorf("quotedTomlStringList(%v) = %q, want %q", in, got, want)
	}
}
