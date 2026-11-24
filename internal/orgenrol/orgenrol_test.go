package orgenrol

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNormalizeServerURL(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "https://org.example.com", want: "https://org.example.com"},
		{in: "  https://org.example.com/  ", want: "https://org.example.com"},
		{in: "http://127.0.0.1:18640", want: "http://127.0.0.1:18640"},
		{in: "https://proxy.example/observer/", want: "https://proxy.example/observer"},
		{in: "", wantErr: true},
		{in: "org.example.com", wantErr: true},
		{in: "ftp://org.example.com", wantErr: true},
		{in: "https://user:pw@org.example.com", wantErr: true},
		{in: "https://org.example.com/enrol/abc?token=x", wantErr: true},
		{in: "https://org.example.com/#x", wantErr: true},
		{in: "https://org example.com", wantErr: true},
		{in: "https://" + strings.Repeat("a", 3000) + ".com", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := NormalizeServerURL(tc.in)
			if tc.wantErr {
				f, ok := AsFailure(err)
				if !ok || f.Code != CodeInvalidInput {
					t.Fatalf("NormalizeServerURL(%q) = (%q, %v), want an invalid_input failure", tc.in, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("NormalizeServerURL(%q) = (%q, %v), want %q", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestCheckTokenShape(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{in: "tok_id.secret", want: "tok_id.secret"},
		{in: "  abc123.Zm9vYmFy-_  ", want: "abc123.Zm9vYmFy-_"},
		{in: "", wantErr: true},
		{in: "nodot", wantErr: true},
		{in: ".secret", wantErr: true},
		{in: "id.", wantErr: true},
		{in: "id .secret", wantErr: true},
		{in: "id.sec\nret", wantErr: true},
		{in: "https://org.example/enrol/id.secret", wantErr: true},
		{in: "a." + strings.Repeat("b", 600), wantErr: true},
	}
	for _, tc := range cases {
		t.Run(strconv.Quote(tc.in), func(t *testing.T) {
			got, err := CheckTokenShape(tc.in)
			if tc.wantErr {
				if f, ok := AsFailure(err); !ok || f.Code != CodeInvalidInput {
					t.Fatalf("CheckTokenShape(%q) = (%q, %v), want an invalid_input failure", tc.in, got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("CheckTokenShape(%q) = (%q, %v), want %q", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestParseMethod(t *testing.T) {
	for in, want := range map[string]Method{"": MethodCode, "code": MethodCode, "LINK": MethodLink, "idp": MethodIdP, "Idp": MethodIdP} {
		if got, err := ParseMethod(in); err != nil || got != want {
			t.Errorf("ParseMethod(%q) = (%q, %v), want %q", in, got, err, want)
		}
	}
	if _, err := ParseMethod("magic"); err == nil {
		t.Error("ParseMethod(magic) accepted an unknown method")
	}
}

func TestFailureUnwraps(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", Fail(CodeGone, "gone %d", 1))
	f, ok := AsFailure(err)
	if !ok || f.Code != CodeGone || f.Message != "gone 1" {
		t.Fatalf("AsFailure = (%+v, %v)", f, ok)
	}
	if _, ok := AsFailure(errors.New("plain")); ok {
		t.Fatal("a plain error classified as a Failure")
	}
}

// TestAuthorityPlainEnglishCoversVocabulary: every authority token the
// governance vocabulary defines has its own sentence (a consent screen must
// never fall back to "UNKNOWN" for a token this build ships).
func TestAuthorityPlainEnglishCoversVocabulary(t *testing.T) {
	unknown := AuthorityPlainEnglish("no.such.token")
	for _, tok := range govern.EnterpriseAuthoritySet() {
		if got := AuthorityPlainEnglish(tok); got == unknown {
			t.Errorf("AuthorityPlainEnglish(%q) fell through to the UNKNOWN fallback", tok)
		}
	}
	if !strings.Contains(unknown, "UNKNOWN") {
		t.Errorf("unknown token rendering = %q, want an honest UNKNOWN", unknown)
	}
}

func TestBuildDisclosure(t *testing.T) {
	cases := []struct {
		name          string
		facts         GrantFacts
		wantWrites    bool
		wantReadsCode bool // the plain "cannot read your code" promise
	}{
		{
			name:          "individual enrolment never writes and keeps the plain promise",
			facts:         GrantFacts{Authority: []string{govern.AuthorityDashboardVisibility, govern.AuthorityExtractManaged}},
			wantWrites:    false,
			wantReadsCode: true,
		},
		{
			name:          "managed enrolment with a governed family discloses the config write",
			facts:         GrantFacts{Managed: true, Authority: []string{govern.AuthorityDashboardVisibility}},
			wantWrites:    true,
			wantReadsCode: true,
		},
		{
			name:          "managed extraction replaces the plain promise",
			facts:         GrantFacts{Managed: true, Authority: []string{govern.AuthorityExtractManaged}},
			wantReadsCode: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := BuildDisclosure(tc.facts)
			if len(d.May) != len(tc.facts.Authority) {
				t.Fatalf("may rows = %d, want one per token", len(d.May))
			}
			if (len(d.ConfigWrites) > 0) != tc.wantWrites && tc.name != "managed extraction replaces the plain promise" {
				t.Fatalf("config writes = %v, want present=%v", d.ConfigWrites, tc.wantWrites)
			}
			hasPlain := false
			for _, l := range d.MayNot {
				if l == mayNotReadCode {
					hasPlain = true
				}
				if strings.Contains(l, "—") {
					t.Errorf("em dash in consent copy: %q", l)
				}
			}
			if hasPlain != tc.wantReadsCode {
				t.Fatalf("plain promise present = %v, want %v (may-not: %v)", hasPlain, tc.wantReadsCode, d.MayNot)
			}
			last := d.MayNot[len(d.MayNot)-1]
			if !strings.Contains(last, "Settings > Enrolment") {
				t.Errorf("the leave line must name the dashboard path too: %q", last)
			}
		})
	}
}

// TestImportsArePure pins the package's purity: no database/sql, net/http or
// fsnotify (CLAUDE.md module rule 1).
func TestImportsArePure(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net/http", "github.com/fsnotify/fsnotify", "os/exec"},
		Reason:    "internal/orgenrol must stay pure",
	})
}

// TestEnforceAdmissionDisclosesThePromptJudge pins F8 (fix round 1): the
// consent sentence for enforce.admission tells the developer that the
// organization's judge reads their coding-agent prompts, because the same
// authority now governs the planeb.admission node lane.
func TestEnforceAdmissionDisclosesThePromptJudge(t *testing.T) {
	got := AuthorityPlainEnglish(govern.AuthorityEnforceAdmission)
	for _, want := range []string{"prompts you type into coding agents", "organization's own server", "secret is never sent"} {
		if !strings.Contains(got, want) {
			t.Errorf("enforce.admission disclosure %q lacks %q", got, want)
		}
	}
}

// TestBuildDisclosureOwnerManaged: the owner paragraph appears only when the
// organization asking is the developer's own AND the enrolment is managed
// (the only tenancy under which its authority takes effect).
func TestBuildDisclosureOwnerManaged(t *testing.T) {
	for _, tc := range []struct {
		name           string
		owner, managed bool
		want           bool
	}{
		{"personal org, managed", true, true, true},
		{"personal org, individual (an old enrolment)", true, false, false},
		{"team org, managed", false, true, false},
	} {
		d := BuildDisclosure(GrantFacts{OrgID: "o", ServerURL: "https://o.example", OwnerManaged: tc.owner, Managed: tc.managed})
		if got := d.Owner == DisclosureOwnerManaged; got != tc.want {
			t.Errorf("%s: owner paragraph %q, want shown %v", tc.name, d.Owner, tc.want)
		}
	}
}

// TestBuildDisclosureManagedDefaults is finding F12's consent half: a managed
// enrolment's screen lists the pages and Settings sections that start hidden
// or read-only for its audience, generated from nodegov's default table
// (never a second list), with one summary sentence; an individual enrolment
// lists nothing because it has no managed defaults.
func TestBuildDisclosureManagedDefaults(t *testing.T) {
	ownerPages := []string{
		"app-traces", "app-sessions", "app-analytics", "app-end-users",
		"app-evals", "app-scores", "app-prompts", "app-alerts", "egress", "routing", "policies",
	}
	for _, tc := range []struct {
		name           string
		owner, managed bool
		audience       nodegov.ManagedAudience
		wantSummary    string // the sentence's fixed head
		wantOwnPages   bool   // ownerPages absent from the hidden list
	}{
		{"team org, managed", false, true, nodegov.ManagedAudienceTeam, "Accepting makes ", false},
		{"personal org, managed", true, true, nodegov.ManagedAudienceOwner, "Accepting makes ", true},
		{"personal org, individual (an old enrolment)", true, false, "", "", false},
		{"team org, individual", false, false, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := BuildDisclosure(GrantFacts{OrgID: "o", ServerURL: "https://o.example", OwnerManaged: tc.owner, Managed: tc.managed})
			if !tc.managed {
				if d.ManagedSummary != "" || len(d.ManagedLines)+len(d.ManagedPages)+len(d.ManagedSettings) != 0 {
					t.Fatalf("an individual enrolment lists managed defaults: %+v", d)
				}
				return
			}
			nav, settings := nodegov.ManagedRestrictions(tc.audience)
			if !slices.Equal(d.ManagedPages, nav) || !slices.Equal(d.ManagedSettings, settings) {
				t.Fatalf("lists do not come from the table for audience %q:\npages %+v\nwant  %+v\nsettings %+v\nwant     %+v",
					tc.audience, d.ManagedPages, nav, d.ManagedSettings, settings)
			}
			if !strings.HasPrefix(d.ManagedSummary, tc.wantSummary) ||
				!strings.Contains(d.ManagedSummary, strconv.Itoa(len(nav))+" dashboard pages") ||
				!strings.Contains(d.ManagedSummary, strconv.Itoa(len(settings))+" Settings sections") {
				t.Fatalf("summary %q does not count %d pages and %d sections", d.ManagedSummary, len(nav), len(settings))
			}
			if got := strings.Contains(d.ManagedSummary, "both the admin and the developer"); got != tc.owner {
				t.Errorf("summary %q: owner wording %v, want %v", d.ManagedSummary, got, tc.owner)
			}
			listed := map[string]bool{}
			for _, r := range d.ManagedPages {
				listed[r.ID] = true
				if r.Label == "" || r.Level == nodegov.VisibilityVisible {
					t.Errorf("page row %+v: needs a label and a non-visible level", r)
				}
			}
			for _, id := range ownerPages {
				if listed[id] == tc.wantOwnPages {
					t.Errorf("page %q listed %v for audience %q", id, listed[id], tc.audience)
				}
			}
			// Every listed label appears in exactly one printed line.
			joined := strings.Join(d.ManagedLines, "\n")
			for _, r := range append(append([]nodegov.ManagedRestriction{}, d.ManagedPages...), d.ManagedSettings...) {
				if !strings.Contains(joined, r.Label) {
					t.Errorf("label %q missing from the printed lines %q", r.Label, d.ManagedLines)
				}
			}
			for _, s := range append([]string{d.ManagedSummary, d.Owner}, d.ManagedLines...) {
				if strings.Contains(s, "—") || strings.Contains(s, "Plane ") {
					t.Errorf("copy rule broken in %q", s)
				}
			}
		})
	}
}

// TestOwnerParagraphNamesOnlyOwnerVisiblePages keeps DisclosureOwnerManaged
// true to the table: the pages it says stay visible for the owner are
// visible at the owner level (and hidden for a team member, which is why the
// sentence is worth saying).
func TestOwnerParagraphNamesOnlyOwnerVisiblePages(t *testing.T) {
	if !strings.Contains(DisclosureOwnerManaged, "Your AI apps pages, Egress, Routing and Policies stay visible") {
		t.Fatalf("owner paragraph no longer names the pages it keeps: %q", DisclosureOwnerManaged)
	}
	for _, id := range []string{
		"app-traces", "app-sessions", "app-analytics", "app-end-users",
		"app-evals", "app-scores", "app-prompts", "app-alerts", "egress", "routing", "policies",
	} {
		if got := nodegov.ManagedNavDefault(id, nodegov.ManagedAudienceOwner); got != nodegov.VisibilityVisible {
			t.Errorf("owner paragraph says %q stays visible, the table says %q", id, got)
		}
		if got := nodegov.ManagedNavDefault(id, nodegov.ManagedAudienceTeam); got == nodegov.VisibilityVisible {
			t.Errorf("%q is visible for a team member too; the owner sentence no longer distinguishes anything", id)
		}
	}
}

// TestManagedCount: the count phrase's singular, plural and empty halves.
func TestManagedCount(t *testing.T) {
	for _, tc := range []struct {
		pages, settings int
		want            string
	}{
		{0, 0, ""},
		{1, 0, "1 dashboard page"},
		{0, 1, "1 Settings section"},
		{2, 3, "2 dashboard pages and 3 Settings sections"},
	} {
		if got := managedCount(tc.pages, tc.settings); got != tc.want {
			t.Errorf("managedCount(%d, %d) = %q, want %q", tc.pages, tc.settings, got, tc.want)
		}
	}
	if managedSummary(false, 0, 0) != "" {
		t.Error("an empty pair of lists needs no summary")
	}
}
