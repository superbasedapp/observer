package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOrgIntelActionsViewFix pins the way forward the session card shows
// for a refusal (dead-end sweep, 2026-11-18): a local place the developer
// changes, and/or the team-dashboard place only the organization's admins
// change, the latter with a URL only for a safe org server address.
func TestOrgIntelActionsViewFix(t *testing.T) {
	enr := &store.Enrolment{OrgID: "o1", OrgServerURL: "https://org.example/"}
	cases := []struct {
		name, reason  string
		enr           *store.Enrolment
		local         string
		orgURL, label string
	}{
		{"org off", "org_off", enr, "", "https://org.example/intelligence?tab=session-enrichment", "Intelligence > Session enrichment"},
		{"org off, unsafe address", "org_off", &store.Enrolment{OrgServerURL: "http://org.example"}, "", "", "Intelligence > Session enrichment"},
		{"not opted in", "individual_not_opted_in", enr, "/settings?section=intel", "", ""},
		{"purpose", "purpose_not_allowed", enr, "/settings?section=intel", "https://org.example/intelligence?tab=session-enrichment", "Intelligence > Session enrichment"},
		{"not enrolled", "not_enrolled", nil, "/settings?section=enrolment", "", ""},
		{"personal session", "not_org_session", enr, "", "", ""},
		{"open", "", enr, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := orgIntelSession{plan: orgintel.SessionActionPlan{Reason: c.reason}}
			s.snap.Enrolment = c.enr
			v := orgIntelActionsView(s, "team")
			if v.Settings != c.local || v.OrgSettings != c.orgURL || v.OrgSettingsLabel != c.label {
				t.Fatalf("got settings=%q org=%q label=%q, want %q %q %q", v.Settings, v.OrgSettings, v.OrgSettingsLabel, c.local, c.orgURL, c.label)
			}
			if v.ReasonText != orgintel.ActionReasonText(c.reason) {
				t.Fatalf("reason text %q", v.ReasonText)
			}
		})
	}
	if got := newOrgIntelStatusView(orgIntelSnapshot{Enrolment: enr}).OrgDashboard; got != "https://org.example" {
		t.Fatalf("status org_dashboard = %q", got)
	}

	// A personal dashboard: its only admin is the person, so the sentence
	// says so, the link carries the kind, and the recorded online address
	// wins over the org server address.
	personal := &store.Enrolment{OrgID: "p1", OrgServerURL: "https://org.example", OnlineURL: "https://u-abc.superbased.app/"}
	s := orgIntelSession{plan: orgintel.SessionActionPlan{Reason: "org_off"}}
	s.snap.Enrolment = personal
	v := orgIntelActionsView(s, "personal")
	if v.ReasonText != "Your personal dashboard has session enrichment off." ||
		v.OrgSettings != "https://u-abc.superbased.app/intelligence?tab=session-enrichment" || v.OrgDashboardKind != "personal" {
		t.Fatalf("personal view = %+v", v)
	}
}

// TestReadConnectKind reads the approval record `observer connect` keeps
// beside config.toml, only for the enrolment's own organization.
func TestReadConnectKind(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readConnectKind(cfg, "p1"); got != "" {
		t.Fatalf("no record: %q", got)
	}
	if err := writeConnectConsent(cfg, connectConsentRecord{OrgID: "p1", Kind: "personal"}); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ org, want string }{{"p1", "personal"}, {"other", ""}, {"", ""}}
	for _, c := range cases {
		if got := readConnectKind(cfg, c.org); got != c.want {
			t.Errorf("readConnectKind(%q) = %q, want %q", c.org, got, c.want)
		}
	}
	if err := writeConnectConsent(cfg, connectConsentRecord{OrgID: "p1", Kind: "weird"}); err != nil {
		t.Fatal(err)
	}
	if got := readConnectKind(cfg, "p1"); got != "" {
		t.Fatalf("unknown kind read as %q", got)
	}
}

// TestProjectsJudgeGradePlace: the judge tier's way forward is its switch
// while the switch is off, else the judge's model; none while it runs.
func TestProjectsJudgeGradePlace(t *testing.T) {
	off := &config.Config{}
	on := &config.Config{}
	on.Projects.AlignmentJudge = "obs_judge"
	cases := []struct {
		name      string
		cfg       *config.Config
		available bool
		want      settingslink.Place
	}{
		{"running", on, true, ""},
		{"switch off", off, false, settingslink.IntelligenceSettings},
		{"no model", on, false, settingslink.ObservabilitySettings},
		{"no config", nil, false, ""},
	}
	for _, c := range cases {
		want := c.want
		if !judgeClientInBuild {
			want = ""
		}
		if got := projectsJudgeGradePlace(c.cfg, c.available); got != want {
			t.Errorf("%s: %q, want %q", c.name, got, want)
		}
	}
}
