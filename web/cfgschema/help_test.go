package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/configschema"
)

// TestUserHelp: each row is a doc comment shape seen in internal/config and
// the help Settings shows for it (U-14).
func TestUserHelp(t *testing.T) {
	cases := []struct {
		name, doc, ident, want string
	}{
		{"type_controls", "RetentionConfig controls DB pruning.", "RetentionConfig", "Controls DB pruning."},
		{"is_the", "UserPolicy is the user policy file location.", "UserPolicy", "The user policy file location."},
		{"table_surface", "ObservabilityAdmissionConfig is the [observability.admission] surface (admission spec §4).", "ObservabilityAdmissionConfig", ""},
		{"table_then_text", "GuardBudgetWindowConfig is [guard.budget.window] (spec §12.1) — utilization thresholds over the windows.", "GuardBudgetWindowConfig", "Utilization thresholds over the windows."},
		{"two_subjects", "WeeklyUSD / MonthlyUSD are $ ceilings over a rolling window (rules B-604 / B-603).", "WeeklyUSD", "$ ceilings over a rolling window."},
		{"leading_parenthetical", "UploadNonGit (decision SBXD-8, audit item H8) uploads a folder that is not a git repository.", "UploadNonGit", "Uploads a folder that is not a git repository."},
		{"quoted_label_choice_list", `PostWriteCapKiB is "Largest file scanned after a write": one of SecurityPostWriteCapsKiB. The hook's cap is fixed [JSP-2]. Default 256.`, "PostWriteCapKiB", "Largest file scanned after a write. The hook's cap is fixed. Default 256."},
		{"quoted_label_text", `WriteCheck is "Secret check before writes": while true the rule judges a write.`, "WriteCheck", "Secret check before writes. While true the rule judges a write."},
		{"code_pointer", "ConnMaxIdleSeconds bounds how long an idle connection is kept (see database/sql.DB.SetConnMaxIdleTime). Zero applies a default.", "ConnMaxIdleSeconds", "Bounds how long an idle connection is kept. Zero applies a default."},
		{"plain_parenthetical_kept", "Desktop sends a notification (sender and subject only) once per message.", "Desktop", "Sends a notification (sender and subject only) once per message."},
		{"multi_line", "Window is the local\nmaintenance window.", "Window", "The local maintenance window."},
		{"empty", "", "Enabled", ""},
	}
	for _, c := range cases {
		if got := userHelp(c.doc, c.ident); got != c.want {
			t.Errorf("%s: userHelp = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestHelpOverridesNameRealKeys: every hand-written help names a table or a
// leaf that exists, so a renamed key cannot leave its help behind.
func TestHelpOverridesNameRealKeys(t *testing.T) {
	desc := configschema.Describe()
	known := map[string]bool{}
	for _, l := range desc.Leaves {
		known[l.Path] = true
	}
	for _, tb := range desc.Tables {
		known[tb.Path] = true
	}
	for k := range helpOverrides {
		if !known[k] {
			t.Errorf("helpOverrides names %q, which is not a config key or table", k)
		}
	}
}

// TestHelpCarriesNoGoIdentifiers walks the whole schema: no help opens with
// its own Go identifier, and none keeps a section sign (the U-14 symptom).
func TestHelpCarriesNoGoIdentifiers(t *testing.T) {
	docs, err := harvestDocs("../..")
	if err != nil {
		t.Fatal(err)
	}
	desc := configschema.Describe()
	check := func(path, doc, ident string) {
		h := helpFor(path, doc, ident)
		if ident != "" && strings.HasPrefix(h, ident+" ") {
			t.Errorf("%s: help opens with its Go identifier: %q", path, h)
		}
		if strings.Contains(h, "§") {
			t.Errorf("%s: help keeps a section sign: %q", path, h)
		}
	}
	for _, l := range desc.Leaves {
		check(l.Path, docs[l.Owner+"."+l.Field], l.Field)
	}
	for _, tb := range desc.Tables {
		check(tb.Path, docs[tb.Owner], typeName(tb.Owner))
	}
}
