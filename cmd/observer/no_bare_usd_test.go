package main

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The Go no-bare-usd guard (T-204), the twin of web2's noBareUsd.test.ts.
//
// Under the token-usage developer cost display (D-013) every developer
// surface renders cost as token usage. A Go file that formats a dollar figure
// ("$%.2f", "$" + amount) is a site that can ignore the display, so this test
// fails when such a site appears in the node binary's code (cmd/observer and
// internal/, minus the admin planes below) unless it is classified here:
//
//   - cliRow: the file belongs to a reporting command listed in
//     costReportCommands, whose stdout renders under the display
//     (costdisplay_cli.go); the row must exist.
//   - reason: anything else. The reason says why the figure is safe (it is
//     mode-aware, it is not money, or it is an admin surface), and the file
//     must carry a `no-bare-usd:allow` marker comment at the site so the
//     reason travels with the code.
//
// An entry that stops matching fails too, so the list cannot rot.

// noBareUSDAdminPlanes are excluded wholesale: admin-facing planes, where
// admins always see dollars (operator ruling 2026-10-02).
var noBareUSDAdminPlanes = []string{
	"internal/orgserver/", "internal/cloudserver/", "internal/mcpgw/", "internal/obs/", "internal/evalcore/",
}

var noBareUSDSite = regexp.MustCompile(`\$%[-+ #0-9.]*[fdgsv]|\$"\s*\+`)

type noBareUSDEntry struct {
	cliRow string
	reason string
}

var noBareUSDAllow = map[string]noBareUSDEntry{
	"cmd/observer/advise.go":          {cliRow: "advise"},
	"cmd/observer/aggregate.go":       {cliRow: "aggregate"},
	"cmd/observer/backfill.go":        {cliRow: "backfill"},
	"cmd/observer/backfill_codex.go":  {cliRow: "backfill"},
	"cmd/observer/benchmark.go":       {cliRow: "benchmark"},
	"cmd/observer/benchmark_run.go":   {cliRow: "benchmark"},
	"cmd/observer/cache_status.go":    {cliRow: "cache-status"},
	"cmd/observer/handoff.go":         {cliRow: "handoff"},
	"cmd/observer/model_value.go":     {cliRow: "model-value"},
	"cmd/observer/project.go":         {cliRow: "project"},
	"cmd/observer/report.go":          {cliRow: "report"},
	"cmd/observer/reprice.go":         {cliRow: "reprice"},
	"cmd/observer/routing.go":         {cliRow: "routing"},
	"cmd/observer/routing_savings.go": {cliRow: "routing"},
	"cmd/observer/tasks.go":           {cliRow: "tasks"},
	"cmd/observer/verbosity.go":       {cliRow: "verbosity"},
	"cmd/observer/cost.go": {reason: "costCell renders the COST_USD cell only when costtext.Tokens is false; " +
		"the token view leaves the column out (printCostSummaryAs)."},
	"cmd/observer/predict.go": {reason: "predictBandRow prints the dollar row only in the dollar view; the token " +
		"view returns before it."},
	"cmd/observer/advisor_digest.go": {reason: "the session-start digest is masked with costtext.MaskDollars under " +
		"the resolved display before it is injected."},
	"cmd/observer/admission.go": {reason: "Plane A admission caps (observer obs admission): an admin-hosted app's " +
		"authored dollar caps, not a developer's coding spend."},
	"cmd/observer/cloud.go": {reason: "the Cloud Intelligence preview prints the exact bytes and metrics that " +
		"would leave the machine (two-digest truth); re-denominating them would make the preview lie."},
	"cmd/observer/cloudconsent.go": {reason: "not money: a flag help string naming an environment variable ($SBO_CLOUD_BASE_URL)."},
	"cmd/observer/cloudenable.go":  {reason: "not money: a flag help string naming an environment variable ($SBO_CLOUD_BASE_URL)."},
	"cmd/observer/security_verify_org.go": {reason: "not money: an error naming the environment variable the CI " +
		"credential is read from ($<name>)."},
	"cmd/observer/security_verify_upload.go": {reason: "not money: an error naming the environment variable the CI " +
		"credential is read from ($<name>)."},
	"internal/accessgrant/describe.go": {reason: "the org decision preview an admin approves (web2), where admins always see dollars."},
	"internal/arena/keep.go": {reason: "provenanceUsage writes the dollar figure only when the developer display " +
		"shows dollars (Runner Options.CostDisplay)."},
	"internal/benchmark/budget.go": {reason: "the ledger's error_class; printed only by the benchmark CLI (covered by " +
		"the benchmark row) and never rendered by the dashboard."},
	"internal/budgetwarn/budgetwarn.go": {reason: "budget warnings render shares of the cap under the token display " +
		"(42274ed2d); the dollar formatter runs only in the dollar view."},
	"internal/intelligence/advisor/detect_phase2.go":       {reason: advisorProseReason},
	"internal/intelligence/advisor/detect_phase4.go":       {reason: advisorProseReason},
	"internal/intelligence/advisor/detect_posture.go":      {reason: advisorProseReason},
	"internal/intelligence/advisor/detect_routing.go":      {reason: advisorProseReason},
	"internal/intelligence/advisor/detect_session_econ.go": {reason: advisorProseReason},
	"internal/intelligence/advisor/detect_spike.go":        {reason: advisorProseReason},
	"internal/notify/digest/digest.go": {reason: "money() runs only in the dollar view; Data.CostDisplay renders " +
		"token figures and drops the movers section under the token display."},
	"internal/notify/sharecard/sharecard.go": {reason: "the shareable spend card; `observer report share` refuses " +
		"to build it under the token display."},
	"internal/oneshot/render.go": {reason: "the one-shot usage report runs only on a machine with no observer " +
		"state (never enrolled, so dollars) and `observer usage` is a covered row."},
	"internal/policy/budget_display.go": {reason: "the ONE owner of the dollar budget and session-spend templates; " +
		"BudgetReasonWithoutDollars / CostConditionReasonWithoutDollars render the token view."},
	"internal/remoteauth/argon2.go": {reason: "not money: the PHC string format ($argon2id$...)."},
	"internal/sandboxremote/vendors.go": {reason: "a remote sandbox vendor's compute list price for box-minutes, " +
		"labelled an estimate; it is not model spend, so the token display has nothing to re-denominate it into."},
	"internal/statusline/segments.go": {reason: "the statusline tile renders TodayTokens / SessionTokens under the " +
		"token display (DaemonTile.tokenMode); the dollar formatter is the dollar view."},
}

const advisorProseReason = "advisor prose: every surface masks it under the token display (the Suggestions " +
	"page through maskDollarAmounts, the advise CLI through the costtext writer, MCP results at the tool-result " +
	"seam, the session digest through MaskDollars)."

func noBareUSDHits(t *testing.T, root string) []string {
	t.Helper()
	var hits []string
	for _, dir := range []string{"cmd/observer", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel := filepath.ToSlash(strings.TrimPrefix(p, root+string(filepath.Separator)))
			if d.IsDir() {
				for _, plane := range noBareUSDAdminPlanes {
					if rel+"/" == plane {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
				return nil
			}
			if dir == "cmd/observer" && strings.Contains(strings.TrimPrefix(rel, "cmd/observer/"), "/") {
				return nil
			}
			if fileHasDollarSite(t, p) {
				hits = append(hits, rel)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	sort.Strings(hits)
	return hits
}

func fileHasDollarSite(t *testing.T, path string) bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "//") {
			continue
		}
		if noBareUSDSite.MatchString(line) {
			return true
		}
	}
	return false
}

func TestNoBareUSDInDeveloperSurfaces(t *testing.T) {
	root := filepath.Join("..", "..")
	rows := map[string]bool{}
	for _, r := range costReportCommands {
		rows[r.path] = true
	}
	hits := noBareUSDHits(t, root)
	seen := map[string]bool{}
	var unclassified []string
	for _, rel := range hits {
		seen[rel] = true
		e, ok := noBareUSDAllow[rel]
		if !ok {
			unclassified = append(unclassified, rel)
			continue
		}
		if e.cliRow != "" {
			if !rows[e.cliRow] {
				t.Errorf("%s names costReportCommands row %q, which does not exist", rel, e.cliRow)
			}
			continue
		}
		if len(e.reason) < 40 {
			t.Errorf("%s needs a real reason", rel)
		}
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), "no-bare-usd:allow") {
			t.Errorf("%s is allow-listed but carries no no-bare-usd:allow marker at the site", rel)
		}
	}
	if len(unclassified) > 0 {
		t.Errorf("these files format a dollar figure that may ignore the developer cost display (T-204). "+
			"Render it through internal/costtext (or the dashboard's formatter seam), cover the command in "+
			"costReportCommands, or allow-list it here with a reason and a no-bare-usd:allow marker: %v", unclassified)
	}
	for rel := range noBareUSDAllow {
		if !seen[rel] {
			t.Errorf("%s is allow-listed but no longer formats a dollar figure; remove the entry", rel)
		}
	}
}

// TestNoBareUSDPatternMatches pins the site pattern both ways.
func TestNoBareUSDPatternMatches(t *testing.T) {
	for _, s := range []string{`fmt.Sprintf("$%.2f", v)`, `"cost $%.4f"`, `return "$" + strconv.FormatFloat(v)`, `"-$%+.4f"`} {
		if !noBareUSDSite.MatchString(s) {
			t.Errorf("pattern misses %s", s)
		}
	}
	for _, s := range []string{`"!#$%&'*+-.^_|~"`, `"$HOME/bin"`, `"echo \"$1\""`, `"%d tok"`} {
		if noBareUSDSite.MatchString(s) {
			t.Errorf("pattern over-matches %s", s)
		}
	}
}
