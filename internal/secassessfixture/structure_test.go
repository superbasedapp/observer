package secassessfixture

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// fixtureRoot is testdata/secassess, relative to this package directory.
const fixtureRoot = "../../testdata/secassess"

func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return data
}

func loadManifest(t *testing.T) Manifest {
	t.Helper()
	m, err := ParseManifest(readFixture(t, "truth/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func loadThreatModel(t *testing.T) ThreatModel {
	t.Helper()
	tm, err := ParseThreatModel(readFixture(t, "truth/threatmodel.json"))
	if err != nil {
		t.Fatal(err)
	}
	return tm
}

func loadProbes(t *testing.T) Probes {
	t.Helper()
	p, err := ParseProbes(readFixture(t, "truth/probes.json"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// appFile reads a file of the application the answer key's anchors point into.
func appFile(t *testing.T, name string) []byte {
	t.Helper()
	return readFixture(t, "app/"+name)
}

// anchorLine resolves an anchor in an app file and checks it is on a code line
// or a comment line as wanted.
func anchorLine(t *testing.T, file, anchor string, wantComment bool) int {
	t.Helper()
	src := appFile(t, file)
	line, err := LineOf(src, anchor)
	if err != nil {
		t.Errorf("%s: %v", file, err)
		return 0
	}
	if IsCommentLine(LineText(src, line)) != wantComment {
		t.Errorf("%s:%d: anchor %q is on a line whose comment-ness is not %v", file, line, anchor, wantComment)
	}
	return line
}

func TestFixtureTruthParsesWithNotices(t *testing.T) {
	m, tm, p := loadManifest(t), loadThreatModel(t), loadProbes(t)
	for name, notice := range map[string]string{"manifest": m.Notice, "threatmodel": tm.Notice, "probes": p.Notice} {
		if !strings.Contains(strings.ToLower(notice), "deliberately vulnerable") && !strings.Contains(strings.ToLower(notice), "local testing") {
			t.Errorf("%s notice does not say it belongs to a fixture for local testing: %q", name, notice)
		}
	}
	if m.Scoring.AnchorWindowLines != 5 {
		t.Errorf("anchor window = %d, the plan says 5", m.Scoring.AnchorWindowLines)
	}
}

var (
	reFlawID  = regexp.MustCompile(`^F[0-9]{2}$`)
	reDecoyID = regexp.MustCompile(`^D[0-9]{2}$`)
	reTrapID  = regexp.MustCompile(`^TR[0-9]$`)
	reCWE     = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
)

// wstgCategories are the 12 two-to-four letter categories of the plan's WSTG
// vocabulary (depth plan section 3.3).
var wstgCategories = map[string]bool{
	"INFO": true, "CONF": true, "IDNT": true, "ATHN": true, "ATHZ": true, "SESS": true,
	"INPV": true, "ERRH": true, "CRYP": true, "BUSL": true, "CLNT": true, "APIT": true,
}

func TestFixtureInventoryCounts(t *testing.T) {
	m, tm := loadManifest(t), loadThreatModel(t)
	counts := []struct {
		name      string
		got, want int
	}{
		{"flaws", len(m.Flaws), 14},
		{"decoys", len(m.Decoys), 6},
		{"traps", len(tm.Traps), 3},
		{"zones", len(tm.Zones), 3},
		{"components", len(tm.Components), 7},
		{"flows", len(tm.Flows), 9},
		{"expected threats", len(tm.Threats), 14},
		{"existing mitigations", len(tm.Existing), 6},
	}
	for _, c := range counts {
		if c.got != c.want {
			t.Errorf("%s = %d, the plan says %d", c.name, c.got, c.want)
		}
	}
}

func TestFixtureManifestRows(t *testing.T) {
	m, tm := loadManifest(t), loadThreatModel(t)
	decoys := map[string]Decoy{}
	for _, d := range m.Decoys {
		if !reDecoyID.MatchString(d.ID) {
			t.Errorf("decoy id %q is malformed", d.ID)
		}
		if _, dup := decoys[d.ID]; dup {
			t.Errorf("decoy id %s repeats", d.ID)
		}
		decoys[d.ID] = d
		if d.File != m.Fixture.Entry || len(d.Anchors) == 0 || d.WhySafe == "" || d.Title == "" || d.Route == "" {
			t.Errorf("decoy %s is incomplete: %+v", d.ID, d)
		}
		for _, c := range d.CWEIfReported {
			if !reCWE.MatchString(c) {
				t.Errorf("decoy %s: malformed CWE %q", d.ID, c)
			}
		}
	}
	traps := map[string]bool{}
	for _, tr := range tm.Traps {
		traps[tr.ID] = true
	}
	seen := map[string]bool{}
	nearOf := map[string]bool{}
	for i, f := range m.Flaws {
		if want := fmt.Sprintf("F%02d", i+1); f.ID != want || !reFlawID.MatchString(f.ID) {
			t.Errorf("flaw %d has id %q, want %s", i+1, f.ID, want)
		}
		if seen[f.ID] {
			t.Errorf("flaw id %s repeats", f.ID)
		}
		seen[f.ID] = true
		if f.File != m.Fixture.Entry || len(f.Anchors) == 0 || f.Description == "" || f.Title == "" || f.Route == "" || f.Class == "" {
			t.Errorf("flaw %s is incomplete", f.ID)
		}
		if len(f.CWE) == 0 || len(f.WSTG) == 0 {
			t.Errorf("flaw %s needs a CWE and a WSTG category", f.ID)
		}
		for _, c := range append(append([]string{}, f.CWE...), f.CWEFamily...) {
			if !reCWE.MatchString(c) {
				t.Errorf("flaw %s: malformed CWE %q", f.ID, c)
			}
		}
		for _, w := range f.WSTG {
			if !wstgCategories[w] {
				t.Errorf("flaw %s: %q is not a WSTG category of the plan", f.ID, w)
			}
		}
		switch f.SeverityHint {
		case "low", "medium", "high", "critical":
		default:
			t.Errorf("flaw %s: severity hint %q", f.ID, f.SeverityHint)
		}
		for _, id := range f.Decoys {
			d, ok := decoys[id]
			if !ok {
				t.Errorf("flaw %s names unknown decoy %s", f.ID, id)
				continue
			}
			if d.NearMissOf != f.ID {
				t.Errorf("flaw %s lists decoy %s, which is a near miss of %s", f.ID, id, d.NearMissOf)
			}
			nearOf[id] = true
		}
		for _, id := range f.Traps {
			if !traps[id] {
				t.Errorf("flaw %s names unknown trap %s", f.ID, id)
			}
		}
	}
	for id := range decoys {
		if !nearOf[id] {
			t.Errorf("decoy %s is listed by no flaw", id)
		}
	}
	if len(m.Incidental) == 0 {
		t.Error("the manifest lists no incidental properties")
	}
	for _, in := range m.Incidental {
		for _, c := range in.CWE {
			if !reCWE.MatchString(c) {
				t.Errorf("incidental %s: malformed CWE %q", in.ID, c)
			}
		}
	}
}

// TestFixtureAnchorsResolve: every anchor is a substring that occurs exactly
// once, on a code line (a trap's comment anchors on a comment line).
func TestFixtureAnchorsResolve(t *testing.T) {
	m, tm := loadManifest(t), loadThreatModel(t)
	for _, f := range m.Flaws {
		for _, a := range f.Anchors {
			anchorLine(t, f.File, a, false)
		}
	}
	for _, d := range m.Decoys {
		for _, a := range d.Anchors {
			anchorLine(t, d.File, a, false)
		}
	}
	for _, c := range tm.Components {
		for _, a := range c.Anchors {
			anchorLine(t, c.File, a, false)
		}
	}
	for _, fl := range tm.Flows {
		for _, a := range fl.Anchors {
			anchorLine(t, m.Fixture.Entry, a, false)
		}
	}
	for _, mit := range tm.Existing {
		for _, a := range mit.Anchors {
			anchorLine(t, mit.File, a, false)
		}
		src := string(appFile(t, mit.File))
		if strings.Count(src, mit.Needle) < 1 {
			t.Errorf("mitigation %s: needle %q is not in %s", mit.ID, mit.Needle, mit.File)
		}
		if len(mit.Needle) < 8 {
			t.Errorf("mitigation %s: needle %q is shorter than 8 characters", mit.ID, mit.Needle)
		}
	}
	for _, tr := range tm.Traps {
		wantComment := tr.Kind == "comment_claim" || tr.Kind == "comment_authz"
		for _, a := range tr.Anchors {
			isCommentAnchor := strings.HasPrefix(a, "#")
			if wantComment != isCommentAnchor && tr.Kind != "inert_validator" {
				t.Errorf("trap %s (%s): anchor %q has the wrong shape", tr.ID, tr.Kind, a)
			}
			anchorLine(t, tr.File, a, isCommentAnchor)
		}
	}
}

// TestFixtureAnchorSpacing pins the guarantee written in the manifest: a
// decoy anchor is at least 11 lines from any other flaw or decoy anchor (two
// windows of 5 lines cannot overlap), and anchors of two different flaws are at
// least 6 lines apart.
func TestFixtureAnchorSpacing(t *testing.T) {
	m := loadManifest(t)
	type pos struct {
		id   string
		line int
		anc  string
	}
	var all []pos
	add := func(id, file string, anchors []string) {
		for _, a := range anchors {
			all = append(all, pos{id: id, line: anchorLine(t, file, a, false), anc: a})
		}
	}
	for _, f := range m.Flaws {
		add(f.ID, f.File, f.Anchors)
	}
	for _, d := range m.Decoys {
		add(d.ID, d.File, d.Anchors)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].line < all[j].line })
	for i := range all {
		for j := i + 1; j < len(all); j++ {
			a, b := all[i], all[j]
			if a.id == b.id {
				continue
			}
			need := 6
			if strings.HasPrefix(a.id, "D") || strings.HasPrefix(b.id, "D") {
				need = 11
			}
			if b.line-a.line < need {
				t.Errorf("%s line %d and %s line %d are %d lines apart, need %d", a.id, a.line, b.id, b.line, b.line-a.line, need)
			}
		}
	}
}

// TestFixtureTrapsSitInsideFlawWindows: a trap is a false claim next to the
// weakness it pretends to cover, so one of its anchors is within the window of
// one of its flaw's anchors.
func TestFixtureTrapsSitInsideFlawWindows(t *testing.T) {
	m, tm := loadManifest(t), loadThreatModel(t)
	flaws := map[string]Flaw{}
	for _, f := range m.Flaws {
		flaws[f.ID] = f
	}
	for _, tr := range tm.Traps {
		if !reTrapID.MatchString(tr.ID) {
			t.Errorf("trap id %q is malformed", tr.ID)
		}
		f, ok := flaws[tr.Flaw]
		if !ok {
			t.Errorf("trap %s names unknown flaw %s", tr.ID, tr.Flaw)
			continue
		}
		listed := false
		for _, id := range f.Traps {
			if id == tr.ID {
				listed = true
			}
		}
		if !listed {
			t.Errorf("trap %s names flaw %s, which does not list it", tr.ID, f.ID)
		}
		near := false
		for _, ta := range tr.Anchors {
			tl := anchorLine(t, tr.File, ta, strings.HasPrefix(ta, "#"))
			for _, fa := range f.Anchors {
				fl := anchorLine(t, f.File, fa, false)
				if d := tl - fl; d >= -m.Scoring.AnchorWindowLines && d <= m.Scoring.AnchorWindowLines {
					near = true
				}
			}
		}
		if !near {
			t.Errorf("trap %s has no anchor within %d lines of flaw %s", tr.ID, m.Scoring.AnchorWindowLines, f.ID)
		}
		if len(tr.ExpectedRefState) == 0 || tr.Claim == "" || tr.Why == "" {
			t.Errorf("trap %s is incomplete", tr.ID)
		}
	}
}

func TestFixtureThreatModelConsistency(t *testing.T) {
	m, tm := loadManifest(t), loadThreatModel(t)
	zones := map[string]bool{}
	for _, z := range tm.Zones {
		zones[z.ID] = true
	}
	actors := map[string]bool{}
	for _, a := range tm.Actors {
		actors[a.ID] = true
	}
	// element id -> STRIDE type and zone
	type elem struct {
		typ, zone string
		logs      bool
	}
	elems := map[string]elem{}
	for _, c := range tm.Components {
		if !zones[c.Zone] {
			t.Errorf("component %s is in unknown zone %q", c.ID, c.Zone)
		}
		typ := map[string]string{"process": "process", "data_store": "data_store"}[c.Type]
		if typ == "" {
			t.Errorf("component %s has type %q", c.ID, c.Type)
		}
		if _, dup := elems[c.ID]; dup {
			t.Errorf("element id %s repeats", c.ID)
		}
		elems[c.ID] = elem{typ: typ, zone: c.Zone, logs: c.HoldsLogs != nil && *c.HoldsLogs}
		if len(c.NameHints) == 0 {
			t.Errorf("component %s has no name hints", c.ID)
		}
	}
	for _, a := range tm.Actors {
		if _, dup := elems[a.ID]; dup {
			t.Errorf("element id %s repeats", a.ID)
		}
		elems[a.ID] = elem{typ: "external_entity", zone: "Z1"}
	}
	for _, as := range tm.Assets {
		for _, s := range as.StoredIn {
			if _, ok := elems[s]; !ok {
				t.Errorf("asset %s is stored in unknown element %s", as.ID, s)
			}
		}
	}
	for _, f := range tm.Flows {
		from, okf := elems[f.From]
		to, okt := elems[f.To]
		if !okf || !okt {
			t.Errorf("flow %s joins unknown elements %s -> %s", f.ID, f.From, f.To)
			continue
		}
		if _, dup := elems[f.ID]; dup {
			t.Errorf("element id %s repeats", f.ID)
		}
		elems[f.ID] = elem{typ: "data_flow"}
		var want []string
		if from.zone != to.zone {
			want = []string{from.zone, to.zone}
		}
		if strings.Join(f.Crosses, ",") != strings.Join(want, ",") {
			t.Errorf("flow %s crosses %v, its endpoints imply %v", f.ID, f.Crosses, want)
		}
	}
	applies := func(c Cell) bool {
		e, ok := elems[c.ID]
		if !ok {
			return false
		}
		for _, cat := range tm.StrideApplicability.Categories(e.typ, e.logs) {
			if cat == c.Category {
				return true
			}
		}
		return false
	}
	flawHasThreat := map[string]int{}
	primary := map[string]string{}
	for _, th := range tm.Threats {
		flawHasThreat[th.Flaw]++
		key := th.Element.ID + "/" + th.Category
		if other, dup := primary[key]; dup {
			t.Errorf("threats %s and %s share the key %s", th.ID, other, key)
		}
		primary[key] = th.ID
		if !applies(Cell{ID: th.Element.ID, Category: th.Category}) {
			t.Errorf("threat %s: STRIDE %s does not apply to %s", th.ID, th.Category, th.Element.ID)
		}
		if k := elems[th.Element.ID]; (k.typ == "data_flow") != (th.Element.Kind == "flow") {
			t.Errorf("threat %s: element kind %q does not match %s", th.ID, th.Element.Kind, th.Element.ID)
		}
		seen := map[string]bool{key: true}
		for _, a := range th.Accept {
			ak := a.ID + "/" + a.Category
			if seen[ak] {
				t.Errorf("threat %s accepts %s twice (or its own key)", th.ID, ak)
			}
			seen[ak] = true
			if !applies(a) {
				t.Errorf("threat %s accepts %s, which STRIDE does not apply to", th.ID, ak)
			}
		}
	}
	for _, f := range m.Flaws {
		if flawHasThreat[f.ID] != 1 {
			t.Errorf("flaw %s has %d expected threats, want 1", f.ID, flawHasThreat[f.ID])
		}
	}
	decoys := map[string]Decoy{}
	for _, d := range m.Decoys {
		decoys[d.ID] = d
	}
	seenDecoy := map[string]bool{}
	for _, mit := range tm.Existing {
		d, ok := decoys[mit.Decoy]
		if !ok {
			t.Errorf("mitigation %s names unknown decoy %s", mit.ID, mit.Decoy)
			continue
		}
		if seenDecoy[mit.Decoy] {
			t.Errorf("decoy %s has two mitigations", mit.Decoy)
		}
		seenDecoy[mit.Decoy] = true
		if strings.Join(mit.Anchors, "|") != strings.Join(d.Anchors, "|") {
			t.Errorf("mitigation %s anchors %v differ from decoy %s anchors %v", mit.ID, mit.Anchors, d.ID, d.Anchors)
		}
		if !applies(Cell{ID: mit.Element.ID, Category: mit.Category}) {
			t.Errorf("mitigation %s: STRIDE %s does not apply to %s", mit.ID, mit.Category, mit.Element.ID)
		}
	}
	for id := range decoys {
		if !seenDecoy[id] {
			t.Errorf("decoy %s has no existing mitigation row", id)
		}
	}
	for _, tr := range tm.Traps {
		if !applies(Cell{ID: tr.ClaimedFor.Element.ID, Category: tr.ClaimedFor.Category}) {
			t.Errorf("trap %s claims for an inapplicable cell", tr.ID)
		}
	}
}

func TestFixtureProbesCoverEveryFlawAndDecoy(t *testing.T) {
	m, p := loadManifest(t), loadProbes(t)
	checkReq := func(where string, r Request) {
		if r.Method != "GET" && r.Method != "POST" {
			t.Errorf("%s: method %q", where, r.Method)
		}
		if !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "://") {
			t.Errorf("%s: path %q must be a path on the fixture, never a URL", where, r.Path)
		}
		if r.Times < 0 || r.Repeat < 0 {
			t.Errorf("%s: negative times or repeat", where)
		}
	}
	nonEmpty := func(where string, in Indicator) {
		if in.Status == 0 && len(in.BodyContains) == 0 && len(in.BodyNotContains) == 0 && len(in.HeaderPresent) == 0 &&
			len(in.HeaderAbsent) == 0 && len(in.HeaderContains) == 0 && len(in.SetCookieLacks) == 0 && in.CookieIncrement == nil {
			t.Errorf("%s: the indicator tests nothing", where)
		}
	}
	flawProbes := map[string]FlawProbe{}
	for _, fp := range p.Flaws {
		flawProbes[fp.ID] = fp
	}
	for _, f := range m.Flaws {
		fp, ok := flawProbes[f.ID]
		if !ok || len(fp.Confirmations) == 0 {
			t.Errorf("flaw %s has no confirming probe", f.ID)
			continue
		}
		for _, c := range fp.Confirmations {
			where := f.ID + "/" + c.Name
			checkReq(where+" control", c.Control)
			checkReq(where+" attack", c.Attack)
			for _, s := range c.Setup {
				checkReq(where+" setup", s)
			}
			nonEmpty(where, c.Indicator)
			if c.Indicator.CookieIncrement != nil && c.Attack.Repeat < 2 {
				t.Errorf("%s: cookie_increments needs an attack with repeat >= 2", where)
			}
		}
	}
	if len(p.Flaws) != len(m.Flaws) {
		t.Errorf("probes list %d flaws, the manifest %d", len(p.Flaws), len(m.Flaws))
	}
	decoyProbes := map[string]DecoyProbe{}
	for _, dp := range p.Decoys {
		decoyProbes[dp.ID] = dp
	}
	for _, d := range m.Decoys {
		dp, ok := decoyProbes[d.ID]
		if !ok {
			t.Errorf("decoy %s has no probe", d.ID)
			continue
		}
		checkReq(d.ID+" attack", dp.Attack)
		checkReq(d.ID+" works", dp.Works.Request)
		nonEmpty(d.ID+" flaw_indicator", dp.FlawIndicator)
		nonEmpty(d.ID+" works", dp.Works.Indicator)
	}
	if len(p.Decoys) != len(m.Decoys) {
		t.Errorf("probes list %d decoys, the manifest %d", len(p.Decoys), len(m.Decoys))
	}
	for _, c := range p.Containment {
		for _, ch := range c.Checks {
			checkReq(c.ID, ch.Request)
			nonEmpty(c.ID, ch.Expect)
		}
	}
}

func TestFixtureManifestFilesExist(t *testing.T) {
	m := loadManifest(t)
	for _, f := range m.Fixture.Files {
		if _, err := os.Stat(filepath.Join(fixtureRoot, m.Fixture.AppDir, filepath.FromSlash(f))); err != nil {
			t.Errorf("manifest lists %s: %v", f, err)
		}
	}
	if m.Fixture.Target.ConsolePort != m.Fixture.Target.Port+1 {
		t.Errorf("console port %d is not the app port %d plus one", m.Fixture.Target.ConsolePort, m.Fixture.Target.Port)
	}
}

// fixtureFiles lists every file under testdata/secassess (slash paths relative
// to it).
func fixtureFiles(t *testing.T) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(fixtureRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(fixtureRoot, p)
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

// tellWords are words the application must never contain: the agent reads the
// application, and a label would hand it the answer (depth plan section 7,
// rule 3). The deliberately-vulnerable notices live outside app/.
var tellWords = []string{
	"vulnerab", "insecure", "flaw", "exploit", "fixme", "backdoor", "deliberate", "on purpose",
	"intentional", "seeded", "decoy", "owasp", "cwe", "wstg", "hack", "payload", "attack", "malicious",
}

var (
	reEmail = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)`)
	reURL   = regexp.MustCompile(`https?://([^/\s"'<>)]+)`)
	reHost  = regexp.MustCompile(`(?i)(c:\\users|/home/|/users/|/mnt/|marmu|appdata|\.local/share)`)
	// reSecrets are the shapes scripts/release.sh blocks in the public tree
	// (its GITLEAKS_BLOCKING_RULES_RE and built-in rules).
	reSecrets = map[string]*regexp.Regexp{
		"aws-access-key-id": regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`),
		"gcp-api-key":       regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		"private-key":       regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY`),
		"stripe-live-key":   regexp.MustCompile(`[rs]k_live_[0-9A-Za-z]{20,}`),
		"github-token":      regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36}`),
		"github-pat":        regexp.MustCompile(`github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}`),
		"slack-token":       regexp.MustCompile(`xox[abposr]-[0-9A-Za-z]+-[0-9A-Za-z-]{10,}`),
		"slack-webhook":     regexp.MustCompile(`hooks\.slack\.com/(?:services|workflows)/T[A-Z0-9]{6,}`),
		"jwt":               regexp.MustCompile(`\bey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9/_-]{17,}\.`),
	}
)

// TestFixtureHasNoTells always runs: the application carries no label that
// names a weakness, no process environment, no machine data and no secret
// shape; the whole fixture tree carries no secret shape the release scan
// blocks.
func TestFixtureHasNoTells(t *testing.T) {
	for _, rel := range fixtureFiles(t) {
		data := readFixture(t, rel)
		text := string(data)
		for name, re := range reSecrets {
			if loc := re.FindStringIndex(text); loc != nil {
				t.Errorf("%s: matches the %s shape at byte %d", rel, name, loc[0])
			}
		}
		if reHost.MatchString(text) {
			t.Errorf("%s: carries a path or name from a development machine: %q", rel, reHost.FindString(text))
		}
		if !strings.HasPrefix(rel, "app/") {
			continue
		}
		lower := strings.ToLower(text)
		for _, w := range tellWords {
			if i := strings.Index(lower, w); i >= 0 {
				t.Errorf("%s: contains %q at line %d", rel, w, 1+strings.Count(text[:i], "\n"))
			}
		}
		for _, m := range reEmail.FindAllStringSubmatch(text, -1) {
			if !strings.HasSuffix(m[1], ".invalid") {
				t.Errorf("%s: %q is not a reserved .invalid address", rel, m[0])
			}
		}
		for _, m := range reURL.FindAllStringSubmatch(text, -1) {
			switch host := m[1]; {
			case host == "127.0.0.1", host == "localhost", strings.HasPrefix(host, "%s"), strings.HasPrefix(host, "127.0.0.1:"):
			default:
				t.Errorf("%s: URL host %q is not loopback", rel, host)
			}
		}
	}
	src := string(appFile(t, "server.py"))
	if n := strings.Count(src, "os.environ"); n != 1 || !strings.Contains(src, `os.environ.get("OBSERVER_SECASSESS_FIXTURE")`) {
		t.Errorf("server.py reads the environment %d times; it must read only the one opt-in variable", n)
	}
	for _, banned := range []string{"environ.items", "environ)", "getenv", "subprocess", "os.system", "eval(", "exec(", "pickle", "socket.gethostname", "getpass"} {
		if strings.Contains(src, banned) {
			t.Errorf("server.py contains %q", banned)
		}
	}
}

// TestFixtureNoticeOnEveryFile: the application files say, in their first
// lines and in neutral words, that they are for local testing only; every
// other file of the fixture says it is a deliberately vulnerable fixture.
func TestFixtureNoticeOnEveryFile(t *testing.T) {
	for _, rel := range fixtureFiles(t) {
		head := strings.ToLower(firstLines(string(readFixture(t, rel)), 12))
		if strings.HasPrefix(rel, "app/") {
			if !strings.Contains(head, "local testing only") {
				t.Errorf("%s: no \"local testing only\" notice in the first lines", rel)
			}
			continue
		}
		if !strings.Contains(head, "deliberately vulnerable") {
			t.Errorf("%s: no \"deliberately vulnerable\" notice in the first lines", rel)
		}
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

// TestFixtureHasNoPackageManifest: nothing under testdata/secassess is a
// project manifest or lockfile a dependency scanner or Dependabot would treat
// as a real project, and no generated or binary file is committed.
func TestFixtureHasNoPackageManifest(t *testing.T) {
	banned := regexp.MustCompile(`(?i)^(requirements.*\.txt|package(-lock)?\.json|yarn\.lock|pnpm-lock\.yaml|pyproject\.toml|setup\.(py|cfg)|pipfile(\.lock)?|poetry\.lock|go\.(mod|sum)|cargo\.(toml|lock)|gemfile(\.lock)?|composer\.(json|lock)|pom\.xml|build\.gradle.*|dockerfile.*|docker-compose.*|.*\.csproj|\.python-version|tox\.ini|environment\.yml|constraints\.txt)$`)
	for _, rel := range fixtureFiles(t) {
		base := rel[strings.LastIndex(rel, "/")+1:]
		if banned.MatchString(base) {
			t.Errorf("%s is a package manifest or lockfile", rel)
		}
		if strings.Contains(rel, "__pycache__") || strings.HasSuffix(rel, ".pyc") || strings.HasSuffix(rel, ".db") || strings.HasSuffix(rel, ".sqlite") {
			t.Errorf("%s is a generated or binary file", rel)
		}
	}
}

// TestFixtureTruthNeverInApp: the answer key is not under app/, so the
// directory copied into a run holds none of it.
func TestFixtureTruthNeverInApp(t *testing.T) {
	for _, rel := range fixtureFiles(t) {
		if !strings.HasPrefix(rel, "app/") {
			continue
		}
		lower := strings.ToLower(rel)
		if strings.Contains(lower, "truth") || strings.Contains(lower, "manifest") || strings.Contains(lower, "probes") || strings.Contains(lower, "golden") {
			t.Errorf("%s looks like answer-key material inside app/", rel)
		}
	}
	m := loadManifest(t)
	src := string(appFile(t, "server.py"))
	for _, f := range m.Flaws {
		if strings.Contains(src, f.ID+" ") || strings.Contains(src, f.Class) {
			t.Errorf("server.py names flaw %s or its class %q", f.ID, f.Class)
		}
	}
}
