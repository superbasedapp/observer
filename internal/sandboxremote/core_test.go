package sandboxremote

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

func TestPlanManifestScope(t *testing.T) {
	cands := []Candidate{
		{Path: "main.go", Kind: KindRegular, Size: 10},
		{Path: "../escape", Kind: KindRegular, Size: 1},
		{Path: "/etc/passwd", Kind: KindRegular, Size: 1},
		{Path: ".git/config", Kind: KindRegular, Size: 1},
		{Path: "link", Kind: KindSymlink},
		{Path: "dir", Kind: KindDir},
		{Path: ".env.local", Kind: KindRegular, Size: 3},
		{Path: "deploy/server.pem", Kind: KindRegular, Size: 3},
		{Path: "keys/id_ed25519", Kind: KindRegular, Size: 3},
		{Path: "pkg/id_test.go", Kind: KindRegular, Size: 3},
		{Path: ".aws/credentials", Kind: KindRegular, Size: 3},
		{Path: "big.bin", Kind: KindRegular, Size: 100},
		{Path: "main.go", Kind: KindRegular, Size: 10},
	}
	m, err := PlanManifest(ManifestInput{
		Root: "/home/u/proj", Home: "/home/u", Repository: true, Candidates: cands,
		Limits: ManifestLimits{MaxFiles: 10, MaxBytes: 1000, MaxFileBytes: 50},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range m.Files {
		got = append(got, f.Path)
	}
	if strings.Join(got, ",") != "main.go,pkg/id_test.go" {
		t.Errorf("files = %v", got)
	}
	want := map[string]string{
		"../escape": ExcludeOutsideRoot, "/etc/passwd": ExcludeOutsideRoot, ".git/config": ExcludeGitDir,
		"link": ExcludeSymlink, "dir": ExcludeNotRegular, ".env.local": ExcludeCredentialShape,
		"deploy/server.pem": ExcludeCredentialShape, "keys/id_ed25519": ExcludeCredentialShape,
		".aws/credentials": ExcludeCredentialShape, "big.bin": ExcludeTooLarge,
	}
	for _, e := range m.Excluded {
		if want[e.Path] != e.Reason {
			t.Errorf("%s excluded as %s, want %s", e.Path, e.Reason, want[e.Path])
		}
		delete(want, e.Path)
	}
	if len(want) != 0 {
		t.Errorf("not excluded: %v", want)
	}
	if m.Count != 2 || m.Bytes != 13 {
		t.Errorf("count %d bytes %d", m.Count, m.Bytes)
	}
}

func TestPlanManifestRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   ManifestInput
		want error
	}{
		{"home", ManifestInput{Root: "/home/u", Home: "/home/u", Repository: true}, ErrScopeHome},
		{"above home", ManifestInput{Root: "/home", Home: "/home/u", Repository: true}, ErrScopeHome},
		{"root", ManifestInput{Root: "/", Home: "/home/u", Repository: true}, ErrScopeRoot},
		{"relative", ManifestInput{Root: "proj", Home: "/home/u", Repository: true}, ErrScopeRoot},
		{"not repo", ManifestInput{Root: "/home/u/p", Home: "/home/u"}, ErrScopeNotRepository},
		{"too many", ManifestInput{
			Root: "/home/u/p", Home: "/home/u", Repository: true, Limits: ManifestLimits{MaxFiles: 1, MaxBytes: 100, MaxFileBytes: 100},
			Candidates: []Candidate{{Path: "a", Kind: KindRegular}, {Path: "b", Kind: KindRegular}},
		}, ErrScopeTooLarge},
	}
	for _, c := range cases {
		if _, err := PlanManifest(c.in); !errors.Is(err, c.want) {
			t.Errorf("%s: err %v, want %v", c.name, err, c.want)
		}
	}
}

// TestCredentialShaped pins the credential-shape rule row by row: every name
// starting with .env (audit finding 4), the identity-file rule (id_* with no
// extension or .pub, never a source file), and the rest.
func TestCredentialShaped(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{".env", true},
		{".env.local", true},
		{".envrc", true},
		{".env-prod", true},
		{".env_local", true},
		{"sub/.ENVRC", true},
		{"app/.env.production", true},
		{"env.go", false},
		{"docs/environment.md", false},
		{"x.env", false},
		{"keys/id_ed25519", true},
		{"id_rsa.pub", true},
		{"pkg/id_test.go", false},
		{"deploy/server.pem", true},
		{".aws/config", true},
		{".netrc", true},
		{"main.go", false},
	}
	for _, c := range cases {
		if got := CredentialShaped(c.path); got != c.want {
			t.Errorf("CredentialShaped(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestScopeKeyBindsRootNotContent(t *testing.T) {
	a, _ := PlanManifest(ManifestInput{Root: "/w/p", Home: "/h", Repository: true, Candidates: []Candidate{{Path: "x", Kind: KindRegular}}})
	b, _ := PlanManifest(ManifestInput{Root: "/w/p", Home: "/h", Repository: true, Candidates: []Candidate{{Path: "y", Kind: KindRegular, Size: 9}}})
	c, _ := PlanManifest(ManifestInput{Root: "/w/q", Home: "/h", Repository: true})
	if a.ScopeKey != b.ScopeKey || a.ScopeKey == c.ScopeKey {
		t.Errorf("scope keys %s %s %s", a.ScopeKey, b.ScopeKey, c.ScopeKey)
	}
}

func baseFacts() ConsentFacts {
	return ConsentFacts{
		Provider: VendorE2B, Endpoint: "https://api.e2b.app", Region: "us-west-1", Custody: "in_box_api_key",
		Tier: "proxy_only", Capture: "full", ScopeKey: "k", BoxBinary: "observer 1.0 (running binary)", MemoryImages: "avoid",
		MaxRunMinutes: 60, DailyBoxMinutes: 240,
	}
}

func TestConsentInvalidation(t *testing.T) {
	rec := NewConsent(baseFacts(), "2026-10-22T00:00:00Z")
	if v := CheckConsent(&rec, baseFacts()); v != ConsentOK {
		t.Fatalf("unchanged: %s", v)
	}
	if v := CheckConsent(nil, baseFacts()); v != ConsentMissing {
		t.Errorf("nil: %s", v)
	}
	changes := map[string]func(*ConsentFacts){
		"custody": func(f *ConsentFacts) { f.Custody = "in_box_oauth_seed" },
		"region":  func(f *ConsentFacts) { f.Region = "eu-west-1" },
		"scope":   func(f *ConsentFacts) { f.ScopeKey = "other" },
		"cap":     func(f *ConsentFacts) { f.MaxRunMinutes = 30 },
		"tier":    func(f *ConsentFacts) { f.Tier = "internet" },
	}
	for name, mut := range changes {
		f := baseFacts()
		mut(&f)
		if v := CheckConsent(&rec, f); v != ConsentChangedPrefix+name {
			t.Errorf("%s: %s", name, v)
		}
	}
	tampered := rec
	tampered.Facts.Region = "eu-west-1"
	if v := CheckConsent(&tampered, tampered.Facts); v != ConsentTampered {
		t.Errorf("tampered: %s", v)
	}
	if _, err := DecodeConsent([]byte(`{"version":1,"extra":1}`)); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestConsentScreenNamesWhatLeaves(t *testing.T) {
	v, _ := VendorFor(VendorE2B)
	m := Manifest{Root: "/w/p", Count: 3, Bytes: 2048, Excluded: []Exclusion{{".env", ExcludeCredentialShape}}}
	s := BuildConsentScreen(v, baseFacts(), m, v.EstimateCost(60))
	text := fmt.Sprint(s.Lines)
	for _, want := range []string{"E2B's machines", "us-west-1", "3 files", "readable by the agent", "proxy_only", "60 minutes", "estimate", "observer 1.0"} {
		if !strings.Contains(text, want) {
			t.Errorf("screen lacks %q: %s", want, text)
		}
	}
	if len(s.Excluded) != 1 {
		t.Error("excluded files not listed")
	}
}

func TestPlanTimeoutAndLedger(t *testing.T) {
	cases := []struct {
		maxRun, daily, used, want int
		refused                   bool
	}{
		{60, 240, 0, 60, false},
		{60, 240, 200, 40, false},
		{60, 240, 238, 0, true},
		{60, 240, 300, 0, true},
		{3, 240, 0, 0, true},
	}
	for _, c := range cases {
		got, err := PlanTimeout(c.maxRun, c.daily, c.used)
		if (err != nil) != c.refused || got != c.want {
			t.Errorf("%+v: got %d %v", c, got, err)
		}
		if err != nil && !strings.Contains(err.Error(), VerdictDailyCapReached) {
			t.Errorf("refusal does not name the cap: %v", err)
		}
	}
	var l Ledger
	day := DayOf(time.Date(2026, 10, 22, 23, 0, 0, 0, time.UTC))
	l.Reserve(VendorE2B, day, "r1", 60)
	l.Reserve(VendorE2B, day, "r2", 60)
	l.Reserve(VendorModal, day, "r3", 30)
	if l.Used(VendorE2B, day) != 120 {
		t.Errorf("used %d", l.Used(VendorE2B, day))
	}
	l.Settle("r1", 90*time.Second)
	if l.Used(VendorE2B, day) != 62 {
		t.Errorf("after settle %d", l.Used(VendorE2B, day))
	}
	l.Settle("r2", 5*time.Hour)
	if l.Used(VendorE2B, day) != 62 {
		t.Errorf("a settle never raises above the reservation: %d", l.Used(VendorE2B, day))
	}
	l.Prune(time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC), 7)
	if len(l.Entries) != 0 {
		t.Errorf("prune kept %v", l.Entries)
	}
}

func TestTeardownTable(t *testing.T) {
	cases := []struct {
		from State
		ev   Event
		to   State
		ok   bool
	}{
		{StateIntent, EvCreateOK, StateCreated, true},
		{StateIntent, EvCreateLost, StateCreateLost, true},
		{StateIntent, EvCreateFailed, StateGone, true},
		{StateIntent, EvDeleteConfirm, StateIntent, false},
		{StateCreateLost, EvFoundByLabel, StateCreated, true},
		{StateCreateLost, EvNotFound, StateGone, true},
		{StateCreateLost, EvStarted, StateCreateLost, false},
		{StateCreated, EvStarted, StateRunning, true},
		{StateRunning, EvPullBegin, StatePulling, true},
		{StatePulling, EvPullFailed, StatePulling, true},
		{StatePulling, EvDeleteSent, StateDeleting, true},
		{StateDeleting, EvDeleteFailed, StateCreated, true},
		{StateDeleting, EvDeleteConfirm, StateGone, true},
		{StateRunning, EvDeleteConfirm, StateRunning, false},
		{StateGone, EvCreateOK, StateGone, false},
	}
	for _, c := range cases {
		got, err := Next(c.from, c.ev)
		if (err == nil) != c.ok || got != c.to {
			t.Errorf("%s + %s = %s %v", c.from, c.ev, got, err)
		}
	}
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	r := NewIntent("run1", VendorE2B, "https://api.e2b.app", "us-west-1", "run1", now, time.Hour)
	if r.Removable() {
		t.Error("an intent is not removable")
	}
	for _, ev := range []Event{EvCreateOK, EvStarted, EvPullBegin, EvDeleteSent} {
		if err := r.Apply(ev); err != nil {
			t.Fatal(err)
		}
	}
	if r.Removable() {
		t.Error("removable before the vendor confirmed")
	}
	_ = r.Apply(EvDeleteConfirm)
	if !r.Removable() {
		t.Error("not removable after confirmation")
	}
}

func TestLeftovers(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	lost := NewIntent("a", VendorModal, "", "", "a", now.Add(-2*time.Hour), time.Hour)
	lost.State = StateCreateLost
	run := NewIntent("b", VendorE2B, "", "", "b", now.Add(-10*time.Minute), time.Hour)
	run.VendorID, run.State = "sbx1", StateRunning
	live := NewIntent("c", VendorE2B, "", "", "c", now, time.Hour)
	gone := NewIntent("d", VendorE2B, "", "", "d", now, time.Hour)
	gone.State = StateGone
	out := Leftovers([]Record{run, lost, live, gone}, map[string]bool{"c": true}, now)
	if len(out) != 2 || out[0].RunID != "a" || out[1].RunID != "b" {
		t.Fatalf("leftovers %+v", out)
	}
	if out[0].Action != "find_and_delete" || out[0].ExpiresInSeconds != 0 || out[0].AgeSeconds != 7200 {
		t.Errorf("lost create row %+v", out[0])
	}
	if !out[1].Adoptable || out[1].Action != "delete" {
		t.Errorf("e2b running row %+v", out[1])
	}
}

func TestCredentialBindingAndRedaction(t *testing.T) {
	v, _ := VendorFor(VendorE2B)
	env := map[string]string{"E2B_API_KEY": "e2b_FAKEKEY_1234567890"}
	c, ok := CredentialFromEnv(v, func(k string) (string, bool) { s, ok := env[k]; return s, ok })
	if !ok {
		t.Fatal("env credential not built")
	}
	if err := CheckBinding(c, v, "https://api.e2b.app/"); err != nil {
		t.Errorf("default endpoint refused: %v", err)
	}
	if err := CheckBinding(c, v, "https://api.region-b.example"); !errors.Is(err, ErrCredentialEndpointMismatch) {
		t.Errorf("env credential sent to another endpoint: %v", err)
	}
	stored := Credential{Provider: VendorE2B, Fields: env, Endpoint: "https://api.region-b.example", Source: SourceKeystore}
	if err := CheckBinding(stored, v, "https://api.region-b.example"); err != nil {
		t.Errorf("stored credential refused at its own endpoint: %v", err)
	}
	if err := CheckBinding(stored, v, "https://attacker.example"); !errors.Is(err, ErrCredentialEndpointMismatch) {
		t.Errorf("stored credential sent elsewhere: %v", err)
	}
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v %+v %#v %s %q", c, c, c, c, c), CheckBinding(c, v, "x").Error()} {
		if strings.Contains(s, "FAKEKEY") {
			t.Errorf("credential value printed: %s", s)
		}
	}
	if got := Redact("401: key e2b_FAKEKEY_1234567890 rejected", c.Secrets()); strings.Contains(got, "FAKEKEY") {
		t.Errorf("redact: %s", got)
	}
	b, _ := EncodeStored(stored)
	back, err := DecodeStored(VendorE2B, b)
	if err != nil || back.Endpoint != stored.Endpoint || back.Get("E2B_API_KEY") != env["E2B_API_KEY"] {
		t.Errorf("round trip: %v %v", back, err)
	}
	if _, err := DecodeStored(VendorModal, b); err == nil || strings.Contains(err.Error(), "FAKEKEY") {
		t.Errorf("wrong provider: %v", err)
	}
	mv, _ := VendorFor(VendorModal)
	if _, ok := CredentialFromEnv(mv, func(k string) (string, bool) { return "x", k == "MODAL_TOKEN_ID" }); ok {
		t.Error("a half-set Modal credential counted")
	}
}

func TestPlanPull(t *testing.T) {
	roots := []string{"/home/user/.claude", "/home/user/.codex"}
	listed := []BoxFile{
		{"/home/user/.claude/projects/p/s.jsonl", 10, true},
		{"/home/user/.claude/link.jsonl", 10, false},
		{"/home/user/.claude/../.ssh/id_rsa", 10, true},
		{"/etc/shadow.json", 10, true},
		{"/home/user/.codex/sessions/a.jsonl", 10, true},
		{"/home/user/.codex/bin/codex", 10, true},
		{"/home/user/.codex/huge.jsonl", 1 << 40, true},
	}
	items, skipped := PlanPull(roots, listed, PullLimits{})
	if len(items) != 2 || items[0].LocalRel != "0/projects/p/s.jsonl" || items[1].LocalRel != "1/sessions/a.jsonl" {
		t.Errorf("items %+v", items)
	}
	if len(skipped) != 5 {
		t.Errorf("skipped %+v", skipped)
	}
	if RekeyID("run1", "sess") != "rsbx-run1-sess" || RekeyID("r", "") != "" {
		t.Error("rekey")
	}
}

func TestVendorTable(t *testing.T) {
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		if v.ID != id || v.Name == "" || v.DefaultEndpoint == "" || v.KeystoreService == "" || len(v.EnvCredential) == 0 {
			t.Errorf("%s: incomplete row", id)
		}
		if _, ok := v.Tiers[vocab.TierHost]; ok {
			t.Errorf("%s: a remote vendor offers the host tier", id)
		}
		for tier, m := range v.Tiers {
			if tier == vocab.TierNone && m.Relay {
				t.Errorf("%s: the none tier carries the model proxy", id)
			}
		}
		if len(v.Docs) == 0 || v.Price.Date == "" || v.Price.Source == "" || v.MinLifetimeMinutes() == 0 {
			t.Errorf("%s: endpoint docs, dated price or lifetime missing", id)
		}
		r, ep, ok := v.ResolveRegion("")
		if !ok || r == "" || ep == "" {
			t.Errorf("%s: default region %q %q", id, r, ep)
		}
		if _, _, ok := v.ResolveRegion("mars-1"); ok {
			t.Errorf("%s: unknown region accepted", id)
		}
	}
	e2b, _ := VendorFor(VendorE2B)
	if _, ep, ok := e2b.ResolveRegion("us-west-1"); !ok || ep != "https://api.e2b.app" {
		t.Errorf("e2b default endpoint %s %v", ep, ok)
	}
	for _, r := range []string{"us-west-2", "eu-west-1", "ap-southeast-1"} {
		if _, ep, ok := e2b.ResolveRegion(r); ok {
			t.Errorf("e2b region %s (%s) is accepted with no E2B doc grounding it", r, ep)
		}
	}
	modal, _ := VendorFor(VendorModal)
	if r, _, _ := modal.ResolveRegion(""); r != ProviderChosen {
		t.Errorf("modal default region %s", r)
	}
}

// registrableDomain is the last two labels of a host (every vendor domain in
// the table is a plain second-level domain under a one-label suffix).
func registrableDomain(host string) string {
	labels := strings.Split(strings.ToLower(host), ".")
	if len(labels) < 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// underVendor reports whether an https URL's host is under one of the
// vendor's own registrable domains.
func underVendor(v Vendor, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return false
	}
	return slices.Contains(v.Domains, registrableDomain(u.Hostname()))
}

// TestVendorRegionsGrounded (SBX-P7 merge, audit finding 1): every region in
// every vendor table carries a doc URL, and the endpoint it resolves to (the
// one a stored credential is sent to) is under the vendor's own registrable
// domain, as is the doc.
func TestVendorRegionsGrounded(t *testing.T) {
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		if len(v.Domains) == 0 {
			t.Errorf("%s: no vendor domains", id)
			continue
		}
		if !underVendor(v, v.DefaultEndpoint) {
			t.Errorf("%s: default endpoint %s is not under %v", id, v.DefaultEndpoint, v.Domains)
		}
		if len(v.Regions.Known) == 0 {
			t.Errorf("%s: no regions", id)
		}
		for _, r := range v.Regions.Known {
			doc := v.Regions.Docs[r]
			if doc == "" || !underVendor(v, doc) {
				t.Errorf("%s: region %s has no doc URL under %v (%q)", id, r, v.Domains, doc)
			}
			_, ep, ok := v.ResolveRegion(r)
			if !ok || !underVendor(v, ep) {
				t.Errorf("%s: region %s resolves to %q, not under %v", id, r, ep, v.Domains)
			}
		}
		for r := range v.Regions.Endpoints {
			if !slices.Contains(v.Regions.Known, r) {
				t.Errorf("%s: endpoint for unlisted region %s", id, r)
			}
		}
		for r := range v.Regions.Docs {
			if !slices.Contains(v.Regions.Known, r) {
				t.Errorf("%s: doc for unlisted region %s", id, r)
			}
		}
	}
}

// TestConsentScreenListsTheFiles (live run 2026-10-23, finding F11): the
// screen names the files sent, capped with a count of the rest, and says
// the box time is an upper bound.
func TestConsentScreenListsTheFiles(t *testing.T) {
	v, _ := VendorFor(VendorModal)
	m := Manifest{Root: "/w/p"}
	for i := 0; i < ConsentFileList+7; i++ {
		m.Files = append(m.Files, ManifestFile{Path: fmt.Sprintf("f%03d.go", i)})
	}
	m.Count = len(m.Files)
	s := BuildConsentScreen(v, baseFacts(), m, v.EstimateCost(60))
	if len(s.Uploaded) != ConsentFileList || s.Uploaded[0] != "f000.go" || s.UploadedMore != 7 {
		t.Errorf("uploaded %d (first %v), more %d", len(s.Uploaded), s.Uploaded[:1], s.UploadedMore)
	}
	small := BuildConsentScreen(v, baseFacts(), Manifest{Root: "/w/p", Files: []ManifestFile{{Path: "README.md"}}, Count: 1}, v.EstimateCost(60))
	if len(small.Uploaded) != 1 || small.Uploaded[0] != "README.md" || small.UploadedMore != 0 {
		t.Errorf("small %+v", small.Uploaded)
	}
	if text := fmt.Sprint(s.Lines); !strings.Contains(text, "at most 60 minutes") {
		t.Errorf("the spend line does not say at most: %s", text)
	}
}

// TestKeepDiffError: a run's diff error is kept once (a second removal
// replaces it), a run without one adds nothing, and at most
// MaxKeptDiffErrors lines are kept, the oldest dropped.
func TestKeepDiffError(t *testing.T) {
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	rec := Record{RunID: "r1", Provider: "e2b", DiffError: "no git"}
	lines := KeepDiffError(nil, rec, now)
	lines = KeepDiffError(lines, rec, now.Add(time.Minute))
	if len(lines) != 1 || !lines[0].At.Equal(now.Add(time.Minute)) {
		t.Fatalf("kept %+v", lines)
	}
	if got := KeepDiffError(lines, Record{RunID: "r2"}, now); len(got) != 1 {
		t.Fatalf("a run with no diff error added a line: %+v", got)
	}
	for i := 0; i < MaxKeptDiffErrors+5; i++ {
		lines = KeepDiffError(lines, Record{RunID: fmt.Sprintf("x%d", i), DiffError: "e"}, now)
	}
	if len(lines) != MaxKeptDiffErrors || lines[len(lines)-1].RunID != fmt.Sprintf("x%d", MaxKeptDiffErrors+4) {
		t.Fatalf("cap: %d lines, last %+v", len(lines), lines[len(lines)-1])
	}
}
