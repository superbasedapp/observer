package seciac

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// TestPackageImports_Bounded pins seciac pure (lane GATES-SEC).
func TestPackageImports_Bounded(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"database/sql", "net", "net/http", "os", "os/exec", "syscall", "github.com/fsnotify/fsnotify"},
		Reason:    "seciac is pure: the cmd layer reads the files, manifests and certificates and runs nothing itself",
	})
}

func hexd(c byte) string { return strings.Repeat(string(c), 64) }

// pinned is a test pin table with the linux amd64 row pinned (archive and
// binary, test digests), every other row owed (independent of the
// compiled table's real digests).
func pinned() []Pin {
	pins := CompiledPins(Trivy)
	for i := range pins {
		if pins[i].OS == "linux" && pins[i].Arch == "amd64" {
			pins[i].Status, pins[i].AssetSHA256, pins[i].BinarySHA256 = PinPinned, hexd('a'), hexd('b')
		} else {
			pins[i].Status, pins[i].AssetSHA256, pins[i].BinarySHA256 = PinOwed, "", ""
		}
	}
	return pins
}

// TestDecideRows walks the decision table, one case per row (and the
// tenancy split of each unverified row).
func TestDecideRows(t *testing.T) {
	t.Parallel()
	base := Input{Engine: Trivy, GOOS: "linux", GOARCH: "amd64", Digest: hexd('b'), Compiled: pinned(), Tree: secengine.TreeNone}
	cases := []struct {
		name   string
		mod    func(*Input)
		status Status
		detail string
	}{
		{"pinned", func(*Input) {}, StatusVerified, DetailCompiled},
		{"pinned tested version", func(in *Input) { in.Version = "0.75.0" }, StatusVerified, DetailCompiled},
		{"revoked", func(in *Input) { in.Revoked = []string{hexd('b')} }, StatusRefused, DetailRevoked},
		{"below the minimum", func(in *Input) { in.Version = "0.74.9" }, StatusRefused, DetailTooOld},
		{"queries tree changed, individual", func(in *Input) { in.Tree = secengine.TreeChanged }, StatusUnverifiedLabelled, DetailTreeChanged},
		{"queries tree changed, managed", func(in *Input) { in.Tree, in.Managed = secengine.TreeChanged, true }, StatusRefused, DetailTreeChanged},
		{"queries tree unreadable", func(in *Input) { in.Tree = secengine.TreeUnreadable }, StatusUnverifiedLabelled, DetailTreeUnreadable},
		{"engine record unreadable", func(in *Input) { in.Tree = secengine.TreeRecordUnreadable }, StatusUnverifiedLabelled, DetailRecordUnreadable},
		{"pin owed, individual refused by default", func(in *Input) { in.GOOS, in.GOARCH = "windows", "amd64" }, StatusRefused, DetailUnpinnedNotAllowed},
		{"pin owed, individual allow_unpinned labelled", func(in *Input) { in.GOOS, in.GOARCH, in.AllowUnpinned = "windows", "amd64", true }, StatusUnverifiedLabelled, DetailPinOwed},
		{"pin owed, managed refused", func(in *Input) { in.GOOS, in.GOARCH, in.Managed = "windows", "amd64", true }, StatusRefused, DetailPinOwed},
		{"pin owed, managed refused whatever allow_unpinned says", func(in *Input) {
			in.GOOS, in.GOARCH, in.Managed, in.AllowUnpinned = "windows", "amd64", true, true
		}, StatusRefused, DetailPinOwed},
		{"digest mismatch, individual refused by default", func(in *Input) { in.Digest = hexd('c') }, StatusRefused, DetailUnpinnedNotAllowed},
		{"digest mismatch, individual allow_unpinned labelled", func(in *Input) { in.Digest, in.AllowUnpinned = hexd('c'), true }, StatusUnverifiedLabelled, DetailNoMatch},
		{"digest mismatch, managed refuses an unverified engine", func(in *Input) { in.Digest, in.Managed = hexd('c'), true }, StatusRefused, DetailNoMatch},
		{"changed since first use, refused by default", func(in *Input) { in.Digest, in.FirstUse = hexd('c'), hexd('d') }, StatusRefused, DetailUnpinnedNotAllowed},
		{"changed since first use, allow_unpinned labelled", func(in *Input) {
			in.Digest, in.FirstUse, in.AllowUnpinned = hexd('c'), hexd('d'), true
		}, StatusUnverifiedLabelled, DetailChangedSinceFirstUse},
	}
	for _, c := range cases {
		in := base
		c.mod(&in)
		got := Decide(in)
		if got.Status != c.status || got.Detail != c.detail {
			t.Errorf("%s: got %s (%s), want %s (%s)", c.name, got.Status, got.Detail, c.status, c.detail)
		}
	}
	// An untested version above the minimum runs, labelled.
	in := base
	in.Version = "0.76.1"
	if d := Decide(in); d.Status != StatusVerified || !d.Untested {
		t.Errorf("untested version: %+v", d)
	}
	if len(RuleNames()) != len(rules) || len(rules) != 9 {
		t.Errorf("the table has %d rows; a new row needs a case above", len(rules))
	}
}

// TestDecideGuidedInstallRecord: the binary the guided install extracted
// from a verified archive counts while that archive's pin is in force, and
// not once the archive is revoked.
func TestDecideGuidedInstallRecord(t *testing.T) {
	t.Parallel()
	m := &ManifestPins{Pins: []Pin{{Engine: Trivy, Version: "0.75.0", OS: "linux", Arch: "amd64", AssetSHA256: hexd('e'), Status: PinPinned, Source: "manifest"}}}
	rec := &InstallRecord{ArchiveSHA256: hexd('e'), BinarySHA256: hexd('f'), Version: "0.75.0", Verified: true}
	in := Input{Engine: Trivy, GOOS: "linux", GOARCH: "amd64", Digest: hexd('f'), Manifest: m, Installed: rec}
	if d := Decide(in); d.Status != StatusVerified || d.Detail != DetailInstalled {
		t.Fatalf("installed binary: %+v", d)
	}
	unverifiedRec := *rec
	unverifiedRec.Verified = false
	in.Installed = &unverifiedRec
	if d := Decide(in); d.Status == StatusVerified {
		t.Fatal("a record whose MAC did not verify vouched for the binary")
	}
	in.Installed = rec
	m.Revoked = []string{hexd('e')}
	if d := Decide(in); d.Status != StatusRefused || d.Detail != DetailRevoked {
		t.Fatalf("a revoked archive's binary: %+v", d)
	}
}

func engineManifest(entries ...content.Entry) content.Manifest {
	return content.Manifest{Kind: content.Engine, ManifestVersion: 3, Entries: entries}
}

// TestManifestEntriesSkipEachOther: a shared security.engine manifest
// holds an opengrep entry and a trivy entry; seciac reads only its own and
// secengine only its own.
func TestManifestEntriesSkipEachOther(t *testing.T) {
	t.Parallel()
	tr, _ := Lookup(Trivy)
	trivyEntry := content.Entry{
		Name: "trivy_0.75.0_Linux-64bit.tar.gz", Version: "0.75.0", OS: "linux", Arch: "amd64", SizeBytes: 50, SHA256: hexd('a'),
		Upstream: content.UpstreamCheck{Method: content.UpstreamCosignKeylessOnline, Identity: tr.Identity("0.75.0"), Issuer: tr.Issuer},
	}
	ogEntry := content.Entry{
		Name: "opengrep_manylinux_x86", Version: secengine.TestedVersion, OS: "linux", Arch: "amd64", SizeBytes: 50, SHA256: hexd('c'),
		Upstream: content.UpstreamCheck{Method: content.UpstreamCosignKeylessOnline, Identity: secengine.Identity(secengine.TestedVersion), Issuer: secengine.Issuer},
	}
	m := engineManifest(trivyEntry, ogEntry)
	got, err := FromManifest(m, Trivy)
	if err != nil || len(got.Pins) != 1 || got.Pins[0].AssetSHA256 != hexd('a') || got.Pins[0].Format != ArchiveTarGz {
		t.Fatalf("seciac read %+v %v", got, err)
	}
	og, err := secengine.FromManifest(m)
	if err != nil || len(og.Pins) != 1 || og.Pins[0].SHA256 != hexd('c') {
		t.Fatalf("secengine read %+v %v", og, err)
	}
	if k, err := FromManifest(m, KICS); err != nil || len(k.Pins) != 0 {
		t.Fatalf("kics read %+v %v", k, err)
	}
	// A trivy entry not verified under Trivy's identity is refused.
	bad := trivyEntry
	bad.Upstream.Identity = "https://github.com/someone/else/.github/workflows/x.yml@refs/tags/v0.75.0"
	if _, err := FromManifest(engineManifest(bad), Trivy); err == nil {
		t.Fatal("an entry verified under another identity was accepted")
	}
	sums := trivyEntry
	sums.Upstream = content.UpstreamCheck{Method: content.UpstreamSHA256Sums}
	if _, err := FromManifest(engineManifest(sums), Trivy); err == nil {
		t.Fatal("a digest-only trivy entry was accepted (Trivy is pinned AND signature-verified)")
	}
	// A KICS entry rides the release checksum file, digest-only.
	kics := content.Entry{Name: "kics_2.2.0_linux_x64.tar.gz", Version: "2.2.0", OS: "linux", Arch: "amd64", SizeBytes: 5, SHA256: hexd('9'), Upstream: content.UpstreamCheck{Method: content.UpstreamSHA256Sums}}
	if k, err := FromManifest(engineManifest(kics), KICS); err != nil || len(k.Pins) != 1 || !k.Pins[0].DigestOnly {
		t.Fatalf("kics entry %+v %v", k, err)
	}
}

// TestPinTables: tested equals minimum, never latest; every row owed in
// this lane (no asset was fetched and compared); asset names are the
// goreleaser names at the tag.
func TestPinTables(t *testing.T) {
	t.Parallel()
	for _, e := range Engines() {
		if e.TestedVersion != e.MinVersion || strings.Contains(strings.ToLower(e.TestedVersion), "latest") || secengine.ParseVersion(e.TestedVersion) == nil {
			t.Errorf("%s: tested %q min %q", e.ID, e.TestedVersion, e.MinVersion)
		}
	}
	pins := CompiledPins(Trivy)
	if len(pins) != 5 {
		t.Fatalf("trivy pins %d", len(pins))
	}
	want := map[string]string{
		"linux/amd64": "trivy_0.75.0_Linux-64bit.tar.gz", "linux/arm64": "trivy_0.75.0_Linux-ARM64.tar.gz",
		"darwin/arm64": "trivy_0.75.0_macOS-ARM64.tar.gz", "darwin/amd64": "trivy_0.75.0_macOS-64bit.tar.gz",
		"windows/amd64": "trivy_0.75.0_windows-64bit.zip",
	}
	// The digests recorded on 2026-10-25 (lane LEFT2-SEC item R-018): the
	// archive matched the release's trivy_0.75.0_checksums.txt and its
	// sigstore bundle passed PrecheckBundle; the binary is the extracted
	// executable. A changed row must come with a fresh fetch and check.
	digests := map[string][2]string{
		"linux/amd64":   {"c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f", "93f9da8e4ba5e0c1c76d8234ed2494cf9afb0a96fd21953e424bb795f3299b8e"},
		"linux/arm64":   {"a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3", "869e310e208f0f2e3e90e4f842cc6adaa2b2c046fecbaade481e6b23fcc8f2a9"},
		"darwin/arm64":  {"4a77108cccf8e55c8d6823e1e759939a622277e66cd0daa3c1fc621ed69e4568", "32b84c068e11e5381fc85d3fe2e8ac238659ab22524ce1b2b9dfcbd0b1f7331a"},
		"darwin/amd64":  {"291edaa9778acbe4693d067b5ad60ee11570e5ac68296e85595417528ca641e4", "484287e06ab2e4038c42ba396da8637aaaca0967e3e65840563706a0284169b4"},
		"windows/amd64": {"4e43bd71a30f51aee39525f60f2b47043af77eb8df8fe082aae4372b69c6660f", "3b4fcf6fec53c4c73c325cfd518c7264100695b19e6c59c6a777e4a67dc9f0e6"},
	}
	for _, p := range pins {
		d := digests[p.OS+"/"+p.Arch]
		if p.Status != PinPinned || p.AssetSHA256 != d[0] || p.BinarySHA256 != d[1] || p.DigestOnly || p.Source != "compiled" {
			t.Errorf("%s/%s is not the recorded pin: %+v", p.OS, p.Arch, p)
		}
		if want[p.OS+"/"+p.Arch] != p.Asset {
			t.Errorf("%s/%s asset %q", p.OS, p.Arch, p.Asset)
		}
	}
	if p := pins[0]; p.URL() != "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz" || p.BundleURL() != p.URL()+".sigstore.json" {
		t.Errorf("urls %s %s", p.URL(), p.BundleURL())
	}
	// KICS v2.2.0 publishes no release binaries: its rows only name the
	// archive an org mirror publishes, owed, digest-only, never a URL.
	kp := CompiledPins(KICS)
	if len(kp) != 5 {
		t.Fatalf("kics mirror rows %d", len(kp))
	}
	wantKICS := map[string]string{
		"linux/amd64": "kics_2.2.0_linux_amd64.tar.gz", "linux/arm64": "kics_2.2.0_linux_arm64.tar.gz",
		"darwin/arm64": "kics_2.2.0_darwin_arm64.tar.gz", "darwin/amd64": "kics_2.2.0_darwin_amd64.tar.gz",
		"windows/amd64": "kics_2.2.0_windows_amd64.zip",
	}
	for _, p := range kp {
		if p.Status != PinOwed || p.AssetSHA256 != "" || p.BinarySHA256 != "" || !p.DigestOnly || p.Source != SourceOrgMirrorRow || p.URL() != "" || p.BundleURL() != "" {
			t.Errorf("kics %s/%s is not an owed mirror row: %+v", p.OS, p.Arch, p)
		}
		if wantKICS[p.OS+"/"+p.Arch] != p.Asset || formatOf(p.Asset) != p.Format {
			t.Errorf("kics %s/%s asset %q format %q", p.OS, p.Arch, p.Asset, p.Format)
		}
	}
	tr, _ := Lookup(Trivy)
	if tr.Identity("0.75.0") != "https://github.com/aquasecurity/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.75.0" {
		t.Errorf("identity %s", tr.Identity("0.75.0"))
	}
}

// TestRequiredFlagsInPinnedHelp: the captured --help of each pinned
// version lists every required flag; a help missing one is refused.
func TestRequiredFlagsInPinnedHelp(t *testing.T) {
	t.Parallel()
	for id, file := range map[EngineID]string{Trivy: "trivy-0.75.0-config-help.txt", KICS: "kics-2.2.0-scan-help.txt"} {
		e, _ := Lookup(id)
		help, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		if miss := MissingFlags(e, help); len(miss) != 0 {
			t.Errorf("%s: the pinned help lacks %v", id, miss)
		}
		cut := strings.ReplaceAll(string(help), e.RequiredFlags[0], "--gone-flag")
		if miss := MissingFlags(e, []byte(cut)); !slices.Contains(miss, e.RequiredFlags[0]) {
			t.Errorf("%s: a help without %s passed", id, e.RequiredFlags[0])
		}
	}
	// KICS v2.2.0 dropped the 1.x --disable-full-descriptions: it is not
	// relied on, and the engine runs only isolated.
	kh, _ := os.ReadFile(filepath.Join("testdata", "kics-2.2.0-scan-help.txt"))
	if strings.Contains(string(kh), "--disable-full-descriptions") {
		t.Error("the fixture says v2.2.0 still has --disable-full-descriptions; revisit RequireIsolation")
	}
	if tr, _ := Lookup(Trivy); !tr.RequireIsolation || tr.IsolationWhy == "" {
		t.Error("Trivy's Terraform scanner fetches remote modules no flag turns off; it must require isolation (audit finding F3)")
	}
	if k, _ := Lookup(KICS); !k.RequireIsolation {
		t.Error("KICS has a network call no flag turns off; it must require isolation")
	}
}

// TestArgsGolden: the fixed argument list per engine, every offline flag
// in it, repository configs off unless allowed.
func TestArgsGolden(t *testing.T) {
	t.Parallel()
	p := RunPaths{Target: "/w/p", Out: "/c/runs/r1", Cache: "/c/engine", Queries: "/c/kics/assets/queries", Libraries: "/c/kics/assets/libraries", EmptyConfig: "/c/runs/r1/empty-config.json"}
	trivy := strings.Join(Args(Trivy, p, false), " ")
	wantTrivy := "config --quiet --format sarif --output /c/runs/r1/trivy.sarif --exit-code 0 --skip-check-update --skip-version-check --disable-telemetry " +
		"--cache-backend memory --cache-dir /c/engine/trivy-cache --module-dir /c/engine/trivy-modules " +
		"--misconfig-scanners cloudformation,dockerfile,helm,kubernetes,terraform --tf-exclude-downloaded-modules --timeout 9m --config  --ignorefile  /w/p"
	if trivy != wantTrivy {
		t.Errorf("trivy argv\n got %s\nwant %s", trivy, wantTrivy)
	}
	kics := strings.Join(Args(KICS, p, false), " ")
	wantKICS := "scan --path /w/p --queries-path /c/kics/assets/queries --libraries-path /c/kics/assets/libraries --output-path /c/runs/r1 --output-name kics " +
		"--report-formats sarif --ignore-on-exit results --no-progress --no-color --silent --disable-secrets --strict-source-resolution " +
		"--type CloudFormation,DockerCompose,Dockerfile,Kubernetes,Terraform --timeout 60 --config /c/runs/r1/empty-config.json"
	if kics != wantKICS {
		t.Errorf("kics argv\n got %s\nwant %s", kics, wantKICS)
	}
	for _, id := range []EngineID{Trivy, KICS} {
		e, _ := Lookup(id)
		args := Args(id, p, false)
		for _, f := range e.RequiredFlags {
			if !slices.Contains(args, f) {
				t.Errorf("%s argv lacks required %s", id, f)
			}
		}
		for _, f := range e.NeverFlags {
			if slices.Contains(args, f) {
				t.Errorf("%s argv passes never-flag %s", id, f)
			}
		}
	}
	allowed := Args(Trivy, p, true)
	if slices.Contains(allowed, "--ignorefile") || slices.Contains(allowed, "--config") {
		t.Error("an allowed repository config is still switched off")
	}
	if !slices.Contains(allowed, "--skip-check-update") {
		t.Error("allowing repository configs dropped an offline flag")
	}
}

// TestSeverityTableRows: one case per row, through the secscan adapter
// the driver uses.
func TestSeverityTableRows(t *testing.T) {
	t.Parallel()
	for i, r := range SeverityTable {
		props := ""
		if r.SecuritySeverity != "" {
			props = `,"properties":{"security-severity":"` + r.SecuritySeverity + `"}`
		}
		resLevel := ""
		if r.Engine == Trivy {
			// Trivy writes the level on each result too; KICS only on the rule.
			resLevel = `"level":"` + r.Level + `",`
		}
		doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","rules":[{"id":"R-1","defaultConfiguration":{"level":"` + r.Level + `"}` + props + `}]}},` +
			`"results":[{"ruleId":"R-1",` + resLevel + `"locations":[{"physicalLocation":{"artifactLocation":{"uri":"Dockerfile"},"region":{"startLine":2}}}],"message":{"text":"m"}}]}]}`
		res, why := ReadSARIF(r.Engine, []byte(doc), secscan.Target{ProjectRoot: "/w/p", Scope: policy.FindingScopeManual}, "/w/p", secscan.EngineIdentity{Name: string(r.Engine)}, true, nil)
		if why != "" || len(res.Findings) != 1 {
			t.Fatalf("row %d: %s %+v", i, why, res)
		}
		if got := res.Findings[0].Severity; got != r.Want {
			t.Errorf("row %d (%s %s %s): got %s, want %s", i, r.Engine, r.SecuritySeverity, r.Level, got, r.Want)
		}
	}
}

// TestRealSARIFFixtures: the pinned versions' own SARIF maps onto iac
// findings with lineage-ready locations, every one at a file and a line.
func TestRealSARIFFixtures(t *testing.T) {
	t.Parallel()
	for id, file := range map[EngineID]string{Trivy: "trivy-0.75.0-config.sarif", KICS: "kics-2.2.0-scan.sarif"} {
		b, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		res, why := ReadSARIF(id, b, secscan.Target{ProjectRoot: "/work/project", Scope: policy.FindingScopeManual}, "/work/project", secscan.EngineIdentity{Name: string(id)}, true, func(string) string { return "h" })
		if why != "" || len(res.Findings) < 20 {
			t.Fatalf("%s: %s, %d findings", id, why, len(res.Findings))
		}
		paths := map[string]bool{}
		for _, f := range res.Findings {
			if f.Category != policy.FindingIaC || f.Location.RelPath == "" || f.Location.StartLine < 1 || f.Confidence == policy.FindingConfidenceHigh {
				t.Errorf("%s: %+v", id, f)
			}
			if f.Engine.Driver != string(id) || f.Rule.Pack != string(id) || strings.Contains(f.Message, "public-read") {
				t.Errorf("%s: engine text or driver leaked: %+v", id, f)
			}
			paths[f.Location.RelPath] = true
		}
		for _, p := range []string{"Dockerfile", "k8s/pod.yaml", "infra/main.tf"} {
			if !paths[p] {
				t.Errorf("%s: no finding at %s", id, p)
			}
		}
		if !CanaryHit(b) {
			t.Errorf("%s: the fixture's Dockerfile results do not satisfy the canary check", id)
		}
	}
}

// TestMapFindingsLocationRule: a result with no file is dropped and
// counted; a lone dropped result leaves the run unknown, never clean.
func TestMapFindingsLocationRule(t *testing.T) {
	t.Parallel()
	fs := []secfinding.Finding{{Rule: secfinding.Rule{ID: "a"}}, {Rule: secfinding.Rule{ID: "b"}, Location: secfinding.Location{RelPath: "Dockerfile"}, Confidence: policy.FindingConfidenceHigh}}
	kept, cov := MapFindings(fs, secscan.Coverage{Outcome: secscan.OutcomeFindings})
	if len(kept) != 1 || kept[0].Location.StartLine != 1 || kept[0].Confidence != policy.FindingConfidenceMedium || len(cov.Skipped) != 1 || cov.Skipped[0].Reason != SkipNoLocation {
		t.Fatalf("%+v %+v", kept, cov)
	}
	kept, cov = MapFindings(fs[:1], secscan.Coverage{Outcome: secscan.OutcomeFindings})
	if len(kept) != 0 || cov.Outcome != secscan.OutcomeUnknown {
		t.Fatalf("lone unlocated: %+v %+v", kept, cov)
	}
}

// TestPathClasses: one case per class, and a non-IaC write queues nothing.
func TestPathClasses(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Dockerfile": "dockerfile", "svc/Dockerfile.prod": "dockerfile", "Containerfile": "dockerfile",
		"infra/main.tf": "terraform", "vars.tfvars": "terraform", "x.tf.json": "terraform",
		"charts/app/Chart.yaml": "helm", "charts/app/templates/dep.yaml": "helm", "values.yaml": "helm",
		"stack.template": "cloudformation", "app.cfn.yaml": "cloudformation",
		"k8s/pod.yaml": "kubernetes", "deploy/svc.yml": "kubernetes",
		"main.go": "", "README.md": "", ".github/workflows/ci.yml": "", "config.yaml": "",
	}
	for p, want := range cases {
		if got := ClassOf(p); got != want {
			t.Errorf("%s: got %q, want %q", p, got, want)
		}
	}
	if got := IaCPaths([]string{"main.go", "k8s/pod.yaml", "k8s/pod.yaml", "Dockerfile"}); !slices.Equal(got, []string{"k8s/pod.yaml", "Dockerfile"}) {
		t.Errorf("IaCPaths %v", got)
	}
	tr, _ := Lookup(Trivy)
	if got := RepoConfigPresent(tr, []string{"src", ".trivyignore", "trivy.yaml"}); !slices.Equal(got, []string{".trivyignore", "trivy.yaml"}) {
		t.Errorf("repo configs %v", got)
	}
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: time.Now().Add(-24 * time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// makeBundle signs digest with a ten-minute leaf naming identity, under a
// test root, as a v0.3 sigstore bundle.
func makeBundle(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, identity string, sum [32]byte) []byte {
	t.Helper()
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := url.Parse(identity)
	tr, _ := Lookup(Trivy)
	issuer, _ := asn1.Marshal(tr.Issuer)
	nb := time.Now().Add(-2 * time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: nb, NotAfter: nb.Add(10 * time.Minute),
		URIs: []*url.URL{id}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}, Value: issuer}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := ecdsa.SignASN1(rand.Reader, leafKey, sum[:])
	b, _ := json.Marshal(map[string]any{
		"mediaType":            "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{"certificate": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(der)}},
		"messageSignature": map[string]any{
			"messageDigest": map[string]string{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(sum[:])},
			"signature":     base64.StdEncoding.EncodeToString(sig),
		},
	})
	return b
}

// TestPrecheckBundle: a bundle under the pinned identity pre-checks; a
// tampered asset, another identity or another root does not.
func TestPrecheckBundle(t *testing.T) {
	t.Parallel()
	root, rootKey, rootPEM := testCA(t)
	tr, _ := Lookup(Trivy)
	asset := []byte("a trivy release archive")
	sum := sha256.Sum256(asset)
	digest := hex.EncodeToString(sum[:])
	b := makeBundle(t, root, rootKey, tr.Identity("0.75.0"), sum)
	in := BundleInput{Engine: Trivy, Version: "0.75.0", Digest: digest, Bundle: b, RootPEM: rootPEM}
	if _, err := PrecheckBundle(in); err != nil {
		t.Fatalf("a good bundle: %v", err)
	}
	bad := in
	tampered := sha256.Sum256(append(asset, 'x'))
	bad.Digest = hex.EncodeToString(tampered[:])
	if _, err := PrecheckBundle(bad); err == nil {
		t.Fatal("a tampered asset pre-checked")
	}
	other := in
	other.Bundle = makeBundle(t, root, rootKey, "https://github.com/evil/trivy/.github/workflows/reusable-release.yaml@refs/tags/v0.75.0", sum)
	if _, err := PrecheckBundle(other); err == nil {
		t.Fatal("another identity pre-checked")
	}
	_, _, otherRoot := testCA(t)
	wrongRoot := in
	wrongRoot.RootPEM = otherRoot
	if _, err := PrecheckBundle(wrongRoot); err == nil {
		t.Fatal("a leaf from another root pre-checked")
	}
	if _, err := PrecheckBundle(BundleInput{Engine: KICS, Digest: digest, Bundle: b}); err == nil {
		t.Fatal("KICS publishes no bundle, yet one pre-checked")
	}
}

// TestPlanInstallRows: one case per blocked row, and an unblocked plan
// that states its size before the consent.
func TestPlanInstallRows(t *testing.T) {
	t.Parallel()
	base := InstallInput{Engine: Trivy, GOOS: "linux", GOARCH: "amd64", Compiled: pinned()}
	cases := []struct {
		name string
		mod  func(*InstallInput)
		want string
	}{
		{"kics publishes no release binaries", func(in *InstallInput) { in.Engine = KICS }, BlockNoVendorRelease},
		{"managed without the mirror", func(in *InstallInput) { in.Managed = true }, BlockManagedNoMirror},
		{"source not allowed", func(in *InstallInput) {
			in.SourceAllowed = func(s InstallSource) bool { return s == SourceOrgMirror }
		}, BlockSourceNotAllowed},
		{"pin owed", func(in *InstallInput) { in.GOOS = "windows" }, BlockPinOwed},
		{"managed takes no compiled pin", func(in *InstallInput) { in.Managed, in.MirrorNamed = true, true }, BlockPinOwed},
		{"managed kics without a mirror entry", func(in *InstallInput) { in.Engine, in.Managed, in.MirrorNamed, in.Compiled = KICS, true, true, nil }, BlockPinOwed},
		{"revoked", func(in *InstallInput) { in.Revoked = []string{hexd('a')} }, BlockRevoked},
		{"unblocked", func(*InstallInput) {}, ""},
	}
	for _, c := range cases {
		in := base
		c.mod(&in)
		if got := PlanInstall(in).Blocked; got != c.want {
			t.Errorf("%s: blocked %q, want %q", c.name, got, c.want)
		}
	}
	p := PlanInstall(base)
	if !p.NeedsConsent || p.DownloadBytes == 0 || p.URL == "" || p.Bundle == "" || p.CapBytes < p.DownloadBytes {
		t.Fatalf("plan %+v", p)
	}
	if !strings.Contains(ConsentText(p), "sigstore") || !strings.Contains(ConsentText(p), p.Pin.AssetSHA256) {
		t.Errorf("consent text %s", ConsentText(p))
	}
	// The managed mirror path: a manifest pin, no URL, no consent.
	m := &ManifestPins{Pins: []Pin{{Engine: Trivy, Version: "0.75.0", OS: "linux", Arch: "amd64", AssetSHA256: hexd('e'), SizeBytes: 10, Status: PinPinned, Source: "manifest"}}}
	mp := PlanInstall(InstallInput{Engine: Trivy, GOOS: "linux", GOARCH: "amd64", Managed: true, MirrorNamed: true, Manifest: m})
	if mp.Blocked != "" || mp.Source != SourceOrgMirror || mp.URL != "" || mp.NeedsConsent || mp.CapBytes != 10 {
		t.Fatalf("mirror plan %+v", mp)
	}
}

// TestConsentCoversOnlyItsPin and TestVerifyArchive.
func TestConsentAndVerify(t *testing.T) {
	t.Parallel()
	p := PlanInstall(InstallInput{Engine: Trivy, GOOS: "linux", GOARCH: "amd64", Compiled: pinned()})
	if _, err := NewInstallConsent(p, "agent", "", time.Now()); err == nil {
		t.Fatal("an agent surface gave the consent")
	}
	c, err := NewInstallConsent(p, "cli", "u", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c.Covers(p) {
		t.Fatal("an unverified record covered the plan")
	}
	c.Verified = true
	if !c.Covers(p) {
		t.Fatal("a verified consent did not cover its pin")
	}
	p2 := p
	p2.Pin.AssetSHA256 = hexd('9')
	if c.Covers(p2) {
		t.Fatal("a consent covered another pin")
	}
	if err := VerifyArchive(p, hexd('a'), 10); err != nil {
		t.Fatalf("a matching archive: %v", err)
	}
	if err := VerifyArchive(p, hexd('9'), 10); err == nil {
		t.Fatal("a mismatched archive passed")
	}
	if err := VerifyArchive(p, hexd('a'), p.CapBytes+1); err == nil {
		t.Fatal("an archive over the cap passed")
	}
	if err := VerifyArchive(p, hexd('a'), 0); err == nil {
		t.Fatal("an empty (half) download passed")
	}
	if err := VerifyBinary(p, hexd('9'), 10); err == nil {
		t.Fatal("a binary that is not the pinned one passed")
	}
	if err := VerifyBinary(p, hexd('b'), 10); err != nil {
		t.Fatalf("the pinned binary: %v", err)
	}
}

// TestQueriesRecord: the KICS tree record takes v2.2.0's size and refuses
// bad paths.
func TestQueriesRecord(t *testing.T) {
	t.Parallel()
	d := map[string]string{}
	for i := 0; i < 15000; i++ {
		d["q/"+strings.Repeat("x", 3)+"/"+string(rune('a'+i%26))+hex.EncodeToString([]byte{byte(i >> 8), byte(i)})+".rego"] = hexd('1')
	}
	if _, ok := NewQueriesRecord(hexd('b'), "2.2.0", d, time.Now()); !ok {
		t.Fatal("a 15000-file tree was not recorded")
	}
	if _, ok := NewQueriesRecord(hexd('b'), "2.2.0", map[string]string{"../x": hexd('1')}, time.Now()); ok {
		t.Fatal("a path escaping the tree was recorded")
	}
	rec, _ := NewQueriesRecord(hexd('b'), "2.2.0", map[string]string{"a.rego": hexd('1')}, time.Now())
	if st, _ := secengine.CheckTree(&rec, hexd('b'), secengine.TreeListing{Files: []string{"a.rego", "b.rego"}}); st != secengine.TreeChanged {
		t.Fatalf("an added query file reads %s", st)
	}
}

// TestRowsPassTheRegistry: both rows pass secscan's registry validation
// and its row contract (process kind, background triggers only).
func TestRowsPassTheRegistry(t *testing.T) {
	t.Parallel()
	var ds []secscan.Driver
	for _, id := range []EngineID{Trivy, KICS} {
		ds = append(ds, NewDriver(Env{Engine: id}))
		r := Row(id)
		if r.Kind != secscan.KindProcess || r.ComponentID != "security.scan."+string(id) || !slices.Contains(r.Categories, policy.FindingIaC) {
			t.Errorf("%s row %+v", id, r)
		}
		for _, s := range r.Triggers {
			if s == policy.FindingScopePreWrite || s == policy.FindingScopeStaged {
				t.Errorf("%s runs on the hook path (%s)", id, s)
			}
		}
	}
	reg, err := secscan.NewRegistry(ds...)
	if err != nil || len(reg.IDs()) != 2 {
		t.Fatalf("registry %v %v", reg, err)
	}
	if _, err := sarif.Decode([]byte(`{"version":"2.1.0","runs":[]}`)); err != nil {
		t.Fatal(err)
	}
}

// TestDebouncerQueuesOnlyIaCWrites: a write outside the IaC path classes
// queues nothing; an IaC write is due once quiet.
func TestDebouncerQueuesOnlyIaCWrites(t *testing.T) {
	t.Parallel()
	var d Debouncer
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	if d.Add("/p", "main.go", now) || len(d.Due(now.Add(time.Hour))) != 0 {
		t.Fatal("a non-IaC write queued a scan")
	}
	if !d.Add("/p", "infra/main.tf", now) {
		t.Fatal("an IaC write was not queued")
	}
	if got := d.Due(now.Add(time.Second)); len(got) != 0 {
		t.Fatalf("due too early: %v", got)
	}
	if got := d.Due(now.Add(PostWriteQuiet)); !slices.Equal(got, []string{"/p"}) {
		t.Fatalf("due %v", got)
	}
	if got := d.Due(now.Add(2 * PostWriteQuiet)); len(got) != 0 {
		t.Fatalf("handed back twice: %v", got)
	}
}

// TestRecordedPinsDecide (lane LEFT2-SEC item R-018): with the compiled
// table as shipped, the extracted Trivy binary of each platform runs
// verified, the guided install on an individual node is offered for it,
// and KICS still has no vendor install; on a managed node a KICS mirror
// manifest entry for the platform is what the install takes.
func TestRecordedPinsDecide(t *testing.T) {
	t.Parallel()
	for _, p := range CompiledPins(Trivy) {
		d := Decide(Input{Engine: Trivy, GOOS: p.OS, GOARCH: p.Arch, Digest: p.BinarySHA256, Version: "0.75.0", Tree: secengine.TreeNone})
		if d.Status != StatusVerified || d.Detail != DetailCompiled {
			t.Errorf("%s/%s: %s (%s)", p.OS, p.Arch, d.Status, d.Detail)
		}
		plan := PlanInstall(InstallInput{Engine: Trivy, GOOS: p.OS, GOARCH: p.Arch})
		if plan.Blocked != "" || plan.URL != p.URL() || plan.Pin.AssetSHA256 != p.AssetSHA256 {
			t.Errorf("%s/%s install plan %+v", p.OS, p.Arch, plan)
		}
	}
	if d := Decide(Input{Engine: KICS, GOOS: "linux", GOARCH: "amd64", Digest: hexd('c'), Managed: true, Tree: secengine.TreeNone}); d.Status != StatusRefused || d.Detail != DetailPinOwed {
		t.Errorf("a managed KICS without a mirror pin: %s (%s)", d.Status, d.Detail)
	}
	if b := PlanInstall(InstallInput{Engine: KICS, GOOS: "linux", GOARCH: "amd64"}).Blocked; b != BlockNoVendorRelease {
		t.Errorf("an individual KICS install: %q", b)
	}
	e, _ := Lookup(KICS)
	asset, _ := MirrorAsset(e, "linux", "amd64")
	entry := content.Entry{Name: asset, Version: "2.2.0", OS: "linux", Arch: "amd64", SizeBytes: 9, SHA256: hexd('9'), Upstream: content.UpstreamCheck{Method: content.UpstreamSHA256Sums}}
	m, err := FromManifest(engineManifest(entry), KICS)
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanInstall(InstallInput{Engine: KICS, GOOS: "linux", GOARCH: "amd64", Managed: true, MirrorNamed: true, Manifest: &m})
	if plan.Blocked != "" || plan.PinFrom != "manifest" || plan.Source != SourceOrgMirror || plan.Pin.Asset != asset || !plan.Pin.DigestOnly {
		t.Errorf("a managed KICS with a mirror entry: %+v", plan)
	}
}
