package terminalsisolation

import (
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

const testCap = 1 << 16

// tokenGrammar is orgcontract.NormalizeCapabilities' grammar, restated so a
// token that the signing step would refuse fails here first.
var tokenGrammar = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)

func TestCompileBody(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
		check   func(t *testing.T, s PolicySpec)
	}{
		{
			name: "every enforceable floor", body: `{"min_isolation":"container","allowed_backends":["oci-runc","bwrap"],"allow_remote":false,"floor_accepts_beta":true,"require_full_capture":true,"allowed_regions":["eu-west-1"],"provider_key_injection":"forbidden","min_egress":"proxy_only"}`,
			check: func(t *testing.T, s PolicySpec) {
				if s.MinIsolation != vocab.ClassContainer || s.MinEgress != vocab.TierProxyOnly || !s.ForbidRemote || !s.RequireFullCapture {
					t.Fatalf("spec %+v", s)
				}
				if strings.Join(s.AllowedBackends, ",") != "bwrap,oci-runc" {
					t.Fatalf("backends %v", s.AllowedBackends)
				}
				if !s.ImpliesSandboxRequired() || len(s.Keys) != 8 {
					t.Fatalf("keys %v", s.Keys)
				}
			},
		},
		{name: "an empty body sets no floor", body: `{}`, check: func(t *testing.T, s PolicySpec) {
			if s.InForce() || s.ImpliesSandboxRequired() {
				t.Fatalf("floors in force: %v", s.Keys)
			}
		}},
		{name: "qualifiers alone never force a sandbox", body: `{"require_full_capture":true,"floor_accepts_beta":true}`, check: func(t *testing.T, s PolicySpec) {
			if s.ImpliesSandboxRequired() {
				t.Fatal("require_full_capture implied sandbox_required")
			}
		}},
		{name: "an unknown key is refused, never ignored", body: `{"min_isolation":"process","sandbox_required":true}`, wantErr: "unknown field"},
		{name: "min_egress none is refused", body: `{"min_egress":"none"}`, wantErr: "cannot be none"},
		{name: "min_egress outside the vocabulary", body: `{"min_egress":"lan"}`, wantErr: "not one of"},
		{name: "min_isolation none is refused", body: `{"min_isolation":"none"}`, wantErr: "not one of"},
		{name: "allow_remote true widens and is refused", body: `{"allow_remote":true}`, wantErr: "only be false"},
		{name: "an empty allow-list is refused", body: `{"allowed_backends":[]}`, wantErr: "allow nothing"},
		{name: "an unknown backend is refused", body: `{"allowed_backends":["docker-desktop"]}`, wantErr: "not a known value"},
		{name: "provider floors take forbidden only", body: `{"provider_key_injection":"allowed"}`, wantErr: "may only be"},
		{name: "trailing bytes", body: `{} {}`, wantErr: "trailing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, canon, err := CompileBody([]byte(tc.body), testCap)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(canon) == 0 || s.Hash == "" {
				t.Fatal("no canonical body or hash")
			}
			tc.check(t, s)
		})
	}
}

// TestCanonicalIsOrderInsensitive: the signed body never depends on list
// order or whitespace.
func TestCanonicalIsOrderInsensitive(t *testing.T) {
	_, a, _ := CompileBody([]byte(`{"allowed_backends":["oci-runc","bwrap"]}`), testCap)
	_, b, _ := CompileBody([]byte(` { "allowed_backends" : ["bwrap","oci-runc"] } `), testCap)
	if string(a) != string(b) {
		t.Fatalf("%s != %s", a, b)
	}
}

// TestCapabilityTokens: one required token per floor key present, and the
// live set lacks exactly the floors this build cannot enforce, so a body
// naming one NACKs (capability_mismatch) instead of being ignored.
func TestCapabilityTokens(t *testing.T) {
	s, _, err := CompileBody([]byte(`{"min_isolation":"process","provider_memory_images":"forbidden"}`), testCap)
	if err != nil {
		t.Fatal(err)
	}
	req := RequiredCapabilities(s)
	if len(req) != 2 {
		t.Fatalf("required %v", req)
	}
	live := map[string]bool{}
	for _, tok := range LiveCapabilities() {
		live[tok] = true
	}
	for _, k := range FloorKeys {
		if live[k.Token] != k.Enforced {
			t.Errorf("%s: live %v, enforced %v", k.Key, live[k.Token], k.Enforced)
		}
		if !strings.HasPrefix(k.Token, tokenPrefix) || !tokenGrammar.MatchString(k.Token) {
			t.Errorf("%s: token %q (must fit the envelope's capability grammar)", k.Key, k.Token)
		}
	}
	if live["terminals.isolation.provider_memory_images"] {
		t.Fatal("provider_memory_images is live before any hosted row exists")
	}
}

// TestRemoteOnlyWarnings: a floor that only remote rows can meet on a host
// OS is linted, naming the OS (a fake remote row stands in; no remote row is
// offered yet).
func TestRemoteOnlyWarnings(t *testing.T) {
	bwrap, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	remote := sandboxbackend.Capability{
		ID: "fake-remote", Maturity: sandboxbackend.MaturityPlanned,
		Iso: sandboxbackend.Isolation{Class: vocab.ClassHWVM, Location: vocab.LocationRemote, Hosts: []sandboxbackend.HostKind{sandboxbackend.HostRemote}},
	}
	localVM := sandboxbackend.Capability{
		ID: "fake-linux-vm", Maturity: sandboxbackend.MaturityPlanned,
		Iso: sandboxbackend.Isolation{Class: vocab.ClassHWVM, Location: vocab.LocationLocal, Hosts: []sandboxbackend.HostKind{sandboxbackend.HostLinux}},
	}
	rows := []sandboxbackend.Capability{bwrap, remote, localVM}
	spec := func(body string) PolicySpec {
		s, _, err := CompileBody([]byte(body), testCap)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	got := RemoteOnlyWarnings(spec(`{"min_isolation":"hw_vm"}`), rows)
	joined := strings.Join(got, "\n")
	for _, os := range []string{"wsl2", "macos", "windows"} {
		if !strings.Contains(joined, "on "+os+" ") {
			t.Errorf("no warning naming %s: %v", os, got)
		}
	}
	if strings.Contains(joined, "on linux ") {
		t.Errorf("linux has a local VM row but was warned: %v", got)
	}
	if w := RemoteOnlyWarnings(spec(`{"min_isolation":"hw_vm","allow_remote":false}`), rows); len(w) != 0 {
		t.Errorf("with remote forbidden nothing is remote-only: %v", w)
	}
	if w := RemoteOnlyWarnings(spec(`{"min_isolation":"process"}`), rows); len(w) == 0 || strings.Contains(strings.Join(w, ""), "linux") {
		t.Errorf("process floor: %v (macOS and Windows have only the remote row in this fake set)", w)
	}
}

// updatePicker regenerates web2/src/lib/sandboxBackends.gen.ts from the
// registry: go test ./internal/policyfam/terminalsisolation -run
// TestAdminBackendPickerMatchesRegistry -update-picker
var updatePicker = flag.Bool("update-picker", false, "regenerate the web2 backend picker list from the sandbox backend registry")

// pickerPath is the generated web2 floors form list.
var pickerPath = filepath.Join("..", "..", "..", "web2", "src", "lib", "sandboxBackends.gen.ts")

// pickerSource renders the web2 picker list from the registry: every
// registry id in id order with the registry's own label. A new registry row
// needs no edit in this test or in the web2 source, only the regeneration.
func pickerSource() string {
	var b strings.Builder
	b.WriteString("// GENERATED from internal/sandboxbackend by TestAdminBackendPickerMatchesRegistry. DO NOT EDIT.\n")
	b.WriteString("// Regenerate with: go test ./internal/policyfam/terminalsisolation -run TestAdminBackendPickerMatchesRegistry -update-picker\n")
	b.WriteString("//\n// The closed backend id vocabulary the floors form offers: exactly the\n")
	b.WriteString("// registry ids the compiler accepts. The picker follows the registry.\n\n")
	b.WriteString("export const SANDBOX_BACKENDS: { id: string; label: string }[] = [\n")
	for _, id := range sandboxbackend.IDs() {
		c, _ := sandboxbackend.Get(id)
		label := c.Label
		if label == "" {
			label = id
		}
		b.WriteString("  { id: " + strconv.Quote(id) + ", label: " + strconv.Quote(label) + " },\n")
	}
	b.WriteString("];\n")
	return b.String()
}

// TestAdminBackendPickerMatchesRegistry: the web2 floors form picks backends
// from a list generated from the registry (web2/src/lib/sandboxBackends.gen.ts,
// re-exported by isolationFloors.ts); it must name exactly the registry ids
// the compiler accepts, with the registry's labels. The expected text derives
// from the registry, so a new row is one regeneration, never a hand edit.
func TestAdminBackendPickerMatchesRegistry(t *testing.T) {
	publictree.Skip(t, "web2/src/lib/sandboxBackends.gen.ts")
	want := pickerSource()
	if *updatePicker {
		if err := os.WriteFile(pickerPath, []byte(want), 0o644); err != nil {
			t.Fatalf("write the picker list: %v", err)
		}
	}
	src, err := os.ReadFile(pickerPath)
	if err != nil {
		t.Fatalf("read the form list: %v", err)
	}
	if string(src) != want {
		t.Fatalf("web2/src/lib/sandboxBackends.gen.ts is out of step with the sandbox backend registry; regenerate with -update-picker\n got:\n%s\nwant:\n%s", src, want)
	}
	var got []string
	for _, m := range regexp.MustCompile(`id: "([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		got = append(got, m[1])
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(sandboxbackend.IDs(), ",") {
		t.Fatalf("form backends %v, registry %v", got, sandboxbackend.IDs())
	}
	floors, err := os.ReadFile(filepath.Join("..", "..", "..", "web2", "src", "lib", "isolationFloors.ts"))
	if err != nil {
		t.Fatalf("read isolationFloors.ts: %v", err)
	}
	if !strings.Contains(string(floors), `export { SANDBOX_BACKENDS } from "./sandboxBackends.gen.ts";`) {
		t.Fatal("isolationFloors.ts must re-export the generated SANDBOX_BACKENDS, not keep a hand list")
	}
}

// TestUnmetLocallyWarnings (SBX-P2E, plan 11.5): each OS is checked
// against the rows this release offers (planned rows left out), and the
// warning names the floor no offered row meets there.
func TestUnmetLocallyWarnings(t *testing.T) {
	bwrap, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	plannedMacVM := sandboxbackend.Capability{
		ID: "fake-mac-vm", Maturity: sandboxbackend.MaturityPlanned,
		Iso: sandboxbackend.Isolation{Class: vocab.ClassHWVM, Location: vocab.LocationLocal, Hosts: []sandboxbackend.HostKind{sandboxbackend.HostMacOS}},
	}
	rows := []sandboxbackend.Capability{bwrap, plannedMacVM}
	spec := func(body string) PolicySpec {
		s, _, err := CompileBody([]byte(body), testCap)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	cases := []struct {
		name     string
		body     string
		warnOn   []string
		quietOn  []string
		mentions string
	}{
		{"process floor: only bwrap's hosts are met", `{"min_isolation":"process"}`, []string{"macos", "windows"}, []string{"linux", "wsl2"}, `"Minimum isolation" (min_isolation)`},
		{"vm floor: met nowhere (the mac VM row is only planned)", `{"min_isolation":"hw_vm"}`, []string{"linux", "wsl2", "macos", "windows"}, nil, `"Minimum isolation"`},
		{"backend pin naming bwrap", `{"allowed_backends":["bwrap"]}`, []string{"macos", "windows"}, []string{"linux", "wsl2"}, `"Allowed sandbox backends" (allowed_backends)`},
		{"a qualifying floor alone implies no sandbox", `{"require_full_capture":true}`, nil, []string{"linux", "wsl2", "macos", "windows"}, ""},
	}
	for _, tc := range cases {
		got := strings.Join(UnmetLocallyWarnings(spec(tc.body), rows), "\n")
		for _, os := range tc.warnOn {
			if !strings.Contains(got, "on "+os+" ") {
				t.Errorf("%s: no warning for %s: %q", tc.name, os, got)
			}
		}
		for _, os := range tc.quietOn {
			if strings.Contains(got, "on "+os+" ") {
				t.Errorf("%s: %s warned: %q", tc.name, os, got)
			}
		}
		if tc.mentions != "" && !strings.Contains(got, tc.mentions) {
			t.Errorf("%s: the warning does not name %s: %q", tc.name, tc.mentions, got)
		}
	}
	// Two floors each met alone on Linux but not together name both.
	both := spec(`{"min_isolation":"hw_vm","allowed_backends":["bwrap"]}`)
	if got := strings.Join(UnmetLocallyWarnings(both, rows), "\n"); !strings.Contains(got, "the floor \"Minimum isolation\"") {
		t.Errorf("the floor no row meets on linux is not named alone: %q", got)
	}
}
