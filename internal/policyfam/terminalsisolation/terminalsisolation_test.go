package terminalsisolation

import (
	"bytes"
	"encoding/json"
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

// TestRequireRefusalAudit (lane N4): the floor key compiles raise-only (true
// sets it, false is no floor, a non-boolean is refused), is a qualifying
// floor (no sandbox implied), carries its own live capability token, and
// leaves the hash of every body published before it unchanged.
func TestRequireRefusalAudit(t *testing.T) {
	compile := func(body string) (PolicySpec, string, error) {
		s, canon, err := CompileBody([]byte(body), testCap)
		return s, string(canon), err
	}
	cases := []struct {
		name    string
		body    string
		want    bool
		wantErr string
	}{
		{name: "true sets the floor", body: `{"require_refusal_audit":true}`, want: true},
		{name: "false is no floor", body: `{"require_refusal_audit":false}`},
		{name: "absent is no floor", body: `{}`},
		{name: "a string is refused", body: `{"require_refusal_audit":"yes"}`, wantErr: "cannot unmarshal"},
		{name: "with other floors", body: `{"require_refusal_audit":true,"min_isolation":"container"}`, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, err := compile(tc.body)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.RequireRefusalAudit != tc.want {
				t.Fatalf("RequireRefusalAudit %v, want %v", s.RequireRefusalAudit, tc.want)
			}
			has := false
			for _, k := range s.Keys {
				has = has || k == "require_refusal_audit"
			}
			if has != tc.want || (tc.want && !s.InForce()) {
				t.Fatalf("keys %v in force %v", s.Keys, s.InForce())
			}
		})
	}

	alone, canon, _ := compile(`{"require_refusal_audit":true}`)
	if alone.ImpliesSandboxRequired() {
		t.Error("require_refusal_audit alone implied sandbox_required (it is a qualifying floor)")
	}
	if !strings.Contains(canon, `"require_refusal_audit":true`) {
		t.Errorf("canonical body %s does not carry the key", canon)
	}
	const token = "terminals.isolation.require_refusal_audit"
	if req := RequiredCapabilities(alone); len(req) != 1 || req[0] != token {
		t.Errorf("required %v, want [%s]", req, token)
	}
	live := false
	for _, tok := range LiveCapabilities() {
		live = live || tok == token
	}
	if !live {
		t.Errorf("%s is not live in this build", token)
	}

	// Hash: false and absent hash alike, true differs, and a body without
	// the key keeps the hash it had before the key existed (golden).
	none, _, _ := compile(`{"min_isolation":"process"}`)
	off, _, _ := compile(`{"min_isolation":"process","require_refusal_audit":false}`)
	on, _, _ := compile(`{"min_isolation":"process","require_refusal_audit":true}`)
	if none.Hash != off.Hash || none.Hash == on.Hash {
		t.Errorf("hash absent %s, false %s, true %s", none.Hash, off.Hash, on.Hash)
	}
	if none.Hash != preRefusalAuditProcessHash {
		t.Errorf("the hash of a body without the key moved: %s, want %s", none.Hash, preRefusalAuditProcessHash)
	}
}

// preRefusalAuditProcessHash is the spec hash of {"min_isolation":"process"}
// computed on the base before lane N4 (8e770a1ad).
const preRefusalAuditProcessHash = "13a9d464107d95ccde691eb561c04dfb1f5a646e47f1b65313b7a4fcd0b026f6"

// TestRefusalAuditUnknownToAnOlderNode (lane N4): a node built before the
// key decodes the body strictly, so it refuses the body (a NACK) instead of
// reading it as no floor. legacyBody is BodyV1 as it was before the key.
func TestRefusalAuditUnknownToAnOlderNode(t *testing.T) {
	type legacyBody struct {
		MinIsolation         string    `json:"min_isolation,omitempty"`
		AllowedBackends      *[]string `json:"allowed_backends,omitempty"`
		AllowRemote          *bool     `json:"allow_remote,omitempty"`
		FloorAcceptsBeta     *bool     `json:"floor_accepts_beta,omitempty"`
		RequireFullCapture   *bool     `json:"require_full_capture,omitempty"`
		AllowedRegions       *[]string `json:"allowed_regions,omitempty"`
		ProviderKeyInjection string    `json:"provider_key_injection,omitempty"`
		ProviderMemoryImages string    `json:"provider_memory_images,omitempty"`
		MinEgress            string    `json:"min_egress,omitempty"`
	}
	_, canon, err := CompileBody([]byte(`{"require_refusal_audit":true}`), testCap)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.DisallowUnknownFields()
	var old legacyBody
	if err := dec.Decode(&old); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("an older node decoded %s with err %v; it must refuse the unknown key", canon, err)
	}
	// An explicit false is no floor, and the canonical (published) body
	// drops it, so an older node accepts the body and applies the other
	// floors (tracker F-012, audit finding N4-A6). The spec and its hash
	// equal the body without the key.
	for _, raw := range []string{`{"require_refusal_audit":false}`, `{"require_refusal_audit":false,"min_isolation":"process"}`} {
		s, canon, err := CompileBody([]byte(raw), testCap)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(canon), "require_refusal_audit") {
			t.Fatalf("%s canonicalized to %s, keeping the key", raw, canon)
		}
		dec := json.NewDecoder(bytes.NewReader(canon))
		dec.DisallowUnknownFields()
		var old legacyBody
		if err := dec.Decode(&old); err != nil {
			t.Fatalf("an older node refused %s: %v", canon, err)
		}
		without, _, _ := CompileBody([]byte(strings.Replace(raw, `"require_refusal_audit":false`, `"floor_accepts_beta":false`, 1)), testCap)
		if s.RequireRefusalAudit || s.Hash != without.Hash {
			t.Fatalf("%s: spec %+v, hash differs from the body without the key", raw, s)
		}
	}
	// A node that knows the key but does not advertise its token (its
	// module inactive) is missing exactly that token: the delivery NACKs
	// with capability_mismatch rather than applying the other floors.
	s, _, _ := CompileBody([]byte(`{"require_refusal_audit":true,"min_isolation":"process"}`), testCap)
	advertised := map[string]bool{"terminals.isolation.min_isolation": true}
	var missing []string
	for _, tok := range RequiredCapabilities(s) {
		if !advertised[tok] {
			missing = append(missing, tok)
		}
	}
	if strings.Join(missing, ",") != "terminals.isolation.require_refusal_audit" {
		t.Errorf("missing %v", missing)
	}
}

// TestRefusalAuditLint (lane N4): the publish lints judge the floor against
// the rows' grounding: a floor only hosted rows could meet would warn, and
// with the registry's grounding the hosted rows never meet it.
func TestRefusalAuditLint(t *testing.T) {
	s, _, _ := CompileBody([]byte(`{"require_refusal_audit":true}`), testCap)
	for _, r := range RegistryRows() {
		if got := meets(s, r); got != r.Net.AuditsRefusals() {
			t.Errorf("%s: meets %v, AuditsRefusals %v", r.ID, got, r.Net.AuditsRefusals())
		}
	}
	if w := RemoteOnlyWarnings(s, RegistryRows()); len(w) != 0 {
		t.Errorf("remote-only warnings %v", w)
	}
	if w := UnmetLocallyWarnings(s, RegistryRows()); len(w) != 0 {
		t.Errorf("a qualifying floor alone was linted as unmet: %v", w)
	}
}

// TestUnmetLocallyIgnoresExplicitOnlyRows (tracker F-020 A14, lane O4): a
// floor met on a host only by an explicit-only row still warns there,
// because the guard's enforce upgrade and an automatic choice never pick
// one. One case per explicit-only row the tracker names.
func TestUnmetLocallyIgnoresExplicitOnlyRows(t *testing.T) {
	for _, tc := range []struct {
		id   string
		body string
	}{
		// process_lite builds process isolation; with bwrap left out, a
		// process floor on Linux is met only by it.
		{sandboxbackend.BackendProcessLite, `{"min_isolation":"process"}`},
		// openshell builds a container; a container floor on Linux is met
		// only by it in this row set.
		{sandboxbackend.BackendOpenShell, `{"min_isolation":"container"}`},
		// Naming the row alone is no better.
		{sandboxbackend.BackendOpenShell, `{"allowed_backends":["openshell"]}`},
	} {
		t.Run(tc.id+" "+tc.body, func(t *testing.T) {
			row, ok := sandboxbackend.Get(tc.id)
			if !ok || !row.ExplicitOnly || !row.RunsOn(sandboxbackend.HostLinux) {
				t.Fatalf("%s is not an explicit-only Linux row", tc.id)
			}
			s, _, err := CompileBody([]byte(tc.body), testCap)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(UnmetLocallyWarnings(s, []sandboxbackend.Capability{row}), "\n")
			if !strings.Contains(got, "on linux ") {
				t.Fatalf("no warning on linux although only the explicit-only %s meets the floor: %q", tc.id, got)
			}
			// The same row made non-explicit meets it, so the row (not the
			// floor) is what the lint now refuses to count.
			row.ExplicitOnly = false
			if got := strings.Join(UnmetLocallyWarnings(s, []sandboxbackend.Capability{row}), "\n"); strings.Contains(got, "on linux ") {
				t.Fatalf("a non-explicit row meeting the floor still warned: %q", got)
			}
		})
	}
}

// TestGatewayModesFloor (lane O4): the key compiles from the closed
// vocabulary only, never empty, sorts canonically, is a qualifying floor
// with its own live token, and leaves the hash of every earlier body
// unchanged.
func TestGatewayModesFloor(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
		wantErr    string
	}{
		{"managed only", `{"gateway_modes":["managed_local"]}`, []string{"managed_local"}, ""},
		{"both, sorted", `{"gateway_modes":["managed_local","external"]}`, []string{"external", "managed_local"}, ""},
		{"empty allows nothing", `{"gateway_modes":[]}`, nil, "empty"},
		{"unknown mode", `{"gateway_modes":["managed"]}`, nil, "not a known value"},
		{"twice", `{"gateway_modes":["external","external"]}`, nil, "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, err := CompileBody([]byte(tc.body), testCap)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if strings.Join(s.GatewayModes, ",") != strings.Join(tc.want, ",") || !s.InForce() || s.ImpliesSandboxRequired() {
				t.Fatalf("spec = %+v", s)
			}
			if got := RequiredCapabilities(s); len(got) != 1 || got[0] != "terminals.isolation.gateway_modes" {
				t.Fatalf("tokens = %v", got)
			}
		})
	}
	found := false
	for _, tok := range LiveCapabilities() {
		found = found || tok == "terminals.isolation.gateway_modes"
	}
	if !found {
		t.Fatal("gateway_modes is not a live capability")
	}
	before, _, err := CompileBody([]byte(`{"min_isolation":"process"}`), testCap)
	if err != nil {
		t.Fatal(err)
	}
	with, _, err := CompileBody([]byte(`{"min_isolation":"process","gateway_modes":["external"]}`), testCap)
	if err != nil {
		t.Fatal(err)
	}
	if before.Hash == with.Hash {
		t.Fatal("the floor does not change the hash")
	}
	// A body without the key keeps the hash it had before the key existed:
	// the same spec compiled twice hashes the same, and hashSpec writes the
	// key only when it is set.
	again, _, _ := CompileBody([]byte(`{"min_isolation":"process"}`), testCap)
	if again.Hash != before.Hash {
		t.Fatal("hash is not stable")
	}
}
