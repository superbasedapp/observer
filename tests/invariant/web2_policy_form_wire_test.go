package invariant

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/admission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/egress"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policyfam/planebadmission"
	"github.com/marmutapp/superbased-observer/internal/policyfam/providers"
	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
	"github.com/marmutapp/superbased-observer/internal/routingconfig"
)

// web2_policy_form_wire_test.go is the Go half of the org dashboard's policy
// form round-trip check (audit org-node-control-coverage-2026-11-11,
// CG-7..CG-11, CG-19). Each web2 policy form reads a stored body into its
// draft (*FromWire / *FromBody) and composes the body it publishes
// (*ToWire / *Body). The forms used to drop keys the node honours, because
// nothing tied the form's model to the Go wire type.
//
// The two halves meet at one checked-in fixture per family under
// web2/src/pages/policyforms/testdata/wire/:
//
//   - this test proves each fixture carries EVERY JSON key the family's Go
//     wire type accepts (walked by reflection, so a new wire field fails
//     here until the fixture names it), and that the node and the server
//     accept the fixture (the family's strict decoder and compiler);
//   - web2/src/components/policyFormWire.test.tsx loads each fixture into
//     its form and asserts the form publishes it back unchanged.
//
// A key a form deliberately never authors is listed in the family's exempt
// table with a reason.

const policyFormFixtureDir = "web2/src/pages/policyforms/testdata/wire"

// policyFormFamily is one row: a fixture, the Go wire type every key is
// walked from, the decoder/compiler that must accept the fixture, nested
// json.RawMessage fields resolved to their real type, and exempt key paths.
type policyFormFamily struct {
	fixture string
	wire    reflect.Type
	accept  func(raw []byte) error
	raw     map[string]reflect.Type
	exempt  map[string]string
}

const policyFormFixtureCap = 1 << 20

func policyFormFamilies() []policyFormFamily {
	return []policyFormFamily{
		{
			fixture: "admission.input.json",
			wire:    reflect.TypeOf(admission.BodyV1{}),
			accept: func(raw []byte) error {
				_, _, err := admission.CompileBody(raw, policyFormFixtureCap)
				return err
			},
		},
		{
			fixture: "planeb.admission.json",
			wire:    reflect.TypeOf(planebadmission.Body{}),
			accept: func(raw []byte) error {
				_, _, err := planebadmission.CompileBody(raw, policyFormFixtureCap)
				return err
			},
			raw: map[string]reflect.Type{"admission": reflect.TypeOf(admission.BodyV1{})},
			exempt: map[string]string{
				// The coding-agent prompt judge owns its own scope at the
				// top level; the Plane A conversation scope is hidden.
				"admission.scope": "hidden on the prompt-judge form (planeb.admission has its own top-level scope)",
			},
		},
		{
			fixture: "egress.routing_guardrail.json",
			wire:    reflect.TypeOf(egress.BodyV1{}),
			accept: func(raw []byte) error {
				_, _, err := egress.CompileBody(raw, policyFormFixtureCap)
				return err
			},
		},
		{
			fixture: "gateway.providers.json",
			wire:    reflect.TypeOf(providers.BodyV1{}),
			accept: func(raw []byte) error {
				_, _, err := providers.CompileBody(raw, policyFormFixtureCap)
				return err
			},
		},
		{
			fixture: "security.scanning.json",
			wire:    reflect.TypeOf(securityscanning.Body{}),
			accept: func(raw []byte) error {
				_, _, err := securityscanning.CompileBody(raw, policyFormFixtureCap)
				return err
			},
		},
		{
			fixture: "security.managed.json",
			wire:    reflect.TypeOf(orgcontract.SecurityManagedPolicyV1{}),
			accept: func(raw []byte) error {
				p, ok, err := orgcontract.DecodeSecurityManagedPolicy(raw)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("decoded as empty")
				}
				return orgcontract.ValidateSecurityManagedPolicy(p)
			},
			exempt: map[string]string{
				"custom_catalog":     "server-filled at serve time from the four-eyes catalog; a PUT that authors it is refused",
				"approved_baselines": "server-filled at serve time for the calling node only",
				"org_dedupe":         "server-filled at serve time for the calling node only",
			},
		},
		{
			fixture: "node.governance.json",
			wire:    reflect.TypeOf(nodegov.Body{}),
			accept: func(raw []byte) error {
				_, _, err := nodegov.CompileBody(raw, policyFormFixtureCap)
				return err
			},
		},
	}
}

// TestWeb2PolicyFormFixturesCoverEveryWireKey fails when a family's Go wire
// type gains a JSON key its web2 fixture does not carry, or when a fixture
// is not a body the node and server accept.
func TestWeb2PolicyFormFixturesCoverEveryWireKey(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "web2")
	root := repoRoot(t)
	for _, fam := range policyFormFamilies() {
		t.Run(fam.fixture, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyFormFixtureDir), fam.fixture))
			if err != nil {
				t.Fatalf("read fixture: %v", err)
			}
			// Strict decode: the fixture carries no key the wire type lacks.
			if err := strictDecode(raw, fam.wire); err != nil {
				t.Fatalf("fixture does not strictly decode into %s: %v", fam.wire, err)
			}
			if err := fam.accept(raw); err != nil {
				t.Fatalf("fixture is not a body the family accepts: %v", err)
			}
			want := map[string]bool{}
			wireKeyPaths(fam.wire, "", fam.raw, want)
			var doc any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			have := map[string]bool{}
			presentKeyPaths(doc, fam.wire, "", fam.raw, have)
			var missing []string
			for p := range want {
				if have[p] {
					continue
				}
				if exemptCovers(fam.exempt, p) {
					continue
				}
				missing = append(missing, p)
			}
			sort.Strings(missing)
			if len(missing) > 0 {
				t.Errorf("%s does not carry %d wire key(s) the node accepts: %s\nAdd them to the fixture and make the web2 form keep them (web2/src/components/policyFormWire.test.tsx), or exempt them here with a reason.", fam.fixture, len(missing), strings.Join(missing, ", "))
			}
			for p, why := range fam.exempt {
				if !want[p] {
					t.Errorf("exempt path %q is not a key of %s any more; remove it", p, fam.wire)
				}
				if strings.TrimSpace(why) == "" {
					t.Errorf("exempt path %q carries no reason", p)
				}
			}
		})
	}
}

// TestWeb2PolicyFormFixturesAreRoundTripped pins that the web2 half names
// every fixture this file checks, so a fixture can never be covered on one
// side only.
func TestWeb2PolicyFormFixturesAreRoundTripped(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "web2")
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "web2", "src", "components", "policyFormWire.test.tsx"))
	if err != nil {
		t.Fatalf("read the web2 round-trip test: %v", err)
	}
	for _, fam := range policyFormFamilies() {
		if !bytes.Contains(src, []byte("testdata/wire/"+fam.fixture)) {
			t.Errorf("web2/src/components/policyFormWire.test.tsx does not round-trip %s", fam.fixture)
		}
	}
	if !bytes.Contains(src, []byte("testdata/wire/routing.org-mode.toml")) {
		t.Errorf("web2/src/components/policyFormWire.test.tsx does not pin routing.org-mode.toml")
	}
}

// TestWeb2RoutingModeFixtureIsHonoured is CG-6's Go half: the org routing
// fragment the web2 Routing page composes with a mode (pinned byte-for-byte
// by the web2 test) is parsed by the node to that mode, the value a managed
// node holding enforce.routing honours (cmd/observer/routing_live.go), and
// its soft rules still compose as an org policy.
func TestWeb2RoutingModeFixtureIsHonoured(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "web2")
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyFormFixtureDir), "routing.org-mode.toml"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if got := routingconfig.OrgBodyMode(string(raw)); got != "enforce" {
		t.Fatalf("OrgBodyMode(fixture) = %q, want %q", got, "enforce")
	}
	if _, err := routingconfig.ComposeOrgPolicy(routingconfig.Spec(config.Default().Routing), string(raw)); err != nil {
		t.Fatalf("ComposeOrgPolicy(fixture): %v", err)
	}
}

// exemptCovers reports whether p is an exempt path or lies under one.
func exemptCovers(exempt map[string]string, p string) bool {
	for e := range exempt {
		if p == e || strings.HasPrefix(p, e+".") || strings.HasPrefix(p, e+"[]") {
			return true
		}
	}
	return false
}

// strictDecode decodes raw into a new value of typ, refusing unknown keys.
func strictDecode(raw []byte, typ reflect.Type) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(reflect.New(typ).Interface())
}

var rawMessageType = reflect.TypeOf(json.RawMessage{})

// jsonFields lists a struct's JSON field names and types (exported fields
// with a json tag name; "-" skipped).
func jsonFields(typ reflect.Type) []reflect.StructField {
	var out []reflect.StructField
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !f.IsExported() {
			continue
		}
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		f.Name = name
		out = append(out, f)
	}
	return out
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// wireKeyPaths records every key path a value of typ can carry: struct
// fields by JSON name, map values under ".*", slice elements under "[]".
func wireKeyPaths(typ reflect.Type, prefix string, raw map[string]reflect.Type, out map[string]bool) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == rawMessageType {
		if sub, ok := raw[prefix]; ok {
			wireKeyPaths(sub, prefix, raw, out)
		}
		return
	}
	switch typ.Kind() {
	case reflect.Struct:
		for _, f := range jsonFields(typ) {
			p := joinPath(prefix, f.Name)
			out[p] = true
			wireKeyPaths(f.Type, p, raw, out)
		}
	case reflect.Map:
		wireKeyPaths(typ.Elem(), prefix+".*", raw, out)
	case reflect.Slice, reflect.Array:
		wireKeyPaths(typ.Elem(), prefix+"[]", raw, out)
	}
}

// presentKeyPaths walks a decoded fixture alongside typ and records the key
// paths it actually carries, in wireKeyPaths' notation.
func presentKeyPaths(doc any, typ reflect.Type, prefix string, raw map[string]reflect.Type, out map[string]bool) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == rawMessageType {
		if sub, ok := raw[prefix]; ok {
			presentKeyPaths(doc, sub, prefix, raw, out)
		}
		return
	}
	switch typ.Kind() {
	case reflect.Struct:
		obj, ok := doc.(map[string]any)
		if !ok {
			return
		}
		for _, f := range jsonFields(typ) {
			v, ok := obj[f.Name]
			if !ok {
				continue
			}
			p := joinPath(prefix, f.Name)
			out[p] = true
			presentKeyPaths(v, f.Type, p, raw, out)
		}
	case reflect.Map:
		obj, ok := doc.(map[string]any)
		if !ok {
			return
		}
		for _, v := range obj {
			presentKeyPaths(v, typ.Elem(), prefix+".*", raw, out)
		}
	case reflect.Slice, reflect.Array:
		arr, ok := doc.([]any)
		if !ok {
			return
		}
		for _, v := range arr {
			presentKeyPaths(v, typ.Elem(), prefix+"[]", raw, out)
		}
	}
}
