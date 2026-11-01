package components

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCatalogValidates(t *testing.T) {
	if p := Validate(); len(p) != 0 {
		t.Fatalf("catalog has %d problems:\n%s", len(p), strings.Join(p, "\n"))
	}
}

// TestCatalogShape pins the headline counts the plan and the lane brief
// name, so a row added or dropped by accident is loud. Bump CatalogVersion
// with any intended change here.
func TestCatalogShape(t *testing.T) {
	var feature, integration, adapter, core, server int
	for _, c := range All() {
		switch {
		case c.Class == ClassAdapter:
			adapter++
		case c.Class == ClassCore:
			core++
		case c.Binary != BinaryNode:
			server++
		case c.Class == ClassIntegration:
			integration++
		default:
			feature++
		}
	}
	if adapter != 55 {
		t.Errorf("adapter rows = %d, want 55 (one per integration registry tool)", adapter)
	}
	if core != 2 {
		t.Errorf("core rows = %d, want 2 (node core and org.core)", core)
	}
	// The upper bound leaves room for the security pillar's children
	// (security.trust, security.secrets, security.code, then deps, the
	// scanner drivers, the code-rules driver and the feedback) and the
	// sandbox rows (the oci, mxc, Seatbelt and Apple container drivers each
	// have their own row: 57 after lanes SBX-P5 and SBX-P6 merged; lane
	// SBX-P7 adds the e2b, modal and vercel hosted drivers; lane GATES-SBX
	// adds readopt, credentials, mxc.appcontainer, wslc and hcs; lane GATES-SEC
	// the trivy and kics drivers and isolation.seal).
	if got := feature + integration; got < 38 || got > 76 {
		t.Errorf("optional node rows = %d, want 38 to 76", got)
	}
	if server < 21 {
		t.Errorf("server rows = %d, want at least 21", server)
	}
	// The plan's three (browser extension, two helpers) plus the VS Code
	// extension and the plugin shims (lane MP-ART, T-601).
	if len(Artifacts()) != 5 {
		t.Errorf("artifact rows = %d, want 5", len(Artifacts()))
	}
	if CatalogVersion < 1 {
		t.Error("CatalogVersion must be positive")
	}
}

// TestValidateRejects is the table of catalog bugs Validate must catch, one
// row per rule.
func TestValidateRejects(t *testing.T) {
	base := func() Component {
		return Component{
			ID: "x.feature", Class: ClassFeature, Binary: BinaryNode, Title: "X", About: "X does x.",
			Levels: lv(onlyL3, l1l2l3, "P2"), Stability: StabilityStable, Distros: dist(out, on, off, on),
		}
	}
	core := Component{
		ID: "core", Class: ClassCore, Binary: BinaryNode, Title: "Core", About: "Core.",
		Levels: lv(onlyL0, onlyL0, ""), Stability: StabilityStable, Distros: dist(on, on, on, on),
	}
	orgc := Component{
		ID: "org.client", Class: ClassFeature, Binary: BinaryNode, Title: "Org", About: "Org.",
		Levels: lv(onlyL3, l2l3, "P1"), Stability: StabilityStable, Distros: dist(off, cond, on, on),
	}
	cases := []struct {
		name   string
		mutate func(rows []Component) []Component
		want   string
	}{
		{"bad id", func(r []Component) []Component { r[2].ID = "X Feature"; return r }, "does not match"},
		{"duplicate id", func(r []Component) []Component { return append(r, r[2]) }, "duplicate id"},
		{"em dash in copy", func(r []Component) []Component { r[2].About = "x — y"; return r }, "em or en dash"},
		{"unknown requires", func(r []Component) []Component { r[2].Requires = []string{"nope"}; return r }, "unknown component nope"},
		{"requires cycle", func(r []Component) []Component {
			y := base()
			y.ID = "y.feature"
			y.Requires = []string{"x.feature"}
			r[2].Requires = []string{"y.feature"}
			return append(r, y)
		}, "requires cycle"},
		{"org.client compiled out", func(r []Component) []Component { r[1].Distros = dist(out, cond, on, on); return r }, "must be compiled into the minimal distro"},
		{"org.client targets L1", func(r []Component) []Component { r[1].Levels = lv(onlyL3, l1l2l3, "P2"); return r }, "must never target L1"},
		{"missing distro cell", func(r []Component) []Component { delete(r[2].Distros, DistroManaged); return r }, "missing the managed distro cell"},
		{"full omits", func(r []Component) []Component { r[2].Distros[DistroFull] = out; return r }, "full distro compiles everything"},
		{"compiled without its requirement", func(r []Component) []Component {
			y := base()
			y.ID = "y.feature"
			y.Distros = dist(out, out, off, on)
			r[2].Requires = []string{"y.feature"}
			return append(r, y)
		}, "which developer compiles out"},
		{"L2-only component compiled out", func(r []Component) []Component {
			r[2].Levels = lv(onlyL3, l2l3, "P1")
			return r
		}, "does not target L1"},
		{"phase missing", func(r []Component) []Component { r[2].Levels.Phase = ""; return r }, "needs the phase"},
		{"level shipped then dropped", func(r []Component) []Component { r[2].Levels = lv(onlyL3, l2, "P1"); return r }, "missing from the target set"},
		{"package owned twice", func(r []Component) []Component {
			y := base()
			y.ID = "y.feature"
			y.Packages = []string{"internal/x"}
			r[2].Packages = []string{"internal/x"}
			return append(r, y)
		}, "already owned"},
		{"verb owned twice", func(r []Component) []Component {
			y := base()
			y.ID = "y.feature"
			y.Verbs = []string{"x"}
			r[2].Verbs = []string{"x"}
			return append(r, y)
		}, "verb x already owned"},
		{"route owned twice", func(r []Component) []Component {
			y := base()
			y.ID = "y.feature"
			y.Routes = []string{"/api/x/"}
			r[2].Routes = []string{"/api/x"}
			return append(r, y)
		}, "route /api/x/ already owned"},
		{"one-way bundle", func(r []Component) []Component {
			y := base()
			y.ID = "y.feature"
			r[2].Bundles = []string{"y.feature"}
			return append(r, y)
		}, "does not bundle or require it back"},
		{"loopback not loopback", func(r []Component) []Component {
			r[2].Surface.Listeners = []Listener{{Proto: "tcp", Addr: "0.0.0.0:1", Loopback: true, Auth: "none", Trigger: TriggerAutomatic}}
			return r
		}, "not on 127.0.0.1"},
		{"shared data without selector", func(r []Component) []Component {
			r[2].Data = []DataOwnership{{Table: "sessions", Ownership: "shared"}}
			return r
		}, "needs a row selector"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := tc.mutate([]Component{core, orgc, base()})
			p := validateRows(rows, nil)
			if !strings.Contains(strings.Join(p, "\n"), tc.want) {
				t.Fatalf("want a problem containing %q, got:\n%s", tc.want, strings.Join(p, "\n"))
			}
		})
	}
	if p := validateRows([]Component{core, orgc, base()}, nil); len(p) != 0 {
		t.Fatalf("the base rows must validate, got:\n%s", strings.Join(p, "\n"))
	}
}

var l2 = []Level{L2}

func TestBuildTagDerivation(t *testing.T) {
	cases := map[string]string{
		"codeintel":         "sbo_omit_codeintel",
		"adapter.zed":       "sbo_omit_adapter_zed",
		"org.saml":          "sbo_omit_org_saml",
		"adapter.kilo-code": "sbo_omit_adapter_kilo_code",
	}
	for id, want := range cases {
		if got := BuildTagFor(id); got != want {
			t.Errorf("BuildTagFor(%q) = %q, want %q", id, got, want)
		}
	}
	if c, _ := Get("core"); c.BuildTag() != "" {
		t.Error("core has no build tag")
	}
}

func TestDistros(t *testing.T) {
	full := InDistro(DistroFull)
	if len(full) != len(ForBinary(BinaryNode)) {
		t.Fatalf("full compiles %d of %d node rows", len(full), len(ForBinary(BinaryNode)))
	}
	if len(OmitTags(DistroFull)) != 0 {
		t.Fatalf("full has omit tags: %v", OmitTags(DistroFull))
	}
	// Each prebuilt distro is a valid selection, and nests: minimal is the
	// smallest.
	for _, d := range Distros() {
		if p := ValidateSelection(BinaryNode, InDistro(d)); len(p) != 0 {
			t.Errorf("%s is not a valid selection:\n%s", d, strings.Join(p, "\n"))
		}
		if DistroOf(InDistro(d)) != d {
			t.Errorf("DistroOf(InDistro(%s)) = %s", d, DistroOf(InDistro(d)))
		}
	}
	if len(InDistro(DistroMinimal)) >= len(InDistro(DistroDeveloper)) {
		t.Error("minimal must be smaller than developer")
	}
	// D-389: Plane A observability is out of developer.
	for _, id := range InDistro(DistroDeveloper) {
		if id == "obs" {
			t.Error("obs must be out of the developer distro (D-389)")
		}
	}
	// D-374: the pricing feed stays on by default in developer.
	if c, _ := Get("egress.pricing-feed"); c.Distros[DistroDeveloper] != DefaultOn {
		t.Error("egress.pricing-feed must be on by default in developer (D-374)")
	}
	if got := ValidateSelection(BinaryNode, []string{"core"}); !strings.Contains(strings.Join(got, "\n"), "org.client") {
		t.Errorf("a selection without org.client must be refused, got %v", got)
	}
}

func TestDigestOrderIndependent(t *testing.T) {
	a := Digest([]string{"core", "codeintel", "org.client"})
	b := Digest([]string{"org.client", "core", "codeintel"})
	if a != b || len(a) != 64 {
		t.Fatalf("digest not order independent: %s vs %s", a, b)
	}
	if a == Digest([]string{"core", "org.client"}) {
		t.Fatal("different sets share a digest")
	}
}

func TestImages(t *testing.T) {
	core := InImage(ImageCore)
	want := map[string]bool{"org.core": true, "org.oidc": true}
	if len(core) != len(want) {
		t.Fatalf("core image = %v, want org.core and org.oidc (Q11)", core)
	}
	for _, id := range core {
		if !want[id] {
			t.Fatalf("core image has %s", id)
		}
	}
}

// TestDigestMixesCatalogVersion pins the digest to the catalog version
// (3 since lane SEC-F2B, 4 since lane GATES-SEC): a version bump changes every binary's
// components digest once, the release-note line.
func TestDigestMixesCatalogVersion(t *testing.T) {
	if CatalogVersion != 4 {
		t.Fatalf("CatalogVersion = %d; the wave-6 bump is 4", CatalogVersion)
	}
	ids := []string{"core", "security", "security.provenance"}
	h := sha256.Sum256([]byte("sbo-components-v4\ncore\nsecurity\nsecurity.provenance"))
	if got := Digest(ids); got != hex.EncodeToString(h[:]) {
		t.Fatalf("digest %s does not mix in catalog v4", got)
	}
	v3 := sha256.Sum256([]byte("sbo-components-v3\ncore\nsecurity\nsecurity.provenance"))
	if Digest(ids) == hex.EncodeToString(v3[:]) {
		t.Fatal("the digest still reads as catalog v3")
	}
}
