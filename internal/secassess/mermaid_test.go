package secassess

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// mmModel is a small system with every shape, three zones, crossing and
// non-crossing flows and two weak ones. The names are invented.
func mmModel() *ThreatModelDoc {
	return &ThreatModelDoc{System: System{
		Zones: []Zone{{ID: "net", Name: "Internet"}, {ID: "app", Name: "Application"}, {ID: "data", Name: "Data"}},
		Components: []Component{
			{ID: "web", Name: "Web client", Type: "ui", Zone: "net"},
			{ID: "api", Name: "Ledger API", Type: "service", Zone: "app"},
			{ID: "db", Name: "Ledger database", Type: "datastore", Zone: "data"},
			{ID: "audit", Name: "Audit log", Type: "log_store", Zone: "data"},
			{ID: "idp", Name: "Identity provider", Type: "external", Zone: "net"},
			{ID: "cron", Name: "Nightly job", Type: "job"},
		},
		Actors: []Actor{
			{ID: "anon", Name: "Anonymous visitor", Kind: "anonymous"},
			{ID: "user", Name: "Signed-in user", Kind: "end_user"},
			{ID: "ghost", Name: "Unused actor", Kind: "service"},
		},
		Flows: []Flow{
			{ID: "f1", From: "user", To: "web", Protocol: "https", Authn: "session", Encrypted: "yes", Crosses: []string{"net"}},
			{ID: "f2", From: "web", To: "api", Protocol: "https", Authn: "session", Crosses: []string{"net", "app"}},
			{ID: "f3", From: "anon", To: "api", Protocol: "https", Authn: "none", Crosses: []string{"net", "app"}},
			{ID: "f4", From: "api", To: "db", Protocol: "postgres", Encrypted: "no", Crosses: []string{"app", "data"}},
			{ID: "f5", From: "api", To: "idp", Protocol: "https", Authn: "token"},
			{ID: "f6", From: "db", To: "audit", Authn: "none"},
			{ID: "f7", From: "cron", To: "api"},
		},
	}}
}

const mmGolden = `flowchart LR
  subgraph z1["Internet"]
    c1["Web client"]
    c5[["Identity provider"]]
  end
  subgraph z2["Application"]
    c2["Ledger API"]
  end
  subgraph z3["Data"]
    c3[("Ledger database")]
    c4[("Audit log")]
  end
  c6["Nightly job"]
  a1(["Anonymous visitor"])
  a2(["Signed-in user"])
  a2 -.->|"https"| c1
  c1 -.->|"https"| c2
  a1 -.->|"https, no authentication"| c2
  c2 -.->|"postgres, not encrypted"| c3
  c2 -.->|"https"| c5
  c3 -->|"no authentication"| c4
  c6 --> c2
  linkStyle 2,3 stroke:#d33,stroke-width:2px`

// mmLabelRE is the characters a label may hold.
const mmLabelRE = `[A-Za-z0-9 .,:/_()-]*`

// mmGrammar is every line the renderer may write, and nothing else. A source
// line that matches none of these is an injection, whatever the agent wrote.
var mmGrammar = []*regexp.Regexp{
	regexp.MustCompile(`^flowchart LR$`),
	regexp.MustCompile(`^  subgraph z\d+\["` + mmLabelRE + `"\]$`),
	regexp.MustCompile(`^  end$`),
	regexp.MustCompile(`^ {2,4}[ca]\d+(\[\("` + mmLabelRE + `"\)\]|\[\["` + mmLabelRE + `"\]\]|\(\["` + mmLabelRE + `"\]\)|\["` + mmLabelRE + `"\])$`),
	regexp.MustCompile(`^  [ca]\d+ (-->|-\.->)(\|"` + mmLabelRE + `"\|)? [ca]\d+$`),
	regexp.MustCompile(`^  linkStyle \d+(,\d+)* stroke:#d33,stroke-width:2px$`),
	regexp.MustCompile(`^  %% \d+ nodes and \d+ flows are not drawn \(cap \d+\)$`),
}

// mmOutsideQuotes returns src with the content of every quoted label removed:
// what is left is the structure the renderer wrote.
func mmOutsideQuotes(src string) string {
	return regexp.MustCompile(`"[^"]*"`).ReplaceAllString(src, `""`)
}

// mmCheckGrammar fails when a line of src is outside the grammar, and when the
// source has a carriage return, a tab or a byte outside ASCII.
func mmCheckGrammar(t *testing.T, src string) {
	t.Helper()
	if strings.ContainsAny(src, "\r\t") {
		t.Errorf("the source holds a carriage return or a tab: %q", src)
	}
	for i := 0; i < len(src); i++ {
		if src[i] >= 0x80 {
			t.Errorf("the source holds a byte outside ASCII: %q", src)
			break
		}
	}
	for _, line := range strings.Split(src, "\n") {
		ok := false
		for _, re := range mmGrammar {
			if re.MatchString(line) {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("a line outside the grammar: %q", line)
		}
	}
}

func TestRenderMermaidGolden(t *testing.T) {
	m := mmModel()
	d := RenderMermaid(m, 0)
	if d.Source != mmGolden {
		t.Errorf("source\n got:\n%s\nwant:\n%s", d.Source, mmGolden)
	}
	want := MermaidDiagram{Source: mmGolden, Nodes: 8, TotalNodes: 8, OmittedNodes: 0, Edges: 7, OmittedEdges: 0, MaxNodes: 60, LabelChars: 40}
	if d != want {
		t.Errorf("diagram = %+v, want %+v", d, want)
	}
	mmCheckGrammar(t, d.Source)
	if again := RenderMermaid(mmModel(), 0); again != d {
		t.Errorf("a second render differs:\n%s", again.Source)
	}
}

// TestRenderMermaidShapes walks the component type table: one row per type, so
// a type added later is drawn on purpose.
func TestRenderMermaidShapes(t *testing.T) {
	shape := func(open, name, close string) string { return open + name + close }
	for _, ct := range ComponentTypes {
		want := shape(`["`, "N", `"]`)
		switch ct.Class {
		case ClassDataStore:
			want = shape(`[("`, "N", `")]`)
		case ClassExternalEntity:
			want = shape(`[["`, "N", `"]]`)
		}
		t.Run(ct.ID, func(t *testing.T) {
			m := &ThreatModelDoc{System: System{Components: []Component{{ID: "x", Name: "N", Type: ct.ID}}}}
			d := RenderMermaid(m, 0)
			if wantSrc := "flowchart LR\n  c1" + want; d.Source != wantSrc {
				t.Errorf("source = %q, want %q", d.Source, wantSrc)
			}
		})
	}
	t.Run("an unknown type is drawn plain", func(t *testing.T) {
		m := &ThreatModelDoc{System: System{Components: []Component{{ID: "x", Name: "N", Type: "teleporter"}}}}
		if got, want := RenderMermaid(m, 0).Source, "flowchart LR\n  c1[\"N\"]"; got != want {
			t.Errorf("source = %q, want %q", got, want)
		}
	})
	t.Run("an actor is a stadium", func(t *testing.T) {
		m := &ThreatModelDoc{System: System{
			Components: []Component{{ID: "x", Name: "N", Type: "service"}},
			Actors:     []Actor{{ID: "u", Name: "Visitor", Kind: "end_user"}},
			Flows:      []Flow{{ID: "f", From: "u", To: "x"}},
		}}
		if got := RenderMermaid(m, 0).Source; !strings.Contains(got, "\n  a1([\"Visitor\"])\n") {
			t.Errorf("source = %q", got)
		}
	})
}

func TestRenderMermaidZones(t *testing.T) {
	comp := func(id, zone string) Component {
		return Component{ID: id, Name: "Name " + id, Type: "service", Zone: zone}
	}
	tests := []struct {
		name  string
		zones []Zone
		comps []Component
		want  string
	}{
		{
			"components sit in their zone's block in model order",
			[]Zone{{ID: "a", Name: "Alpha"}, {ID: "b", Name: "Beta"}},
			[]Component{comp("1", "b"), comp("2", "a"), comp("3", "b")},
			"flowchart LR\n  subgraph z1[\"Alpha\"]\n    c2[\"Name 2\"]\n  end\n  subgraph z2[\"Beta\"]\n    c1[\"Name 1\"]\n    c3[\"Name 3\"]\n  end",
		},
		{
			"a component with no zone sits outside any block",
			[]Zone{{ID: "a", Name: "Alpha"}},
			[]Component{comp("1", ""), comp("2", "a")},
			"flowchart LR\n  subgraph z1[\"Alpha\"]\n    c2[\"Name 2\"]\n  end\n  c1[\"Name 1\"]",
		},
		{
			"a zone id the model lacks sits outside any block",
			[]Zone{{ID: "a", Name: "Alpha"}},
			[]Component{comp("1", "nowhere"), comp("2", "a")},
			"flowchart LR\n  subgraph z1[\"Alpha\"]\n    c2[\"Name 2\"]\n  end\n  c1[\"Name 1\"]",
		},
		{
			"a zone with no drawn component writes no block",
			[]Zone{{ID: "a", Name: "Alpha"}, {ID: "b", Name: "Beta"}},
			[]Component{comp("1", "b")},
			"flowchart LR\n  subgraph z2[\"Beta\"]\n    c1[\"Name 1\"]\n  end",
		},
		{
			"a repeated zone id keeps the first zone",
			[]Zone{{ID: "a", Name: "First"}, {ID: "a", Name: "Second"}},
			[]Component{comp("1", "a")},
			"flowchart LR\n  subgraph z1[\"First\"]\n    c1[\"Name 1\"]\n  end",
		},
		{
			"a zone with an empty id holds nothing",
			[]Zone{{ID: "", Name: "Nameless"}},
			[]Component{comp("1", "")},
			"flowchart LR\n  c1[\"Name 1\"]",
		},
		{
			"a zone name with nothing printable falls back to the zone's own id",
			[]Zone{{ID: "a", Name: "\u00e9\u00e8"}},
			[]Component{comp("1", "a")},
			"flowchart LR\n  subgraph z1[\"z1\"]\n    c1[\"Name 1\"]\n  end",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := RenderMermaid(&ThreatModelDoc{System: System{Zones: tc.zones, Components: tc.comps}}, 0)
			if d.Source != tc.want {
				t.Errorf("source\n got: %q\nwant: %q", d.Source, tc.want)
			}
			mmCheckGrammar(t, d.Source)
		})
	}
}

// TestRenderMermaidFlows pins the arrow of a flow, the highlight of a weak
// crossing and the linkStyle indices, which count edges in the order written.
func TestRenderMermaidFlows(t *testing.T) {
	sys := func(flows ...Flow) *ThreatModelDoc {
		return &ThreatModelDoc{System: System{
			Zones: []Zone{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}},
			Components: []Component{
				{ID: "p", Name: "P", Type: "service", Zone: "a"},
				{ID: "q", Name: "Q", Type: "service", Zone: "b"},
				{ID: "r", Name: "R", Type: "service", Zone: "a"},
				{ID: "s", Name: "S", Type: "service"},
			},
			Actors: []Actor{{ID: "u", Name: "U", Kind: "end_user"}},
			Flows:  flows,
		}}
	}
	edgeLines := func(src string) []string {
		var out []string
		for _, l := range strings.Split(src, "\n") {
			if strings.Contains(l, "-->") || strings.Contains(l, "-.->") {
				out = append(out, strings.TrimSpace(l))
			}
		}
		return out
	}
	tests := []struct {
		name  string
		flows []Flow
		edges []string
		style string // the linkStyle line, "" for none
	}{
		{"a crosses list makes the edge dashed", []Flow{{From: "p", To: "r", Crosses: []string{"a"}}}, []string{"c1 -.-> c3"}, ""},
		{"two components in different known zones make it dashed", []Flow{{From: "p", To: "q"}}, []string{"c1 -.-> c2"}, ""},
		{"two components in one zone are solid", []Flow{{From: "p", To: "r"}}, []string{"c1 --> c3"}, ""},
		{"a component with no zone against one in a zone is solid", []Flow{{From: "p", To: "s"}}, []string{"c1 --> c4"}, ""},
		{"an actor and a component are solid without a crosses list", []Flow{{From: "u", To: "p"}}, []string{"a1 --> c1"}, ""},
		{"an actor with a crosses list is dashed", []Flow{{From: "u", To: "p", Crosses: []string{"a"}}}, []string{"a1 -.-> c1"}, ""},
		{"a self loop is an edge", []Flow{{From: "p", To: "p"}}, []string{"c1 --> c1"}, ""},
		{
			"a crossing flow with no authentication is highlighted",
			[]Flow{{From: "p", To: "q", Authn: "none"}},
			[]string{`c1 -.->|"no authentication"| c2`},
			"linkStyle 0 stroke:#d33,stroke-width:2px",
		},
		{
			"a crossing flow that is not encrypted is highlighted",
			[]Flow{{From: "p", To: "q", Encrypted: "no"}},
			[]string{`c1 -.->|"not encrypted"| c2`},
			"linkStyle 0 stroke:#d33,stroke-width:2px",
		},
		{
			"a crossing flow with unknown authentication and encryption is not highlighted",
			[]Flow{{From: "p", To: "q", Authn: "unknown", Encrypted: "unknown"}},
			[]string{"c1 -.-> c2"},
			"",
		},
		{
			"a crossing flow with authentication and encryption is not highlighted",
			[]Flow{{From: "p", To: "q", Authn: "mtls", Encrypted: "yes"}},
			[]string{"c1 -.-> c2"},
			"",
		},
		{
			"a flow that does not cross is never highlighted, but says what is missing",
			[]Flow{{From: "p", To: "r", Authn: "none", Encrypted: "no"}},
			[]string{`c1 -->|"no authentication, not encrypted"| c3`},
			"",
		},
		{
			"the indices count the edges in the order written, solid ones included",
			[]Flow{
				{From: "p", To: "r"},                                             // 0 solid
				{From: "p", To: "q", Authn: "none"},                              // 1 weak
				{From: "q", To: "p", Authn: "mtls"},                              // 2 dashed, fine
				{From: "q", To: "r", Encrypted: "no", Crosses: []string{"b"}},    // 3 weak
				{From: "r", To: "s", Authn: "none"},                              // 4 solid
				{From: "u", To: "p", Authn: "none", Crosses: []string{"a", "b"}}, // 5 weak
			},
			nil,
			"linkStyle 1,3,5 stroke:#d33,stroke-width:2px",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := RenderMermaid(sys(tc.flows...), 0)
			mmCheckGrammar(t, d.Source)
			if tc.edges != nil {
				got := edgeLines(d.Source)
				// Compare the arrows, ids and the label's presence; the label
				// words are pinned in TestRenderMermaidEdgeLabels.
				if len(got) != len(tc.edges) {
					t.Fatalf("edges = %q, want %q", got, tc.edges)
				}
				for i := range got {
					if got[i] != tc.edges[i] {
						t.Errorf("edge %d = %q, want %q", i, got[i], tc.edges[i])
					}
				}
			}
			var style string
			for _, l := range strings.Split(d.Source, "\n") {
				if strings.Contains(l, "linkStyle") {
					if style != "" {
						t.Errorf("more than one linkStyle line:\n%s", d.Source)
					}
					style = strings.TrimSpace(l)
				}
			}
			if style != tc.style {
				t.Errorf("linkStyle = %q, want %q", style, tc.style)
			}
			if d.Edges != len(tc.flows) || d.OmittedEdges != 0 {
				t.Errorf("edges = %d omitted %d, want %d and 0", d.Edges, d.OmittedEdges, len(tc.flows))
			}
		})
	}
}

func TestRenderMermaidEdgeLabels(t *testing.T) {
	tests := []struct {
		name string
		flow Flow
		want string // the label as written, "" for none
	}{
		{"nothing to say, no label", Flow{}, ""},
		{"a protocol", Flow{Protocol: "https"}, `|"https"|`},
		{"authentication none", Flow{Authn: "none"}, `|"no authentication"|`},
		{"not encrypted", Flow{Encrypted: "no"}, `|"not encrypted"|`},
		{"both", Flow{Authn: "none", Encrypted: "no"}, `|"no authentication, not encrypted"|`},
		{"protocol first, then Observer's words", Flow{Protocol: "grpc", Authn: "none", Encrypted: "no"}, `|"grpc, no authentication, not encrypted"|`},
		{"authentication that exists is not said", Flow{Protocol: "https", Authn: "session", Encrypted: "yes"}, `|"https"|`},
		{"unknown is not said", Flow{Authn: "unknown", Encrypted: "unknown"}, ""},
		{"a protocol with nothing printable has no label", Flow{Protocol: "\u2603\u2603"}, ""},
		{"a hostile protocol is cleaned", Flow{Protocol: "https\"|c9; click c1 `x` %%{init}%%"}, `|"https c9 click c1 x init"|`},
		{"a long protocol is cut", Flow{Protocol: strings.Repeat("abcd", 30)}, `|"` + strings.Repeat("abcd", 10) + `"|`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &ThreatModelDoc{System: System{
				Components: []Component{{ID: "a", Name: "A", Type: "service"}, {ID: "b", Name: "B", Type: "service"}},
				Flows:      []Flow{{From: "a", To: "b", Protocol: tc.flow.Protocol, Authn: tc.flow.Authn, Encrypted: tc.flow.Encrypted}},
			}}
			d := RenderMermaid(m, 0)
			mmCheckGrammar(t, d.Source)
			want := "  c1 --> c2"
			if tc.want != "" {
				want = "  c1 -->" + tc.want + " c2"
			}
			if !strings.Contains(d.Source, "\n"+want) {
				t.Errorf("source = %q, want the edge line %q", d.Source, want)
			}
		})
	}
}

func TestRenderMermaidLabelSanitising(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Ledger API", "Ledger API"},
		{"every allowed punctuation mark", "a.b,c:d/e_f(g)h-i 0", "a.b,c:d/e_f(g)h-i 0"},
		{"double quotes", `say "hi"`, "say hi"},
		{"square brackets and a semicolon", `x"];click c1`, "x click c1"},
		{"curly braces", `{init: x}`, "init: x"},
		{"pipes", "a|b|c", "a b c"},
		{"backticks", "`code` here", "code here"},
		{"a directive and comment marker", "%%{init: {}}%% x", "init: x"},
		{"the word end", "end", "end"},
		{"newlines and tabs", "a\nb\r\nc\td", "a b c d"},
		{"unicode letters become spaces", "caf\u00e9 \u4e2d\u6587 ok", "caf ok"},
		{"zero width characters become spaces", "a\u200bb", "a b"},
		{"angle brackets and an ampersand", "<script>alert(1)</script> & co", "script alert(1) /script co"},
		{"a backslash and a hash", `a\b#c`, "a b c"},
		{"leading and trailing junk", "  ;;; name ;;;  ", "name"},
		{"runs of spaces collapse", "a      b", "a b"},
		{"cut to 40 runes", strings.Repeat("x", 100), strings.Repeat("x", 40)},
		{"cut at a space leaves no trailing space", strings.Repeat("x", 39) + " tail", strings.Repeat("x", 39)},
		{"cut across a space run", strings.Repeat("x", 39) + "     tail", strings.Repeat("x", 39)},
		{"exactly 40 runes is kept", strings.Repeat("y", 40), strings.Repeat("y", 40)},
		{"empty falls back to the id", "", "c1"},
		{"spaces only falls back to the id", "   ", "c1"},
		{"nothing allowed falls back to the id", "\u2603\"';", "c1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := &ThreatModelDoc{System: System{Components: []Component{{ID: "x", Name: tc.in, Type: "service"}}}}
			d := RenderMermaid(m, 0)
			if want := "flowchart LR\n  c1[\"" + tc.want + "\"]"; d.Source != want {
				t.Errorf("source\n got: %q\nwant: %q", d.Source, want)
			}
			mmCheckGrammar(t, d.Source)
		})
	}
}

// TestRenderMermaidHostileModel puts hostile text in every place the agent's
// words reach the source, and holds the whole source to the grammar.
func TestRenderMermaidHostileModel(t *testing.T) {
	hostile := []string{
		"a\"];click c1 \"javascript:alert(1)\"",
		"end",
		"%%{init: {\"securityLevel\":\"loose\"}}%%",
		"x\n  c9[\"y\"]\n  click c9 call alert()",
		"`${process.env.X}`",
		"<img src=x onerror=alert(1)>",
		"__proto__",
		"subgraph",
		"flowchart TB",
		"a\u2028b\u2029c",
	}
	m := &ThreatModelDoc{}
	for i, h := range hostile {
		zone := fmt.Sprintf("z%d", i)
		m.System.Zones = append(m.System.Zones, Zone{ID: h, Name: h})
		m.System.Components = append(m.System.Components, Component{ID: h, Name: h, Type: "service", Zone: h})
		m.System.Actors = append(m.System.Actors, Actor{ID: zone + h, Name: h, Kind: "end_user"})
		m.System.Flows = append(m.System.Flows, Flow{
			ID: h, From: zone + h, To: h, Protocol: h, Authn: h, Encrypted: h, Crosses: []string{h},
		})
	}
	d := RenderMermaid(m, 0)
	mmCheckGrammar(t, d.Source)
	// The agent's words are inert inside the quotes; outside them nothing of
	// the agent's is left.
	structure := mmOutsideQuotes(d.Source)
	for _, bad := range []string{"click", "javascript", "securityLevel", "init", "<", "__proto__", "process", "TB", "call", "%%{"} {
		if strings.Contains(structure, bad) {
			t.Errorf("the structure of the source carries %q:\n%s", bad, d.Source)
		}
	}
	// Every block line is written by position.
	for _, l := range strings.Split(d.Source, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "subgraph") && !regexp.MustCompile(`^  subgraph z\d+\["`).MatchString(l) {
			t.Errorf("a subgraph line not written by position: %q", l)
		}
	}
}

// TestRenderMermaidIDsArePositional pins that node and subgraph ids come from
// positions in the model and never from the agent's ids.
func TestRenderMermaidIDsArePositional(t *testing.T) {
	m := &ThreatModelDoc{System: System{
		Zones: []Zone{{ID: "end", Name: "Z"}},
		Components: []Component{
			{ID: `a"];click`, Name: "First", Type: "service", Zone: "end"},
			{ID: "subgraph", Name: "Second", Type: "datastore"},
		},
		Actors: []Actor{{ID: "style", Name: "Third", Kind: "anonymous"}},
		Flows: []Flow{
			{ID: "x", From: "style", To: `a"];click`},
			{ID: "y", From: `a"];click`, To: "subgraph"},
		},
	}}
	d := RenderMermaid(m, 0)
	want := strings.Join([]string{
		"flowchart LR",
		`  subgraph z1["Z"]`,
		`    c1["First"]`,
		"  end",
		`  c2[("Second")]`,
		`  a1(["Third"])`,
		`  a1 --> c1`,
		`  c1 --> c2`,
	}, "\n")
	if d.Source != want {
		t.Errorf("source\n got:\n%s\nwant:\n%s", d.Source, want)
	}
	// The ids do not move when the model is capped: a node is c<position in
	// System.Components>, whatever else is drawn.
	m.System.Components = append([]Component{{ID: "front", Name: "Front", Type: "service"}}, m.System.Components...)
	if got := RenderMermaid(m, 0).Source; !strings.Contains(got, `c2["First"]`) || !strings.Contains(got, `c3[("Second")]`) {
		t.Errorf("ids did not follow the positions:\n%s", got)
	}
}

func TestRenderMermaidNodeCap(t *testing.T) {
	// A hub (h) with four spokes and an isolated chain: degrees h=4, s1..s4=1,
	// c1=1, c2=2, c3=1.
	m := &ThreatModelDoc{System: System{
		Components: []Component{
			{ID: "s1", Name: "S1", Type: "service"},
			{ID: "s2", Name: "S2", Type: "service"},
			{ID: "h", Name: "Hub", Type: "service"},
			{ID: "s3", Name: "S3", Type: "service"},
			{ID: "s4", Name: "S4", Type: "service"},
			{ID: "k1", Name: "K1", Type: "service"},
			{ID: "k2", Name: "K2", Type: "service"},
			{ID: "k3", Name: "K3", Type: "service"},
		},
		Actors: []Actor{{ID: "u", Name: "User", Kind: "end_user"}},
		Flows: []Flow{
			{ID: "1", From: "s1", To: "h"},
			{ID: "2", From: "s2", To: "h"},
			{ID: "3", From: "h", To: "s3"},
			{ID: "4", From: "h", To: "s4"},
			{ID: "5", From: "k1", To: "k2"},
			{ID: "6", From: "k2", To: "k3"},
			{ID: "7", From: "u", To: "h"},
		},
	}}
	tests := []struct {
		name     string
		max      int
		nodes    []string // node ids drawn, in the order written
		edges    int
		omitN    int
		omitE    int
		comment  string
		maxField int
	}{
		// 9 nodes (8 components, the actor). Degrees: h 5, k2 2, then every
		// other node 1.
		{"all fit", 9, []string{"c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "a1"}, 7, 0, 0, "", 9},
		{"one over drops the last of the least busy", 8, []string{"c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8"}, 6, 1, 1, "%% 1 nodes and 1 flows are not drawn (cap 8)", 8},
		{"the hub and the busiest go first, ties in model order", 3, []string{"c1", "c3", "c7"}, 1, 6, 6, "%% 6 nodes and 6 flows are not drawn (cap 3)", 3},
		{"one node", 1, []string{"c3"}, 0, 8, 7, "%% 8 nodes and 7 flows are not drawn (cap 1)", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := RenderMermaid(m, tc.max)
			mmCheckGrammar(t, d.Source)
			var ids []string
			for _, l := range strings.Split(d.Source, "\n") {
				if mm := regexp.MustCompile(`^ {2,4}([ca]\d+)[\[(]`).FindStringSubmatch(l); mm != nil {
					ids = append(ids, mm[1])
				}
			}
			if !reflect.DeepEqual(ids, tc.nodes) {
				t.Errorf("nodes drawn = %v, want %v", ids, tc.nodes)
			}
			if d.Nodes != len(tc.nodes) || d.TotalNodes != 9 || d.OmittedNodes != tc.omitN {
				t.Errorf("nodes %d total %d omitted %d, want %d, 9, %d", d.Nodes, d.TotalNodes, d.OmittedNodes, len(tc.nodes), tc.omitN)
			}
			if d.Edges != tc.edges || d.OmittedEdges != tc.omitE {
				t.Errorf("edges %d omitted %d, want %d and %d", d.Edges, d.OmittedEdges, tc.edges, tc.omitE)
			}
			if d.MaxNodes != tc.maxField {
				t.Errorf("max_nodes = %d, want %d", d.MaxNodes, tc.maxField)
			}
			lines := strings.Split(d.Source, "\n")
			last := lines[len(lines)-1]
			switch {
			case tc.comment == "" && strings.Contains(d.Source, "%%"):
				t.Errorf("a comment line with nothing left out: %q", last)
			case tc.comment != "" && last != "  "+tc.comment:
				t.Errorf("last line = %q, want %q", last, "  "+tc.comment)
			}
			// Edges are drawn only between drawn nodes.
			drawn := map[string]bool{}
			for _, id := range ids {
				drawn[id] = true
			}
			for _, l := range lines {
				if mm := regexp.MustCompile(`^  ([ca]\d+) (?:-->|-\.->)(?:\|"[^"]*"\|)? ([ca]\d+)$`).FindStringSubmatch(l); mm != nil {
					if !drawn[mm[1]] || !drawn[mm[2]] {
						t.Errorf("an edge to a node that is not drawn: %q", l)
					}
				}
			}
		})
	}
}

// TestRenderMermaidKeepsEdgeIndicesAfterTheCap pins that linkStyle indices
// count the edges that are drawn, not the flows of the model.
func TestRenderMermaidKeepsEdgeIndicesAfterTheCap(t *testing.T) {
	m := &ThreatModelDoc{System: System{
		Zones: []Zone{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}},
		Components: []Component{
			{ID: "p", Name: "P", Type: "service", Zone: "a"},
			{ID: "q", Name: "Q", Type: "service", Zone: "b"},
			{ID: "x", Name: "X", Type: "service"},
			{ID: "y", Name: "Y", Type: "service"},
		},
		Flows: []Flow{
			{ID: "1", From: "x", To: "y"},                  // not drawn: x and y are the least busy
			{ID: "2", From: "p", To: "q", Authn: "none"},   // 0 drawn, weak
			{ID: "3", From: "q", To: "p", Encrypted: "no"}, // 1 drawn, weak
			{ID: "4", From: "p", To: "q"},                  // 2 drawn
		},
	}}
	d := RenderMermaid(m, 2)
	if !strings.Contains(d.Source, "\n  linkStyle 0,1 stroke:#d33,stroke-width:2px") {
		t.Errorf("the highlight does not follow the drawn edges:\n%s", d.Source)
	}
	if d.Edges != 3 || d.OmittedEdges != 1 || d.Nodes != 2 || d.OmittedNodes != 2 {
		t.Errorf("diagram = %+v", d)
	}
	mmCheckGrammar(t, d.Source)
}

func TestRenderMermaidCapRange(t *testing.T) {
	many := func(n int) *ThreatModelDoc {
		m := &ThreatModelDoc{}
		for i := 0; i < n; i++ {
			m.System.Components = append(m.System.Components, Component{ID: fmt.Sprint("c", i), Name: fmt.Sprint("Part ", i), Type: "service"})
		}
		return m
	}
	tests := []struct {
		name       string
		components int
		max        int
		wantMax    int
		wantNodes  int
	}{
		{"zero reads as the default", 70, 0, DefaultMermaidNodes, DefaultMermaidNodes},
		{"a negative cap reads as the default", 70, -5, DefaultMermaidNodes, DefaultMermaidNodes},
		{"the default is 60", 70, 0, 60, 60},
		{"an explicit cap", 70, 25, 25, 25},
		{"the ceiling is kept", 320, MaxMermaidNodes, MaxMermaidNodes, 300},
		{"above the ceiling reads as the ceiling", 320, 5000, MaxMermaidNodes, 300},
		{"the ceiling is 300", 320, 301, 300, 300},
		{"fewer nodes than the cap", 5, 0, DefaultMermaidNodes, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := RenderMermaid(many(tc.components), tc.max)
			if d.MaxNodes != tc.wantMax || d.Nodes != tc.wantNodes || d.TotalNodes != tc.components || d.OmittedNodes != tc.components-tc.wantNodes {
				t.Errorf("diagram = {max %d nodes %d total %d omitted %d}, want max %d nodes %d total %d",
					d.MaxNodes, d.Nodes, d.TotalNodes, d.OmittedNodes, tc.wantMax, tc.wantNodes, tc.components)
			}
			mmCheckGrammar(t, d.Source)
			if tc.components > tc.wantNodes {
				want := fmt.Sprintf("  %%%% %d nodes and 0 flows are not drawn (cap %d)", tc.components-tc.wantNodes, tc.wantMax)
				if !strings.HasSuffix(d.Source, "\n"+want) {
					t.Errorf("source does not end with %q", want)
				}
			}
		})
	}
	if MaxMermaidNodes != 300 || DefaultMermaidNodes != 60 {
		t.Errorf("the caps moved: default %d max %d", DefaultMermaidNodes, MaxMermaidNodes)
	}
}

func TestRenderMermaidEmpty(t *testing.T) {
	empty := func(max int) MermaidDiagram {
		return MermaidDiagram{Source: "flowchart LR", MaxNodes: max, LabelChars: 40}
	}
	tests := []struct {
		name string
		m    *ThreatModelDoc
		max  int
		want MermaidDiagram
	}{
		{"a nil model", nil, 0, empty(DefaultMermaidNodes)},
		{"a nil model with a cap", nil, 12, empty(12)},
		{"a model with no system", &ThreatModelDoc{}, 0, empty(DefaultMermaidNodes)},
		{
			"flows and actors but no component",
			&ThreatModelDoc{System: System{
				Actors: []Actor{{ID: "u", Name: "U", Kind: "end_user"}},
				Flows:  []Flow{{ID: "f", From: "u", To: "u"}},
			}},
			// Nothing can be drawn, so the one flow is a flow not drawn.
			0, func() MermaidDiagram { d := empty(DefaultMermaidNodes); d.OmittedEdges = 1; return d }(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := RenderMermaid(tc.m, tc.max); got != tc.want {
				t.Errorf("diagram = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestRenderMermaidOddFlows covers flows a validated model never has but a
// stored or hand-built one might: an endpoint that is not in the model, an id
// that is both a component and an actor, an actor in no flow.
func TestRenderMermaidOddFlows(t *testing.T) {
	m := &ThreatModelDoc{System: System{
		Components: []Component{
			{ID: "a", Name: "A", Type: "service"},
			{ID: "both", Name: "Comp", Type: "service"},
			{ID: "a", Name: "Dup", Type: "service"},
		},
		Actors: []Actor{
			{ID: "both", Name: "Actor", Kind: "end_user"},
			{ID: "idle", Name: "Idle", Kind: "service"},
			{ID: "u", Name: "U", Kind: "end_user"},
			{ID: "u", Name: "U again", Kind: "end_user"},
		},
		Flows: []Flow{
			{ID: "1", From: "a", To: "ghost"},
			{ID: "2", From: "ghost", To: "a"},
			{ID: "3", From: "u", To: "both"},
			{ID: "4", From: "a", To: "a"},
		},
	}}
	d := RenderMermaid(m, 0)
	mmCheckGrammar(t, d.Source)
	// Components: c1 A, c2 Comp ("both" reads as the component), c3 Dup (its id
	// repeats, so a flow to "a" reaches c1). Actors: only "u" takes part (a3);
	// "both" is a component, "idle" is in no flow, and the second "u" repeats.
	want := strings.Join([]string{
		"flowchart LR",
		`  c1["A"]`,
		`  c2["Comp"]`,
		`  c3["Dup"]`,
		`  a3(["U"])`,
		`  a3 --> c2`,
		`  c1 --> c1`,
		`  %% 0 nodes and 2 flows are not drawn (cap 60)`,
	}, "\n")
	if d.Source != want {
		t.Errorf("source\n got:\n%s\nwant:\n%s", d.Source, want)
	}
	if d.Nodes != 4 || d.TotalNodes != 4 || d.Edges != 2 || d.OmittedEdges != 2 {
		t.Errorf("diagram = %+v", d)
	}
}

func TestRenderMermaidIsDeterministicAndPure(t *testing.T) {
	m := mmModel()
	before := mmModel()
	first := RenderMermaid(m, 4)
	for i := 0; i < 25; i++ {
		if got := RenderMermaid(m, 4); got != first {
			t.Fatalf("render %d differs:\n%s\nvs\n%s", i, got.Source, first.Source)
		}
	}
	if !reflect.DeepEqual(m, before) {
		t.Error("RenderMermaid changed the model")
	}
	mmCheckGrammar(t, first.Source)
}

// TestRenderMermaidOfAValidatedModel renders a model the validator produced.
func TestRenderMermaidOfAValidatedModel(t *testing.T) {
	res := rdValidated(t, ContractThreatModel, baseThreatModel, func(m map[string]any) {})
	if res.TM == nil {
		t.Fatalf("the model was refused: %+v", res.Report)
	}
	d := RenderMermaid(res.TM, 0)
	mmCheckGrammar(t, d.Source)
	want := strings.Join([]string{
		"flowchart LR",
		`  subgraph z1["DMZ"]`,
		`    c1["API"]`,
		"  end",
		`  subgraph z2["Internal"]`,
		`    c2[("Database")]`,
		`    c3[("Audit log")]`,
		"  end",
		`  a1(["User"])`,
		`  a1 -.->|"https, no authentication"| c1`,
		`  c1 -.->|"not encrypted"| c2`,
		`  linkStyle 0,1 stroke:#d33,stroke-width:2px`,
	}, "\n")
	if d.Source != want {
		t.Errorf("source\n got:\n%s\nwant:\n%s", d.Source, want)
	}
	if d.Nodes != 4 || d.TotalNodes != 4 || d.Edges != 2 {
		t.Errorf("diagram = %+v", d)
	}
}

// TestRenderMermaidDiagramJSON pins the JSON keys the web reads (ModelMermaid in
// secAssessModel.ts).
func TestRenderMermaidDiagramJSON(t *testing.T) {
	d := RenderMermaid(mmModel(), 0)
	got := jsonKeys(t, d)
	want := []string{"edges", "label_chars", "labels_cut", "max_nodes", "nodes", "omitted_edges", "omitted_nodes", "source", "total_nodes"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

// TestRenderMermaidLabelLength: the label length is an option, it is clamped to
// its range, a label is cut only when allowed text was left off, and the diagram
// counts the drawn labels it cut (a node, a zone and a flow's protocol each
// count once).
func TestRenderMermaidLabelLength(t *testing.T) {
	long := strings.Repeat("abcdefghi ", 9) // 89 characters of label text once trimmed
	model := func() *ThreatModelDoc {
		return &ThreatModelDoc{System: System{
			Zones:      []Zone{{ID: "z", Name: long}},
			Components: []Component{{ID: "a", Name: long, Zone: "z"}, {ID: "b", Name: "short"}},
			Flows:      []Flow{{ID: "f", From: "a", To: "b", Protocol: long}},
		}}
	}
	tests := []struct {
		name       string
		chars      int
		wantChars  int
		wantCut    int
		wantLabels int // the longest node label, in runes, never over wantChars
	}{
		{"the default", 0, DefaultMermaidLabelChars, 3, DefaultMermaidLabelChars},
		{"a negative reads as the default", -5, DefaultMermaidLabelChars, 3, DefaultMermaidLabelChars},
		{"twenty", 20, 20, 3, 20},
		{"below the range reads as the lowest", 3, minMermaidLabelChars, 3, minMermaidLabelChars},
		{"the ceiling", MaxMermaidLabelChars, MaxMermaidLabelChars, 0, 89},
		{"above the ceiling reads as the ceiling", 5000, MaxMermaidLabelChars, 0, 89},
		{"exactly the text's length is not a cut", 89, 89, 0, 89},
		{"one short of the text's length is", 88, 88, 3, 88},
	}
	labelRE := regexp.MustCompile(`c1\["([^"]*)"\]`)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := RenderMermaidWith(model(), MermaidOptions{LabelChars: tc.chars})
			if d.LabelChars != tc.wantChars || d.LabelsCut != tc.wantCut {
				t.Errorf("label_chars %d labels_cut %d, want %d and %d\n%s", d.LabelChars, d.LabelsCut, tc.wantChars, tc.wantCut, d.Source)
			}
			m := labelRE.FindStringSubmatch(d.Source)
			if m == nil {
				t.Fatalf("no node label in:\n%s", d.Source)
			}
			if got := len([]rune(m[1])); got > tc.wantLabels {
				t.Errorf("the node label holds %d runes, want at most %d: %q", got, tc.wantLabels, m[1])
			}
			mmCheckGrammar(t, d.Source)
		})
	}

	t.Run("characters a label cannot hold past the cut are not a cut", func(t *testing.T) {
		m := &ThreatModelDoc{System: System{Components: []Component{{ID: "a", Name: strings.Repeat("x", 40) + " !!! <> ``` "}}}}
		if d := RenderMermaid(m, 0); d.LabelsCut != 0 {
			t.Errorf("a label of 40 characters followed by characters a label cannot hold counted as cut: %+v", d)
		}
		m.System.Components[0].Name = strings.Repeat("x", 41)
		if d := RenderMermaid(m, 0); d.LabelsCut != 1 {
			t.Errorf("a label of 41 characters was not counted as cut: %+v", d)
		}
	})

	t.Run("a label that is not drawn is not counted", func(t *testing.T) {
		// Ten components in a ring (two flows each) and two with one flow and a long
		// name: with room for ten nodes the two long ones are the ones left out.
		m := &ThreatModelDoc{}
		for i := 0; i < 12; i++ {
			name := fmt.Sprintf("part %d", i)
			if i >= 10 {
				name = long
			}
			m.System.Components = append(m.System.Components, Component{ID: fmt.Sprintf("c%d", i), Name: name})
		}
		for i := 0; i < 10; i++ {
			m.System.Flows = append(m.System.Flows, Flow{ID: fmt.Sprintf("r%d", i), From: fmt.Sprintf("c%d", i), To: fmt.Sprintf("c%d", (i+1)%10)})
		}
		m.System.Flows = append(m.System.Flows, Flow{ID: "x10", From: "c10", To: "c0"}, Flow{ID: "x11", From: "c11", To: "c0"})
		d := RenderMermaidWith(m, MermaidOptions{MaxNodes: 10})
		if d.Nodes != 10 || d.OmittedNodes != 2 || d.LabelsCut != 0 {
			t.Errorf("two long labels were left out and must not be counted: %+v", d)
		}
	})

	t.Run("a flow's protocol past the length is cut and counted once", func(t *testing.T) {
		m := &ThreatModelDoc{System: System{
			Components: []Component{{ID: "a", Name: "A"}, {ID: "b", Name: "B"}},
			Flows:      []Flow{{ID: "f", From: "a", To: "b", Protocol: strings.Repeat("p", 60), Authn: "none"}},
		}}
		d := RenderMermaid(m, 0)
		if d.LabelsCut != 1 || !strings.Contains(d.Source, "no authentication") {
			t.Errorf("diagram = %+v\n%s", d, d.Source)
		}
	})
}

// TestRenderMermaidWithZeroOptionsIsRenderMermaid: the two entry points agree.
func TestRenderMermaidWithZeroOptionsIsRenderMermaid(t *testing.T) {
	if a, b := RenderMermaid(mmModel(), 0), RenderMermaidWith(mmModel(), MermaidOptions{}); a != b {
		t.Errorf("RenderMermaid and RenderMermaidWith differ: %+v %+v", a, b)
	}
}
