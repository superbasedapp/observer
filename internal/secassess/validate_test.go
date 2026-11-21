package secassess

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

type vcase struct {
	name     string
	contract Contract
	raw      []byte // used instead of the base document when set
	mut      func(m map[string]any)
	opts     func(o *ValidateOptions)
	state    ValidationState
	fatal    string
	want     []string // "V4:bad_id"
	check    func(t *testing.T, r Result)
}

func (c vcase) run(t *testing.T) {
	t.Helper()
	contract := c.contract
	if contract == "" {
		contract = ContractThreatModel
	}
	base := baseThreatModel
	if contract == ContractPentest {
		base = basePentest
	}
	data := c.raw
	if data == nil {
		data = edit(t, base, func(m map[string]any) {
			if c.mut != nil {
				c.mut(m)
			}
		})
	}
	o := optsFor(contract)
	if c.opts != nil {
		c.opts(&o)
	}
	r := Validate(data, o)
	want := c.state
	if want == "" {
		want = ValidationValid
	}
	if r.Report.State != want {
		t.Fatalf("state = %s, want %s (fatal %q) issues: %s", r.Report.State, want, r.Report.Fatal, issueCodes(r.Report))
	}
	if r.Report.Fatal != c.fatal {
		t.Fatalf("fatal = %q, want %q", r.Report.Fatal, c.fatal)
	}
	for _, w := range c.want {
		row, code, _ := strings.Cut(w, ":")
		if !hasIssue(r.Report, row, code) {
			t.Errorf("missing issue %s; got %s", w, issueCodes(r.Report))
		}
	}
	if c.check != nil {
		c.check(t, r)
	}
}

func TestValidateFile(t *testing.T) {
	deep := strings.Repeat("[", MaxModelDepth+1) + strings.Repeat("]", MaxModelDepth+1)
	cases := []vcase{
		{name: "V1 over the size cap", raw: bytes.Repeat([]byte(" "), MaxModelBytes+1), state: ValidationInvalid, fatal: "too_large", want: []string{"V1:too_large"}},
		{name: "V1 over the depth cap", raw: []byte(deep), state: ValidationInvalid, fatal: "too_deep", want: []string{"V1:too_deep"}},
		{name: "V2 empty file", raw: []byte(""), state: ValidationInvalid, fatal: "not_json", want: []string{"V2:not_json"}},
		{name: "V2 not json", raw: []byte("{nope"), state: ValidationInvalid, fatal: "not_json", want: []string{"V2:not_json"}},
		{name: "V2 trailing value", raw: []byte(baseThreatModel + "{}"), state: ValidationInvalid, fatal: "trailing_data", want: []string{"V2:trailing_data"}},
		{name: "V2 not an object", raw: []byte("[1]"), state: ValidationInvalid, fatal: "not_object", want: []string{"V2:not_object"}},
		{name: "V2 other schema", mut: func(m map[string]any) { m["schema"] = SchemaPentest }, state: ValidationInvalid, fatal: "schema_mismatch", want: []string{"V2:schema_mismatch"}},
		{name: "V2 other run", mut: func(m map[string]any) { m["run_id"] = "ffffffffffffffff" }, state: ValidationInvalid, fatal: "run_id_mismatch", want: []string{"V2:run_id_mismatch"}},
		{name: "V2 wrong type", mut: func(m map[string]any) { threat(m, 0)["rating"] = map[string]any{"likelihood": "four", "impact": 4} }, state: ValidationInvalid, fatal: "bad_shape", want: []string{"V2:bad_shape"}},
		{name: "V2 kind without a model", contract: ContractSARIF, state: ValidationInvalid, fatal: "no_model_contract", want: []string{"V2:no_model_contract"}},
		{name: "a valid threat model", check: func(t *testing.T, r Result) {
			if r.TM == nil || r.PT != nil || len(r.TM.Threats) != 2 || r.Report.Fatal != "" {
				t.Fatalf("result = %+v", r)
			}
		}},
		{name: "a valid pen test", contract: ContractPentest, check: func(t *testing.T, r Result) {
			if r.PT == nil || r.TM != nil || len(r.PT.Findings) != 1 {
				t.Fatalf("result = %+v", r)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateRefusedFileKeepsNoModel(t *testing.T) {
	r := Validate([]byte("{nope"), optsFor(ContractThreatModel))
	if r.TM != nil || r.PT != nil || r.Report.State != ValidationInvalid {
		t.Fatalf("result = %+v", r)
	}
}

// manyComponents adds n components named c0..c(n-1).
func manyComponents(n int) func(m map[string]any) {
	return func(m map[string]any) {
		var cs []any
		for i := 0; i < n; i++ {
			cs = append(cs, map[string]any{"id": fmt.Sprintf("c%d", i), "name": "C", "type": "service"})
		}
		sys(m)["components"] = cs
		m["threats"], m["no_threat"] = nil, nil
		sys(m)["flows"], sys(m)["entry_points"], sys(m)["assets"] = nil, nil, nil
	}
}

func TestValidateCaps(t *testing.T) {
	cases := []vcase{
		{name: "V3 on the cap is accepted", mut: manyComponents(maxComponents), check: func(t *testing.T, r Result) {
			if c := r.Report.Counts["components"]; c.Read != maxComponents || c.Kept != maxComponents || c.LeftOut != 0 {
				t.Fatalf("components count = %+v", c)
			}
			if hasIssue(r.Report, "V3", "cap_exceeded") {
				t.Fatal("a cap issue on a collection exactly at its cap")
			}
		}},
		{name: "V3 one past the cap", mut: manyComponents(maxComponents + 1), state: ValidationPartial, want: []string{"V3:cap_exceeded"}, check: func(t *testing.T, r Result) {
			c := r.Report.Counts["components"]
			if c.Read != maxComponents+1 || c.LeftOut != 1 || c.Kept != maxComponents {
				t.Fatalf("components count = %+v", c)
			}
			if len(r.TM.System.Components) != maxComponents {
				t.Fatalf("kept %d components", len(r.TM.System.Components))
			}
		}},
		{name: "V3 refs of an item past the per-item bound", state: ValidationPartial, want: []string{"V3:cap_exceeded"}, mut: func(m map[string]any) {
			var rs []any
			for i := 0; i <= maxPerItemList; i++ {
				rs = append(rs, map[string]any{"path": "cmd/api/main.go", "line": 12})
			}
			obj(arr(threat(m, 0)["missing"])[0])["refs"] = rs
		}, check: func(t *testing.T, r Result) {
			if n := len(r.TM.Threats[0].Missing[0].Refs); n != maxPerItemList {
				t.Fatalf("kept %d refs", n)
			}
		}},
		// Review M4b: the findings themselves are bounded by the file's byte cap and
		// nothing else (the model's missing mitigations are what an import derives).
		{name: "V3 no count cap on the missing mitigations of a threat", mut: func(m map[string]any) {
			var ms []any
			for i := 0; i < 3*maxPerItemList; i++ {
				ms = append(ms, map[string]any{"text": fmt.Sprintf("Do thing %d", i)})
			}
			threat(m, 0)["missing"] = ms
		}, check: func(t *testing.T, r Result) {
			if n := len(r.TM.Threats[0].Missing); n != 3*maxPerItemList || hasIssue(r.Report, "V3", "cap_exceeded") {
				t.Fatalf("kept %d mitigations: %s", n, issueCodes(r.Report))
			}
		}},
		{name: "V3 no count cap on threats or no-threat rows", mut: func(m map[string]any) {
			var ts, ns []any
			for i := 0; i < 350; i++ {
				ts = append(ts, map[string]any{
					"id": fmt.Sprintf("T-%d", i), "title": "A threat", "framework": "stride", "category": "tampering",
					"element": map[string]any{"kind": "component", "id": "api"}, "rating": map[string]any{"likelihood": 2, "impact": 2},
				})
			}
			for i := 0; i < 450; i++ {
				ns = append(ns, map[string]any{
					"element": map[string]any{"kind": "component", "id": "api"}, "category": "denial_of_service", "reason": fmt.Sprintf("Reason %d", i),
				})
			}
			m["threats"], m["no_threat"] = ts, ns
		}, check: func(t *testing.T, r Result) {
			if c := r.Report.Counts["threats"]; c.Read != 350 || c.Kept != 350 || c.LeftOut != 0 {
				t.Fatalf("threats = %+v", c)
			}
			if c := r.Report.Counts["no_threat"]; c.Read != 450 || c.LeftOut != 0 {
				t.Fatalf("no_threat = %+v", c)
			}
			if hasIssue(r.Report, "V3", "cap_exceeded") {
				t.Fatal("a count cap fired on threats or no-threat rows")
			}
		}},
		{name: "V3 tree nodes past the cap", state: ValidationPartial, want: []string{"V3:cap_exceeded"}, mut: func(m map[string]any) {
			var ns []any
			for i := 0; i <= maxTreeNodes; i++ {
				ns = append(ns, map[string]any{"id": fmt.Sprintf("n%d", i), "label": "Step"})
			}
			obj(arr(m["attack_trees"])[0])["nodes"] = ns
		}, check: func(t *testing.T, r Result) {
			if c := r.Report.Counts["tree_nodes"]; c.LeftOut != 1 || c.Kept != maxTreeNodes {
				t.Fatalf("tree_nodes = %+v", c)
			}
		}},
		{name: "V3 no count cap on pen test findings", contract: ContractPentest, mut: func(m map[string]any) {
			var fs []any
			for i := 0; i < 250; i++ {
				f := map[string]any{}
				b, _ := json.Marshal(finding(m, 0))
				_ = json.Unmarshal(b, &f)
				f["id"] = fmt.Sprintf("F-%d", i)
				fs = append(fs, f)
			}
			m["findings"] = fs
		}, check: func(t *testing.T, r Result) {
			if c := r.Report.Counts["findings"]; c.Read != 250 || c.Kept != 250 || hasIssue(r.Report, "V3", "cap_exceeded") {
				t.Fatalf("findings = %+v %s", c, issueCodes(r.Report))
			}
		}},
		{name: "V1 the size cap is the setting", contract: ContractPentest, check: func(t *testing.T, r Result) {
			o := optsFor(ContractPentest)
			o.MaxBytes = 1 << 10
			if got := Validate([]byte(basePentest), o).Report.Fatal; got != "too_large" {
				t.Fatalf("a file over a lowered cap: %q", got)
			}
			o.MaxBytes = 1 << 40
			if o.ModelCap() != MaxModelBytesCeiling {
				t.Fatalf("a cap above the ceiling reads as %d", o.ModelCap())
			}
			if got := Validate([]byte(basePentest), o).Report.State; got != ValidationValid {
				t.Fatalf("a file under the raised cap: %s", got)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateIDs(t *testing.T) {
	cases := []vcase{
		{name: "V4 bad characters", state: ValidationPartial, want: []string{"V4:bad_id"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["zones"])[0])["id"] = "bad id!"
		}},
		{name: "V4 empty id", state: ValidationPartial, want: []string{"V4:bad_id"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["actors"])[0])["id"] = ""
		}},
		{name: "V4 id too long", state: ValidationPartial, want: []string{"V4:bad_id"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["zones"])[0])["id"] = strings.Repeat("a", 49)
		}},
		{name: "V4 duplicate in a collection", state: ValidationPartial, want: []string{"V4:duplicate_id"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["zones"])[1])["id"] = "dmz"
		}},
		{name: "V4 the same id in two collections is allowed", mut: func(m map[string]any) {
			obj(arr(sys(m)["zones"])[1])["id"] = "user"
			for _, c := range arr(sys(m)["components"]) {
				if z := obj(c); z["zone"] == "internal" {
					z["zone"] = "user"
				}
			}
		}},
		{name: "V4 duplicate coverage category", contract: ContractPentest, state: ValidationPartial, want: []string{"V4:duplicate_category"}, mut: func(m map[string]any) {
			obj(arr(m["coverage"])[1])["category"] = "ATHN"
		}},
		{name: "V4 duplicate finding id", contract: ContractPentest, state: ValidationPartial, want: []string{"V4:duplicate_id"}, mut: func(m map[string]any) {
			f := map[string]any{}
			b, _ := json.Marshal(finding(m, 0))
			_ = json.Unmarshal(b, &f)
			m["findings"] = append(arr(m["findings"]), f)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateEnums(t *testing.T) {
	cases := []vcase{
		{name: "V5 component type", state: ValidationPartial, want: []string{"V5:bad_enum", "V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["components"])[0])["type"] = "spaceship"
		}},
		{name: "V5 actor kind", state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["actors"])[0])["kind"] = "alien"
		}},
		{name: "V5 asset sensitivity", state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["assets"])[0])["sensitivity"] = "spicy"
		}},
		{name: "V5 entry point kind", state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["entry_points"])[0])["kind"] = "portal"
		}},
		{name: "V5 optional authn is dropped, the item stays", want: []string{"V5:bad_enum_dropped"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["entry_points"])[0])["authn"] = "magic"
		}, check: func(t *testing.T, r Result) {
			if len(r.TM.System.EntryPoints) != 1 || r.TM.System.EntryPoints[0].Authn != "" {
				t.Fatalf("entry points = %+v", r.TM.System.EntryPoints)
			}
		}},
		{name: "V5 optional encrypted is dropped", want: []string{"V5:bad_enum_dropped"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["flows"])[0])["encrypted"] = "maybe"
		}},
		{name: "V5 framework", state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			threat(m, 0)["framework"] = "dread"
		}},
		{name: "V5 category of another framework", state: ValidationPartial, want: []string{"V5:bad_category"}, mut: func(m map[string]any) {
			threat(m, 0)["category"] = "linkability"
		}},
		{name: "V5 AI category shape", state: ValidationPartial, want: []string{"V5:bad_category"}, mut: func(m map[string]any) {
			threat(m, 0)["framework"], threat(m, 0)["category"] = "owasp_llm", "LLM11"
		}},
		{name: "V5 AI category accepted by shape", mut: func(m map[string]any) {
			threat(m, 0)["framework"], threat(m, 0)["category"] = "owasp_agentic", "ASI04"
		}},
		{name: "V5 element kind", state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			threat(m, 0)["element"] = map[string]any{"kind": "planet", "id": "api"}
		}},
		{name: "V5 rating zero", state: ValidationPartial, want: []string{"V5:bad_rating"}, mut: func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": 0, "impact": 3}
		}},
		{name: "V5 rating six", state: ValidationPartial, want: []string{"V5:bad_rating"}, mut: func(m map[string]any) {
			threat(m, 0)["rating"] = map[string]any{"likelihood": 3, "impact": 6}
		}},
		{name: "V5 optional status dropped", want: []string{"V5:bad_enum_dropped"}, mut: func(m map[string]any) {
			threat(m, 0)["status"] = "fixed"
		}},
		{name: "V5 effort dropped", want: []string{"V5:bad_enum_dropped"}, mut: func(m map[string]any) {
			obj(arr(threat(m, 0)["missing"])[0])["effort"] = "xl"
		}},
		{name: "V5 malformed cwe dropped", want: []string{"V5:bad_standard_id"}, mut: func(m map[string]any) {
			threat(m, 0)["cwe"] = []any{"CWE-0", "CWE-89", "cwe-79", "CWE-1234567"}
		}, check: func(t *testing.T, r Result) {
			if got := strings.Join(r.TM.Threats[0].CWE, ","); got != "CWE-89" {
				t.Fatalf("cwe = %s", got)
			}
		}},
		{name: "V5 no_threat category", state: ValidationPartial, want: []string{"V5:bad_category"}, mut: func(m map[string]any) {
			obj(arr(m["no_threat"])[0])["category"] = "chaos"
		}},
		{name: "V5 tree op dropped", want: []string{"V5:bad_enum_dropped"}, mut: func(m map[string]any) {
			obj(arr(obj(arr(m["attack_trees"])[0])["nodes"])[0])["op"] = "xor"
		}},
		{name: "V5 pen test category", contract: ContractPentest, state: ValidationPartial, want: []string{"V5:bad_category"}, mut: func(m map[string]any) {
			obj(arr(m["coverage"])[0])["category"] = "ZZZZ"
		}},
		{name: "V5 pen test coverage status", contract: ContractPentest, state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			obj(arr(m["coverage"])[0])["status"] = "done"
		}},
		{name: "V5 pen test basis", contract: ContractPentest, state: ValidationPartial, want: []string{"V5:bad_enum"}, mut: func(m map[string]any) {
			finding(m, 0)["basis"] = "hunch"
		}},
		{name: "V5 pen test rating", contract: ContractPentest, state: ValidationPartial, want: []string{"V5:bad_rating"}, mut: func(m map[string]any) {
			finding(m, 0)["rating"] = map[string]any{"likelihood": 9, "impact": 1}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateText(t *testing.T) {
	cases := []vcase{
		{name: "V6 empty required text", state: ValidationPartial, want: []string{"V6:empty_text"}, mut: func(m map[string]any) {
			threat(m, 0)["title"] = "  \t "
		}},
		{name: "V6 empty mitigation is refused alone", state: ValidationPartial, want: []string{"V6:empty_text"}, mut: func(m map[string]any) {
			obj(arr(threat(m, 0)["missing"])[0])["text"] = ""
		}, check: func(t *testing.T, r Result) {
			if len(r.TM.Threats) != 2 || len(r.TM.Threats[0].Missing) != 0 {
				t.Fatalf("threats = %+v", r.TM.Threats)
			}
		}},
		{name: "V6 long text is cut and counted", want: []string{"V6:text_truncated"}, mut: func(m map[string]any) {
			threat(m, 0)["description"] = strings.Repeat("word ", 200)
		}, check: func(t *testing.T, r Result) {
			if n := utf8.RuneCountInString(r.TM.Threats[0].Description); n > capDescription {
				t.Fatalf("description has %d runes", n)
			}
		}},
		{name: "V6 abuse case without a goal is dropped", want: []string{"V6:abuse_case_dropped"}, mut: func(m map[string]any) {
			threat(m, 0)["abuse_case"] = map[string]any{"actor": "x"}
		}, check: func(t *testing.T, r Result) {
			if r.TM.Threats[0].AbuseCase != nil {
				t.Fatal("abuse case kept")
			}
		}},
		{name: "V6 scope path that is not relative", want: []string{"V6:scope_path_dropped"}, mut: func(m map[string]any) {
			obj(m["scope"])["in_scope"] = []any{"../etc", "cmd/api", "/abs"}
		}, check: func(t *testing.T, r Result) {
			if got := strings.Join(r.TM.Scope.InScope, ","); got != "cmd/api" {
				t.Fatalf("in_scope = %s", got)
			}
		}},
		{name: "V6 fence lookalike is shrunk", mut: func(m map[string]any) {
			threat(m, 0)["title"] = "Bad ----- END FINDINGS (scanner data) " + cp(0x2014, 0x2014, 0x2014, 0x2014, 0x2014) + " more `ticks`"
		}, check: func(t *testing.T, r Result) {
			title := r.TM.Threats[0].Title
			if strings.Contains(title, "---") || strings.Contains(title, "`") || strings.Contains(title, cp(0x2014, 0x2014, 0x2014)) {
				t.Fatalf("title = %q", title)
			}
		}},
		{name: "V6 control characters and newlines", mut: func(m map[string]any) {
			threat(m, 0)["description"] = "line one\nline two\x00" + cp(0x202e) + " hidden"
		}, check: func(t *testing.T, r Result) {
			if d := r.TM.Threats[0].Description; strings.ContainsAny(d, "\n\x00"+cp(0x202e)) {
				t.Fatalf("description = %q", d)
			}
		}},
		{name: "V6 redactor runs on every text", opts: func(o *ValidateOptions) {
			o.Redact = func(s string) string { return strings.ReplaceAll(s, "hunter2", "[REDACTED]") }
		}, mut: func(m map[string]any) {
			threat(m, 0)["description"] = "The password is hunter2 in the source."
			obj(arr(threat(m, 0)["missing"])[0])["text"] = "Remove hunter2"
			m["summary"] = "hunter2"
		}, check: func(t *testing.T, r Result) {
			b, _ := json.Marshal(r)
			if bytes.Contains(b, []byte("hunter2")) {
				t.Fatalf("the secret survived in %s", b)
			}
			if !strings.Contains(r.TM.Threats[0].Description, "[REDACTED]") {
				t.Fatalf("description = %q", r.TM.Threats[0].Description)
			}
		}},
		{name: "V6 pen test texts", contract: ContractPentest, want: []string{"V6:text_truncated"}, state: ValidationPartial, mut: func(m map[string]any) {
			finding(m, 0)["impact"] = strings.Repeat("x ", 500)
			finding(m, 0)["reproduction"] = []any{map[string]any{"step": "", "request": "GET /"}, map[string]any{"step": "ok", "request": "GET /"}}
		}, check: func(t *testing.T, r Result) {
			if n := len(r.PT.Findings[0].Reproduction); n != 1 {
				t.Fatalf("kept %d reproduction steps", n)
			}
		}},
		{name: "V6 argv is redacted", contract: ContractPentest, opts: func(o *ValidateOptions) {
			o.Redact = func(s string) string { return strings.ReplaceAll(s, "sekrit", "[REDACTED]") }
		}, mut: func(m map[string]any) {
			obj(obj(m["target"])["start"])["argv"] = []any{"env", "TOKEN=sekrit", "node"}
		}, check: func(t *testing.T, r Result) {
			if got := strings.Join(r.PT.Target.Start.Argv, " "); strings.Contains(got, "sekrit") {
				t.Fatalf("argv = %s", got)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateReferences(t *testing.T) {
	cases := []vcase{
		{name: "V7 entry point of no component", state: ValidationPartial, want: []string{"V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["entry_points"])[0])["component"] = "nope"
		}, check: func(t *testing.T, r Result) {
			if len(r.TM.System.EntryPoints) != 0 {
				t.Fatal("entry point kept")
			}
		}},
		{name: "V7 unknown zone is cleared", want: []string{"V7:dangling_reference_dropped"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["components"])[0])["zone"] = "ghost"
		}, check: func(t *testing.T, r Result) {
			if z := r.TM.System.Components[0].Zone; z != "" {
				t.Fatalf("zone = %q", z)
			}
		}},
		{name: "V7 stored_in entry dropped", want: []string{"V7:dangling_reference_dropped"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["assets"])[0])["stored_in"] = []any{"db", "ghost"}
		}, check: func(t *testing.T, r Result) {
			if got := strings.Join(r.TM.System.Assets[0].StoredIn, ","); got != "db" {
				t.Fatalf("stored_in = %s", got)
			}
		}},
		{name: "V7 flow endpoint is nothing", state: ValidationPartial, want: []string{"V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["flows"])[1])["to"] = "ghost"
		}},
		{name: "V7 flow endpoint is a component and an actor", state: ValidationPartial, want: []string{"V7:ambiguous_endpoint"}, mut: func(m map[string]any) {
			sys(m)["actors"] = append(arr(sys(m)["actors"]), map[string]any{"id": "api", "name": "API actor", "kind": "service"})
		}},
		{name: "V7 flow data and crosses entries dropped", want: []string{"V7:dangling_reference_dropped"}, mut: func(m map[string]any) {
			f := obj(arr(sys(m)["flows"])[0])
			f["data"], f["crosses"] = []any{"creds", "ghost"}, []any{"dmz", "ghost"}
		}},
		{name: "V7 threat about nothing", state: ValidationPartial, want: []string{"V7:dangling_reference"}, mut: func(m map[string]any) {
			threat(m, 0)["element"] = map[string]any{"kind": "flow", "id": "ghost"}
		}},
		{name: "V7 threat actor cleared", want: []string{"V7:dangling_reference_dropped"}, mut: func(m map[string]any) {
			threat(m, 0)["actor"] = "ghost"
		}, check: func(t *testing.T, r Result) {
			if r.TM.Threats[0].Actor != "" {
				t.Fatal("actor kept")
			}
		}},
		{name: "V7 no_threat about nothing", state: ValidationPartial, want: []string{"V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(m["no_threat"])[0])["element"] = map[string]any{"kind": "component", "id": "ghost"}
		}},
		{name: "V7 a refused component takes its flows and threats with it", state: ValidationPartial, want: []string{"V5:bad_enum", "V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(sys(m)["components"])[0])["type"] = "nope"
		}, check: func(t *testing.T, r Result) {
			if len(r.TM.Threats) != 0 {
				t.Fatalf("threats = %+v", r.TM.Threats)
			}
		}},
		{name: "V7 attack tree parent that is not a node", state: ValidationPartial, want: []string{"V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(obj(arr(m["attack_trees"])[0])["nodes"])[0])["parent"] = "ghost"
		}},
		{name: "V7 attack tree orphans cascade", state: ValidationPartial, want: []string{"V7:dangling_reference"}, mut: func(m map[string]any) {
			obj(arr(m["attack_trees"])[0])["nodes"] = []any{
				map[string]any{"id": "a", "label": "A", "parent": "ghost"},
				map[string]any{"id": "b", "label": "B", "parent": "a"},
				map[string]any{"id": "c", "label": "C"},
			}
		}, check: func(t *testing.T, r Result) {
			if n := len(r.TM.AttackTrees[0].Nodes); n != 1 {
				t.Fatalf("kept %d nodes", n)
			}
		}},
		{name: "V7 attack tree cycle", state: ValidationPartial, want: []string{"V7:tree_too_deep_or_cyclic"}, mut: func(m map[string]any) {
			obj(arr(m["attack_trees"])[0])["nodes"] = []any{
				map[string]any{"id": "a", "label": "A", "parent": "b"},
				map[string]any{"id": "b", "label": "B", "parent": "a"},
				map[string]any{"id": "c", "label": "C"},
			}
		}, check: func(t *testing.T, r Result) {
			if n := len(r.TM.AttackTrees[0].Nodes); n != 1 {
				t.Fatalf("kept %d nodes", n)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateRefStates(t *testing.T) {
	setRef := func(r map[string]any) func(m map[string]any) {
		return func(m map[string]any) {
			obj(arr(threat(m, 0)["missing"])[0])["refs"] = []any{r}
		}
	}
	state := func(t *testing.T, r Result) RefState { return r.TM.Threats[0].Missing[0].Refs[0].State }
	cases := []struct {
		name string
		ref  map[string]any
		opts func(o *ValidateOptions)
		want RefState
		code string
	}{
		{"needle on the cited line", map[string]any{"path": "cmd/api/main.go", "line": 12, "needle": "func Login("}, nil, RefFound, ""},
		{"needle in a range", map[string]any{"path": "cmd/api/main.go", "line": 10, "end_line": 14, "needle": "func Login("}, nil, RefFound, ""},
		{"needle absent", map[string]any{"path": "cmd/api/main.go", "line": 12, "needle": "func Logout()"}, nil, RefClaimedNotFound, "ref_needle_not_found"},
		{"needle on the next line is outside the cite", map[string]any{"path": "cmd/api/main.go", "line": 11, "needle": "func Login("}, nil, RefClaimedNotFound, "ref_needle_not_found"},
		{"no needle", map[string]any{"path": "cmd/api/main.go", "line": 12}, nil, RefExists, ""},
		{"weak needle", map[string]any{"path": "cmd/api/main.go", "line": 12, "needle": "func"}, nil, RefExists, "ref_needle_weak"},
		{"needle with no identifier", map[string]any{"path": "cmd/api/main.go", "line": 12, "needle": "(((((((("}, nil, RefExists, "ref_needle_weak"},
		{"needle without a line", map[string]any{"path": "cmd/api/main.go", "needle": "func Login("}, nil, RefExists, "ref_needle_needs_line"},
		{"file level", map[string]any{"path": "cmd/api/main.go"}, nil, RefExists, ""},
		{"path with backslashes", map[string]any{"path": "cmd\\api\\main.go", "line": 12}, nil, RefExists, ""},
		{"path escaping the project", map[string]any{"path": "../secret", "line": 1}, nil, RefInvalid, "ref_path_refused"},
		{"absolute path", map[string]any{"path": "/etc/passwd", "line": 1}, nil, RefInvalid, "ref_path_refused"},
		{"backwards range", map[string]any{"path": "cmd/api/main.go", "line": 12, "end_line": 3}, nil, RefInvalid, "ref_range_invalid"},
		{"negative line", map[string]any{"path": "cmd/api/main.go", "line": -4}, nil, RefInvalid, "ref_range_invalid"},
		{"range without a start", map[string]any{"path": "cmd/api/main.go", "end_line": 4}, nil, RefInvalid, "ref_range_invalid"},
		{"range over the span cap", map[string]any{"path": "cmd/api/main.go", "line": 1, "end_line": 1 + maxRefSpan + 1}, nil, RefInvalid, "ref_range_long"},
		{"range on the span cap", map[string]any{"path": "cmd/api/main.go", "line": 1, "end_line": 1 + maxRefSpan}, nil, RefMissing, "ref_line_past_end"},
		{"missing file", map[string]any{"path": "cmd/none.go", "line": 1}, nil, RefMissing, "ref_file_missing"},
		{"line past the end", map[string]any{"path": "cmd/api/main.go", "line": 31}, nil, RefMissing, "ref_line_past_end"},
		{"range past the end", map[string]any{"path": "cmd/api/main.go", "line": 29, "end_line": 31}, nil, RefMissing, "ref_line_past_end"},
		{"budget used up", map[string]any{"path": "cmd/api/main.go", "line": 12}, func(o *ValidateOptions) { o.Refs.(*fakeProject).budget = map[string]bool{"cmd/api/main.go": true} }, RefUnchecked, "ref_budget"},
		{"no checker", map[string]any{"path": "cmd/api/main.go", "line": 12}, func(o *ValidateOptions) { o.Refs = nil }, RefUnchecked, "ref_no_checker"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := edit(t, baseThreatModel, setRef(tc.ref))
			o := optsFor(ContractThreatModel)
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := Validate(data, o)
			if r.TM == nil {
				t.Fatalf("refused: %s", issueCodes(r.Report))
			}
			if got := state(t, r); got != tc.want {
				t.Fatalf("state = %s, want %s", got, tc.want)
			}
			if tc.code != "" && !hasIssue(r.Report, "V8", tc.code) {
				t.Fatalf("missing V8:%s in %s", tc.code, issueCodes(r.Report))
			}
		})
	}
}

func TestValidateRefTallyAndMemo(t *testing.T) {
	o := optsFor(ContractThreatModel)
	r := Validate([]byte(baseThreatModel), o)
	if r.Report.State != ValidationValid {
		t.Fatalf("state = %s: %s", r.Report.State, issueCodes(r.Report))
	}
	// The component path, the existing mitigation and the missing mitigation
	// carry a needle that is on the cited line; the entry point has none.
	want := RefTally{Found: 3, Exists: 1}
	if r.Report.Refs != want {
		t.Fatalf("refs = %+v, want %+v", r.Report.Refs, want)
	}
	// The component path and the missing mitigation cite the same place with
	// the same needle: one lookup serves both.
	if calls := o.Refs.(*fakeProject).calls; calls != 3 {
		t.Fatalf("%d lookups, want 3", calls)
	}
}

func TestValidateScope(t *testing.T) {
	cases := []vcase{
		{name: "V9 scope inside the plan", opts: func(o *ValidateOptions) { o.ScopePaths = []string{"cmd"} }, check: func(t *testing.T, r Result) {
			if hasIssue(r.Report, "V9", "scope_outside_plan") {
				t.Fatal("a scope issue for a path inside the plan")
			}
		}},
		{name: "V9 scope outside the plan", opts: func(o *ValidateOptions) { o.ScopePaths = []string{"internal"} }, want: []string{"V9:scope_outside_plan"}},
		{name: "V9 prefix is not containment", opts: func(o *ValidateOptions) { o.ScopePaths = []string{"cmd/ap"} }, want: []string{"V9:scope_outside_plan"}},
		{name: "V9 root scope means everything", opts: func(o *ValidateOptions) { o.ScopePaths = []string{"."} }, check: func(t *testing.T, r Result) {
			if hasIssue(r.Report, "V9", "scope_outside_plan") {
				t.Fatal("scope issue under a root scope")
			}
		}},
		{name: "V9 target differs", contract: ContractPentest, opts: func(o *ValidateOptions) { o.TargetURL = "http://127.0.0.1:4000/" }, want: []string{"V9:target_differs"}},
		{name: "V9 target equal", contract: ContractPentest, opts: func(o *ValidateOptions) { o.TargetURL = "http://127.0.0.1:3000/" }, check: func(t *testing.T, r Result) {
			if hasIssue(r.Report, "V9", "target_differs") {
				t.Fatal("target issue for the confirmed target")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateComputedFields(t *testing.T) {
	c := vcase{name: "V10 band is computed, never read", mut: func(m map[string]any) {
		threat(m, 0)["band"], threat(m, 0)["score"] = "low", 1
		threat(m, 1)["band"], threat(m, 1)["risk"] = "critical", "9.9"
		obj(arr(obj(arr(threat(m, 0)["missing"])[0])["refs"])[0])["state"] = "found"
		obj(arr(sys(m)["components"])[0])["verified"] = true
	}, check: func(t *testing.T, r Result) {
		if b := r.TM.Threats[0]; b.Band != BandHigh || b.Score != 16 {
			t.Fatalf("T-1 band %s score %d", b.Band, b.Score)
		}
		if b := r.TM.Threats[1]; b.Band != BandLow || b.Score != 6 {
			t.Fatalf("T-2 band %s score %d", b.Band, b.Score)
		}
		if r.Report.Ignored != 6 {
			t.Fatalf("ignored = %d (%v)", r.Report.Ignored, r.Report.IgnoredKeys)
		}
		joined := strings.Join(r.Report.IgnoredKeys, ";")
		for _, k := range []string{".threats[].band (2)", ".threats[].score (1)", ".threats[].risk (1)"} {
			if !strings.Contains(joined, k) {
				t.Errorf("ignored keys %q lack %q", joined, k)
			}
		}
	}}
	t.Run(c.name, c.run)
}

func TestValidateUnknownFieldsAreCaseSensitive(t *testing.T) {
	data := edit(t, baseThreatModel, func(m map[string]any) {
		m["Threats"] = []any{}
		m["Band"] = "x"
	})
	r := Validate(data, optsFor(ContractThreatModel))
	if r.Report.Ignored != 2 || len(r.TM.Threats) != 2 {
		t.Fatalf("ignored %d, threats %d", r.Report.Ignored, len(r.TM.Threats))
	}
}

func TestValidateThreatModelCoverage(t *testing.T) {
	cases := []struct {
		name  string
		opts  func(o *ValidateOptions)
		mut   func(m map[string]any)
		cells [4]int // analysed, waived, empty, linddun cells
	}{
		// api 6 + db 3 + audit 4 (log store) + user 2 + f1 3 + f2 3 stride cells = 21,
		// f1 carries personal data: 7 LINDDUN cells. Two threats analyse a cell, one
		// no_threat waives one.
		{"all frameworks", nil, nil, [4]int{2, 1, 25, 7}},
		{"stride only", func(o *ValidateOptions) { o.Frameworks = []string{FrameworkSTRIDE} }, nil, [4]int{2, 1, 18, 0}},
		{"nil frameworks means all", func(o *ValidateOptions) { o.Frameworks = nil }, nil, [4]int{2, 1, 25, 7}},
		{"a threat in a linddun cell", nil, func(m map[string]any) {
			m["threats"] = append(arr(m["threats"]), map[string]any{
				"id": "T-3", "title": "Linkable", "framework": "linddun", "category": "linkability",
				"element": map[string]any{"kind": "flow", "id": "f1"}, "rating": map[string]any{"likelihood": 2, "impact": 2},
			})
		}, [4]int{3, 1, 24, 7}},
		{"a waiver does not beat a threat", nil, func(m map[string]any) {
			m["no_threat"] = append(arr(m["no_threat"]), map[string]any{"element": map[string]any{"kind": "component", "id": "api"}, "category": "spoofing", "reason": "Considered."})
		}, [4]int{2, 1, 25, 7}},
		{"a waiver of a cell that does not apply counts nothing", nil, func(m map[string]any) {
			m["no_threat"] = append(arr(m["no_threat"]), map[string]any{"element": map[string]any{"kind": "component", "id": "db"}, "category": "spoofing", "reason": "Considered."})
		}, [4]int{2, 1, 25, 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := edit(t, baseThreatModel, func(m map[string]any) {
				if tc.mut != nil {
					tc.mut(m)
				}
			})
			o := optsFor(ContractThreatModel)
			if tc.opts != nil {
				tc.opts(&o)
			}
			r := Validate(data, o)
			cov := r.Report.TM
			if cov == nil {
				t.Fatalf("no coverage: %s", issueCodes(r.Report))
			}
			if cov.Analysed != tc.cells[0] || cov.Waived != tc.cells[1] || cov.Empty != tc.cells[2] {
				t.Fatalf("analysed %d waived %d empty %d, want %v", cov.Analysed, cov.Waived, cov.Empty, tc.cells)
			}
			linddun := 0
			for _, f := range cov.ByFramework {
				if f.Framework == FrameworkLINDDUN {
					linddun = f.Analysed + f.Waived + f.Empty
				}
			}
			if linddun != tc.cells[3] {
				t.Fatalf("linddun cells %d, want %d", linddun, tc.cells[3])
			}
			total := 0
			for _, row := range cov.Rows {
				total += len(row.Cells)
			}
			if total != cov.Analysed+cov.Waived+cov.Empty {
				t.Fatalf("rows hold %d cells, totals %d", total, cov.Analysed+cov.Waived+cov.Empty)
			}
		})
	}
}

func TestValidateAIThreatsAreCounted(t *testing.T) {
	data := edit(t, baseThreatModel, func(m map[string]any) {
		m["threats"] = append(arr(m["threats"]), map[string]any{
			"id": "T-3", "title": "Prompt injection", "framework": "owasp_llm", "category": "LLM01",
			"element": map[string]any{"kind": "component", "id": "api"}, "rating": map[string]any{"likelihood": 3, "impact": 3},
		})
	})
	o := optsFor(ContractThreatModel)
	o.AIApp = true
	r := Validate(data, o)
	if r.Report.TM.AIThreats[FrameworkOWASPLLM] != 1 || !r.Report.Sets.AIApp {
		t.Fatalf("coverage = %+v sets = %+v", r.Report.TM, r.Report.Sets)
	}
}

func TestValidateMethodExtras(t *testing.T) {
	cases := []vcase{
		{name: "V12 a top threat with no abuse case", want: []string{"V12:abuse_case_missing"}},
		{name: "V12 off when the extra is not in force", opts: func(o *ValidateOptions) { o.MethodExtras = nil }, check: func(t *testing.T, r Result) {
			if hasIssue(r.Report, "V12", "abuse_case_missing") {
				t.Fatal("abuse case issue with the extra off")
			}
		}},
		{name: "V12 every top threat has one", mut: func(m map[string]any) {
			threat(m, 1)["abuse_case"] = map[string]any{"goal": "Read the wire"}
		}, check: func(t *testing.T, r Result) {
			if hasIssue(r.Report, "V12", "abuse_case_missing") {
				t.Fatal("abuse case issue though all have one")
			}
		}},
		{name: "V12 three high threats and no tree", want: []string{"V12:attack_tree_missing"}, mut: func(m map[string]any) {
			var ts []any
			for i := 0; i < 3; i++ {
				ts = append(ts, map[string]any{
					"id": fmt.Sprintf("H%d", i), "title": "High", "framework": "stride", "category": "tampering",
					"element": map[string]any{"kind": "component", "id": "api"}, "rating": map[string]any{"likelihood": 4, "impact": 4},
					"abuse_case": map[string]any{"goal": "g"},
				})
			}
			m["threats"], m["attack_trees"] = ts, nil
		}},
		{name: "V12 trees are not asked for when the extra is off", opts: func(o *ValidateOptions) { o.MethodExtras = []string{ExtraAbuseCases} }, mut: func(m map[string]any) {
			var ts []any
			for i := 0; i < 3; i++ {
				ts = append(ts, map[string]any{
					"id": fmt.Sprintf("H%d", i), "title": "High", "framework": "stride", "category": "tampering",
					"element": map[string]any{"kind": "component", "id": "api"}, "rating": map[string]any{"likelihood": 4, "impact": 4},
					"abuse_case": map[string]any{"goal": "g"},
				})
			}
			m["threats"], m["attack_trees"] = ts, nil
		}, check: func(t *testing.T, r Result) {
			if hasIssue(r.Report, "V12", "attack_tree_missing") {
				t.Fatal("attack tree issue with the extra off")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidatePentestCoverage(t *testing.T) {
	cases := []vcase{
		{name: "V13 effective rows", contract: ContractPentest, want: []string{"V13:coverage_missing_rows"}, check: func(t *testing.T, r Result) {
			cov := r.Report.PT
			if cov == nil || len(cov.Rows) != 12 || !cov.Started {
				t.Fatalf("coverage = %+v", cov)
			}
			want := map[string]int{CovTestedClaimed: 2, CovNotApplicable: 1, CovMissing: 9}
			for k, n := range want {
				if cov.Counts[k] != n {
					t.Errorf("%s = %d, want %d (%v)", k, cov.Counts[k], n, cov.Counts)
				}
			}
			if cov.Counts[CovTestedLogged] != 0 {
				t.Error("a logged row before there is a request log")
			}
		}},
		{name: "V13 target did not start", contract: ContractPentest, want: []string{"V13:target_not_started", "V13:observed_without_target"}, mut: func(m map[string]any) {
			obj(obj(m["target"])["start"])["started"] = false
		}, check: func(t *testing.T, r Result) {
			if r.Report.PT.Counts[CovNotStarted] != 12 {
				t.Fatalf("counts = %v", r.Report.PT.Counts)
			}
			if b := r.PT.Findings[0].Basis; b != "inferred" {
				t.Fatalf("basis = %s", b)
			}
		}},
		{name: "V13 categories in force", contract: ContractPentest, opts: func(o *ValidateOptions) {
			o.Categories, _ = ResolvePreset(CategoryPresets, "auth_access")
		}, check: func(t *testing.T, r Result) {
			if n := len(r.Report.PT.Rows); n != 4 {
				t.Fatalf("%d rows", n)
			}
			if got := strings.Join(r.Report.Sets.Categories, ","); got != "IDNT,ATHN,ATHZ,SESS" {
				t.Fatalf("sets = %s", got)
			}
		}},
		{name: "V13 empty category set means all twelve", contract: ContractPentest, opts: func(o *ValidateOptions) { o.Categories = nil }, check: func(t *testing.T, r Result) {
			if n := len(r.Report.PT.Rows); n != 12 {
				t.Fatalf("%d rows", n)
			}
		}},
		{name: "V10 pen test band", contract: ContractPentest, check: func(t *testing.T, r Result) {
			if f := r.PT.Findings[0]; f.Band != BandMedium || f.Score != 12 {
				t.Fatalf("band %s score %d", f.Band, f.Score)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

func TestValidateRecordsTheSetsInForce(t *testing.T) {
	o := optsFor(ContractThreatModel)
	o.Frameworks = []string{FrameworkLINDDUN}
	o.MethodExtras = []string{ExtraAttackTrees}
	r := Validate([]byte(baseThreatModel), o)
	s := r.Report.Sets
	if strings.Join(s.Frameworks, ",") != "linddun,stride" || strings.Join(s.MethodExtras, ",") != "attack_trees" {
		t.Fatalf("sets = %+v", s)
	}
}

func TestValidateIsDeterministicAndPure(t *testing.T) {
	o := optsFor(ContractThreatModel)
	a, _ := json.Marshal(Validate([]byte(baseThreatModel), o))
	b, _ := json.Marshal(Validate([]byte(baseThreatModel), optsFor(ContractThreatModel)))
	if !bytes.Equal(a, b) {
		t.Fatal("two validations of the same bytes differ")
	}
	if len(o.Frameworks) != 4 || len(o.MethodExtras) != 2 {
		t.Fatalf("options were changed: %+v", o)
	}
}

func TestValidateIssueListIsBounded(t *testing.T) {
	data := edit(t, baseThreatModel, func(m map[string]any) {
		var cs []any
		for i := 0; i < maxComponents; i++ {
			cs = append(cs, map[string]any{"id": fmt.Sprintf("c%d", i), "name": "C", "type": "nope"})
		}
		sys(m)["components"] = cs
	})
	r := Validate(data, optsFor(ContractThreatModel))
	if len(r.Report.Issues) != maxIssues || r.Report.IssuesMore == 0 {
		t.Fatalf("%d issues, %d more", len(r.Report.Issues), r.Report.IssuesMore)
	}
}

func TestRulesTable(t *testing.T) {
	var ids []string
	for _, r := range Rules() {
		ids = append(ids, r.ID)
		if r.Name == "" || r.Effect == "" {
			t.Errorf("row %s has no name or effect", r.ID)
		}
	}
	if got := strings.Join(ids, ","); got != "V1,V2,V3,V4,V5,V6,V7,V8,V9,V10,V11,V12,V13,V14,V16" {
		t.Fatalf("rows = %s", got)
	}
}

func TestContractSchema(t *testing.T) {
	for c, want := range map[Contract]string{ContractThreatModel: SchemaThreatModel, ContractPentest: SchemaPentest, ContractSARIF: "", "": ""} {
		if got := c.Schema(); got != want {
			t.Errorf("%q: %q, want %q", c, got, want)
		}
	}
}
