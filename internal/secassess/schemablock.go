package secassess

import (
	"errors"
	"fmt"
	"strings"
)

// The result model block of a prompt (depth plan W1c): the compact, annotated
// schema an agent is handed so it writes assessment.json in the shape the
// validator reads. The shape is one small example that is itself a valid model
// (a test runs it through Validate), so the words in the prompt cannot drift
// from the rules; the closed word lists under it are generated from the vocab
// tables, never typed twice.

// SchemaInput is what a schema block is built from. Every set is plain data;
// the pure package never reads configuration.
type SchemaInput struct {
	Contract      Contract
	RunID         string
	PromptVersion string
	// TargetURL is the confirmed target of a penetration test ("" shows the
	// loopback placeholder).
	TargetURL string
	// Frameworks are the threat-model frameworks in force; nil takes every one.
	// STRIDE is always asked for.
	Frameworks []string
	// MethodExtras are the method extras in force (nil takes none here; the
	// caller resolves a preset).
	MethodExtras []string
	// Categories are the test categories in force; empty takes all twelve.
	Categories []string
	// Helper says the run has the request helper: the example then carries an
	// indicator, and the probe ids are the ones the helper prints.
	Helper bool
	// Exercise says the kind asks for an exercise (a red team run): the example
	// then carries one and the rules say how it is read.
	Exercise bool
}

// tmExample is a small valid threat model. RUNID, PVER are replaced.
const tmExample = `{"schema":"observer.threatmodel.v1","run_id":"RUNID","prompt_version":"PVER",
 "generator":{"tool":"name","model":"name"},
 "summary":"What the project is and its main risks.",
 "scope":{"in_scope":["cmd/api"],"out_of_scope":["vendor"],"assumptions":["Behind a TLS proxy."]},
 "system":{
  "components":[{"id":"api","name":"API","type":"service","zone":"dmz","paths":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},
   {"id":"db","name":"Database","type":"datastore","zone":"internal"}],
  "zones":[{"id":"dmz","name":"Public"},{"id":"internal","name":"Internal"}],
  "actors":[{"id":"user","name":"User","kind":"end_user"}],
  "assets":[{"id":"creds","name":"Credentials","sensitivity":"restricted","stored_in":["db"]}],
  "entry_points":[{"id":"login","component":"api","kind":"http_route","authn":"none","exposure":"internet"}],
  "flows":[{"id":"f1","from":"user","to":"api","data":["creds"],"crosses":["dmz"],"authn":"none","encrypted":"yes","personal_data":true}]},
 "threats":[{"id":"T-1","title":"Credential stuffing","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},
   "rating":{"likelihood":4,"impact":4},
   "existing":[{"text":"Passwords are hashed."}],
   "missing":[{"text":"Rate limit the login route.","control":"throttle","effort":"s","refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]}],
   "cwe":["CWE-307"],"abuse_case":{"actor":"user","goal":"Take over an account","steps":["Replay leaked passwords"]}}],
 "no_threat":[{"element":{"kind":"component","id":"db"},"category":"repudiation","reason":"Only the API writes to it."}],
 "attack_trees":[{"root":"Take over an account","nodes":[{"id":"n1","label":"Guess a password","op":"or","leaf":true}]}],
 "limits":["Code read only."]}`

// ptExample is a small valid penetration test result. RUNID, PVER, TARGET and
// INDICATOR are replaced (INDICATOR is the finding's indicator when the run has
// the request helper, and nothing otherwise).
const ptExample = `{"schema":"observer.pentest.v1","run_id":"RUNID","prompt_version":"PVER",
 "generator":{"tool":"name","model":"name"},"summary":"What was tested and the result.",
 "target":{"url":"TARGET","start":{"argv":["npm","run","dev"],"source":"package.json scripts.dev","started":true,"startup_seconds":6,"health":{"path":"/health","status":200}},
  "accounts":[{"label":"user1","role":"member"}]},
 "method":{"standard":"wstg"},
 "coverage":[{"category":"ATHN","status":"tested","probes":["p1","p2"],"notes":"Crafted password on sign-in."},
  {"category":"CRYP","status":"not_applicable","reason":"Loopback over http only."}],
 "findings":[{"id":"F-1","title":"Sign-in can be bypassed","category":"ATHN","cwe":["CWE-287"],"rating":{"likelihood":4,"impact":3},"cvss":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N","basis":"observed",
   "where":{"refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},"route":"/login","evidence":["p1","p2"],INDICATOR
   "reproduction":[{"step":"Sign in with a crafted password","request":{"method":"POST","path":"/login","body":"user=a&password=' OR 1=1--"}}],"impact":"Anyone can sign in as anyone.","fix":"Parameterise the query.","status":"open"}],
 EXERCISE"limits":["Dev server only."]}`

// rtExample is a small valid retest result (depth plan W7.2). RUNID and PVER are
// replaced. The finding it labels is one the retest replayed; its attack is the
// helper's replay of that finding and its control an ordinary request.
const rtExample = `{"schema":"observer.retest.v1","run_id":"RUNID","prompt_version":"PVER",
 "generator":{"tool":"name","model":"name"},"summary":"What was replayed and the result.","started":true,
 "results":[{"finding":"F-1","result":"not_reproduced","attack":"p2","control":"p1","evidence":["p3"],"note":"Now answers 401."}],
 "limits":["Dev server only."]}`

// ptExercise is the exercise a red team example carries, and the rule under the
// example; both are placed only for a kind that asks for one.
const (
	ptExercise     = `"exercise":{"objective":"Read user data","chain":[{"step":"Bypass sign-in","finding":"F-1","result":"achieved","stop":"Rate limit sign-in."}]},`
	ptExerciseRule = "exercise: objective as given, else yours; chain steps in order, finding optional, result achieved, partly or blocked, stop what would have detected or stopped it.\n"
)

// ptIndicator is the example's indicator when the run has the request helper: a
// control request, an attack request and a response condition that holds for the
// attack's response and not for the control's.
const ptIndicator = `"indicator":{"control":"p1","attack":"p2","when":{"status":200,"body_contains":["token"]}},`

// SchemaExample returns the example model of the contract with the run id,
// prompt version and target filled in ("" for a contract without a model).
func SchemaExample(in SchemaInput) string {
	var ex string
	switch in.Contract {
	case ContractThreatModel:
		ex = tmExample
	case ContractPentest:
		ex = ptExample
	case ContractRetest:
		ex = rtExample
	default:
		return ""
	}
	target := in.TargetURL
	if target == "" {
		target = "http://127.0.0.1:3000/"
	}
	indicator, exercise := "", ""
	if in.Helper {
		indicator = ptIndicator
	}
	if in.Exercise {
		exercise = ptExercise
	}
	return strings.NewReplacer("RUNID", in.RunID, "PVER", in.PromptVersion, "TARGET", cleanURLForExample(target), "INDICATOR", indicator, "EXERCISE", exercise).Replace(ex)
}

// cleanURLForExample keeps a target URL that goes inside a JSON string safe.
func cleanURLForExample(s string) string {
	return strings.NewReplacer(`"`, "", `\`, "", "\n", "", "\r", "").Replace(s)
}

// ids joins a list of words with a comma and a space.
func ids(xs []string) string { return strings.Join(xs, ", ") }

func idsOfStride() []string {
	out := make([]string, len(StrideCategories))
	for i, c := range StrideCategories {
		out[i] = c.ID
	}
	return out
}

func idsOfLinddun() []string {
	out := make([]string, len(LinddunCategories))
	for i, c := range LinddunCategories {
		out[i] = c.ID
	}
	return out
}

func idsOfComponentTypes() []string {
	out := make([]string, len(ComponentTypes))
	for i, c := range ComponentTypes {
		out[i] = c.ID
	}
	return out
}

func has(set []string, x string) bool {
	for _, s := range set {
		if s == x {
			return true
		}
	}
	return false
}

// SchemaBlock renders the result-model section of a prompt for a contract
// with a model, in the sets given. It is the one text a prompt carries about
// the shape of assessment.json.
func SchemaBlock(in SchemaInput) (string, error) {
	ex := SchemaExample(in)
	if ex == "" {
		return "", errors.New("secassess.SchemaBlock: not a model contract")
	}
	var b strings.Builder
	fmt.Fprintf(&b, "RESULT MODEL (assessment.json, schema %s): one JSON object. This example is a valid file; write these fields and no others. Leave out what Observer computes (reference states, risk band, scores). An item that breaks a rule is left out and named. Write no findings.sarif%s\n", in.Contract.Schema(), schemaSarifTail(in.Contract))
	b.WriteString(ex)
	b.WriteString("\n")
	switch in.Contract {
	case ContractThreatModel:
		writeTMRules(&b, in)
	case ContractPentest:
		writePTRules(&b, in)
	case ContractRetest:
		writeRTRules(&b)
		b.WriteString("Ids: letters, digits, . _ - only, 48 at most, unique per list.\n")
		return b.String(), nil
	}
	b.WriteString("References (ref): path is project-relative with forward slashes, no leading slash, no ..; end_line (optional) at most 200 lines after line; needle is text copied exactly from the cited line, 8 or more characters with a name from the code (without one it counts only as a location).\n")
	b.WriteString("Ids: letters, digits, . _ - only, 48 at most, unique per list. likelihood, impact: whole numbers 1 to 5.\n")
	return b.String(), nil
}

// writeTMRules is the threat-model part of the block under the example.
func writeTMRules(b *strings.Builder, in SchemaInput) {
	fws := in.Frameworks
	if fws == nil {
		fws, _ = ResolvePreset(FrameworkPresets, "all")
	}
	b.WriteString("Words (others refuse the item):\n")
	fmt.Fprintf(b, "- component type: %s; actor kind: %s; asset sensitivity: %s\n", ids(idsOfComponentTypes()), ids(EnumActorKind), ids(EnumSensitivity))
	fmt.Fprintf(b, "- entry point kind: %s; authn: %s; exposure: %s; flow encrypted: %s\n", ids(EnumEntryKind), ids(EnumAuthn), ids(EnumExposure), ids(EnumEncrypted))
	fmt.Fprintf(b, "- element kind: %s; threat status: %s; effort: %s; attack tree op: %s\n", ids(EnumElementKind), ids(EnumThreatState), ids(EnumEffort), ids(EnumTreeOp))
	fmt.Fprintf(b, "- framework stride, category: %s\n", ids(idsOfStride()))
	if has(fws, FrameworkLINDDUN) {
		fmt.Fprintf(b, "- framework linddun, category: %s\n", ids(idsOfLinddun()))
	}
	var aiWords []string
	for _, f := range AIFrameworks {
		if has(fws, f.ID) {
			aiWords = append(aiWords, fmt.Sprintf("%s (category %s01 to %s10)", f.ID, f.IDPrefix, f.IDPrefix))
		}
	}
	if len(aiWords) > 0 {
		fmt.Fprintf(b, "- framework %s\n", strings.Join(aiWords, ", "))
	}
	b.WriteString("Coverage: for each component, flow and entry point, every category that applies needs a threat or a no_threat entry with a reason. Do STRIDE")
	if has(fws, FrameworkLINDDUN) {
		b.WriteString(", LINDDUN on each flow with personal_data true")
	}
	var ai []string
	for _, f := range AIFrameworks {
		if has(fws, f.ID) {
			ai = append(ai, f.ID)
		}
	}
	if len(ai) > 0 {
		fmt.Fprintf(b, ", and only for an AI application %s", strings.Join(ai, " and "))
	}
	b.WriteString(".\n")
	var extras []string
	if has(in.MethodExtras, ExtraAbuseCases) {
		extras = append(extras, "an abuse_case on the five highest-risk threats and every high one")
	}
	if has(in.MethodExtras, ExtraAttackTrees) {
		extras = append(extras, "an attack_trees entry once three threats rate high")
	}
	if len(extras) > 0 {
		b.WriteString("Also: " + strings.Join(extras, "; ") + ".\n")
	}
	b.WriteString("A missing[] entry whose refs point at the file and line where the control belongs becomes one importable finding.\n")
}

// writePTRules is the penetration-test part of the block under the example.
func writePTRules(b *strings.Builder, in SchemaInput) {
	cats := in.Categories
	if len(cats) == 0 {
		cats, _ = ResolvePreset(CategoryPresets, "all")
	}
	b.WriteString("Words (others refuse the item):\n")
	fmt.Fprintf(b, "- coverage status: %s; finding basis: %s; finding status: %s\n", ids(EnumCoverageStatus), ids(EnumBasis), ids(EnumFindingState))
	var names []string
	for _, id := range cats {
		if c, ok := WSTGCategoryByID(id); ok {
			names = append(names, c.ID)
		}
	}
	fmt.Fprintf(b, "- categories, one coverage entry each (tested, or another status with a reason): %s\n", strings.Join(names, ", "))
	b.WriteString("basis observed: seen against the target; inferred: concluded from the code. cvss: optional, base metrics only. ")
	if in.Helper {
		b.WriteString("indicator.when takes status, body_contains, body_not_contains, header_present, header_absent or header_contains (name and value). ")
	} else {
		b.WriteString("Probe ids are your own short names (p1, p2) for requests you made. ")
	}
	b.WriteString("A reproduction request is a method, a path with its query, optional headers and a short body; give a credential header no value.\n")
	if in.Exercise {
		b.WriteString(ptExerciseRule)
	}
	b.WriteString("A finding's where.refs point at the code the weakness comes from; each becomes one importable finding.\n")
}

// schemaSarifTail is the end of the header sentence about findings.sarif: a kind
// whose findings Observer derives says so; a retest has none to derive.
func schemaSarifTail(c Contract) string {
	if c == ContractRetest {
		return "."
	}
	return "; Observer derives it."
}

// writeRTRules is the retest part of the block under the example.
func writeRTRules(b *strings.Builder) {
	b.WriteString("Words (others refuse the item):\n")
	fmt.Fprintf(b, "- result: %s\n", ids(EnumRetestResult))
	b.WriteString("One result for each finding of the REPLAY SET. started: true only if the target answered. attack: the probe id of the replay that shows the weakness; control: the probe id of an ordinary request; evidence: a list of other probe ids (optional). Do not write a condition: Observer reads the one stored with the finding. A result that says reproduced needs a control that differs from the attack; one that says not_reproduced needs the attack replayed and answered. inconclusive claims nothing.\n")
}
