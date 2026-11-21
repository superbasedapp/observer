package secassess

import (
	"encoding/json"
	"strings"
	"testing"
)

// Shared fixtures of the validator tests: a valid threat model and a valid
// penetration test as JSON, a fake project to look references up in, and
// small helpers to edit the generic JSON.

const modelRun = "0123456789abcdef"

const baseThreatModel = `{
 "schema":"observer.threatmodel.v1","run_id":"0123456789abcdef","prompt_version":"tm.2",
 "generator":{"tool":"claude-code","model":"m"},
 "summary":"A small web service.",
 "scope":{"in_scope":["cmd/api"],"out_of_scope":["vendor"],"assumptions":["Runs behind a proxy."]},
 "system":{
  "components":[
   {"id":"api","name":"API","type":"service","zone":"dmz","paths":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},
   {"id":"db","name":"Database","type":"datastore","zone":"internal"},
   {"id":"audit","name":"Audit log","type":"log_store","zone":"internal"}
  ],
  "zones":[{"id":"dmz","name":"DMZ"},{"id":"internal","name":"Internal"}],
  "actors":[{"id":"user","name":"User","kind":"end_user"}],
  "assets":[{"id":"creds","name":"Credentials","sensitivity":"restricted","stored_in":["db"]}],
  "entry_points":[{"id":"login","component":"api","kind":"http_route","authn":"none","exposure":"internet","ref":{"path":"cmd/api/main.go","line":12}}],
  "flows":[
   {"id":"f1","from":"user","to":"api","data":["creds"],"protocol":"https","crosses":["dmz"],"authn":"none","encrypted":"yes","personal_data":true},
   {"id":"f2","from":"api","to":"db","data":["creds"],"encrypted":"no"}
  ]},
 "threats":[
  {"id":"T-1","title":"Credential stuffing","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},"actor":"user","description":"Login has no throttle.","rating":{"likelihood":4,"impact":4},
   "existing":[{"text":"Passwords are hashed.","refs":[{"path":"cmd/api/main.go","line":20,"needle":"bcrypt.Compare"}]}],
   "missing":[{"text":"Rate limit the login route.","control":"throttle","effort":"s","refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]}],
   "cwe":["CWE-307"],"status":"identified","abuse_case":{"actor":"user","goal":"Take over an account","steps":["Try leaked passwords"]}},
  {"id":"T-2","title":"Weak transport to the database","framework":"stride","category":"information_disclosure","element":{"kind":"flow","id":"f2"},"rating":{"likelihood":2,"impact":3},
   "missing":[{"text":"Use TLS to the database."}]}
 ],
 "no_threat":[{"element":{"kind":"component","id":"audit"},"category":"repudiation","reason":"The audit log is append-only."}],
 "attack_trees":[{"root":"Take over an account","nodes":[{"id":"n1","label":"Guess a password","op":"or","leaf":true}]}],
 "open_questions":["Is there an admin console?"],"limits":["Read from code only."]
}`

const basePentest = `{
 "schema":"observer.pentest.v1","run_id":"0123456789abcdef","prompt_version":"pt.2","generator":{"tool":"claude-code"},"summary":"Tested the dev server.",
 "target":{"url":"http://127.0.0.1:3000/","start":{"argv":["npm","run","dev"],"source":"package.json scripts.dev","started":true,"startup_seconds":6,"health":{"path":"/health","status":200}},"accounts":[{"label":"user1","role":"member"}]},
 "method":{"standard":"wstg+ptes"},
 "coverage":[
  {"category":"ATHN","status":"tested","probes":["p1"],"notes":"Tried weak passwords."},
  {"category":"INPV","status":"tested"},
  {"category":"CRYP","status":"not_applicable","reason":"Loopback http only."}],
 "findings":[{"id":"F-1","title":"No login throttle","category":"ATHN","cwe":["CWE-307"],"rating":{"likelihood":4,"impact":3},"basis":"observed",
   "where":{"refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},"route":"/login","evidence":["p1"],
   "reproduction":[{"step":"Send 50 bad logins","request":"POST /login"}],"impact":"Account takeover.","fix":"Add a throttle.","status":"open"}],
 "limits":["Only the dev server."]
}`

// fakeProject is a RefChecker over an in-memory project.
type fakeProject struct {
	files  map[string][]string
	budget map[string]bool
	calls  int
}

func (p *fakeProject) Lines(rel string, first, last int) ([]string, int, LookupStatus) {
	p.calls++
	if p.budget[rel] {
		return nil, 0, LookupBudget
	}
	ls, ok := p.files[rel]
	if !ok {
		return nil, 0, LookupMissing
	}
	if first < 1 {
		first = 1
	}
	if last > len(ls) {
		last = len(ls)
	}
	if first > last {
		return nil, len(ls), LookupOK
	}
	return ls[first-1 : last], len(ls), LookupOK
}

// testProject returns the project the baseline documents point into.
func testProject() *fakeProject {
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	lines[19] = "\tif bcrypt.CompareHashAndPassword(h, p) != nil {"
	return &fakeProject{files: map[string][]string{"cmd/api/main.go": lines}}
}

// optsFor returns default options for a contract with the test project.
func optsFor(c Contract) ValidateOptions {
	o := DefaultValidateOptions(c, modelRun)
	o.Refs = testProject()
	return o
}

// edit applies fn to the generic JSON of doc and returns the new bytes.
func edit(t *testing.T, doc string, fn func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	fn(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

func obj(v any) map[string]any { return v.(map[string]any) }
func arr(v any) []any          { return v.([]any) }

// sys returns the system object of a threat model map.
func sys(m map[string]any) map[string]any { return obj(m["system"]) }

// threat returns threat i of a threat model map.
func threat(m map[string]any, i int) map[string]any { return obj(arr(m["threats"])[i]) }

// finding returns finding i of a pen test map.
func finding(m map[string]any, i int) map[string]any { return obj(arr(m["findings"])[i]) }

// hasIssue reports whether the report carries an issue with the row and code.
func hasIssue(r Report, row, code string) bool {
	for _, is := range r.Issues {
		if is.Row == row && is.Code == code {
			return true
		}
	}
	return false
}

func issueCodes(r Report) string {
	var out []string
	for _, is := range r.Issues {
		out = append(out, is.Row+":"+is.Code)
	}
	return strings.Join(out, " ")
}
