//go:build !sbo_omit_security

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

const checkRun = "3fa9c2d17b0e4a56"

// checkProject is a project holding cmd/api/main.go (with the line the example
// model cites) and the model in its run folder.
func checkProject(t *testing.T, model string) (root, rel string) {
	t.Helper()
	root = t.TempDir()
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cmd/api/main.go", strings.Join(lines, "\n")+"\n")
	rel = secassess.ResultPaths(checkRun).Model
	write(rel, model)
	return root, rel
}

func runCheck(t *testing.T, root, path, run string, asJSON bool) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := runSecurityAssessCheck(&out, root, path, run, asJSON)
	return out.String(), err
}

// TestSecurityAssessCheck: the self-check passes the example the prompt carries,
// and names what it would refuse in a file that breaks a rule.
func TestSecurityAssessCheck(t *testing.T) {
	tm := secassess.SchemaExample(secassess.SchemaInput{Contract: secassess.ContractThreatModel, RunID: checkRun, PromptVersion: "tm.2"})
	pt := secassess.SchemaExample(secassess.SchemaInput{Contract: secassess.ContractPentest, RunID: checkRun, PromptVersion: "pt.2"})
	cases := []struct {
		name    string
		model   string
		run     string
		wantErr bool
		must    []string
		mustNot []string
	}{
		{"a valid threat model", tm, "", false, []string{"Read without anything refused or left out.", "2 found near the cited line", "structure and file references only"}, []string{"verified", "confirmed", "clean"}},
		{"a valid penetration test", pt, "", false, []string{"schema observer.pentest.v1", "Read without anything"}, nil},
		{"a closed word it does not know", strings.Replace(tm, `"type":"service"`, `"type":"microservice"`, 1), "", true, []string{"Read, with items left out", "[V5 refused]", "components[0]"}, nil},
		{"a wrong run id", strings.Replace(tm, `"run_id":"`+checkRun+`"`, `"run_id":"0000000000000000"`, 1), "", true, []string{"Not read", "[V2 refused]"}, nil},
		{"the run id from the flag", tm, checkRun, false, []string{"run " + checkRun}, nil},
		{"a flag that disagrees with the file", tm, "ffffffffffffffff", true, []string{"[V2 refused]"}, nil},
		{"a cited file that is not there", strings.Replace(tm, `"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},
   {"id":"db"`, `"path":"cmd/gone.go","line":12,"needle":"func Login("}]},
   {"id":"db"`, 1), "", false, []string{"1 missing"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, rel := checkProject(t, tc.model)
			out, err := runCheck(t, root, rel, tc.run, false)
			if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, errSecurityAssessCheck)) {
				t.Fatalf("err = %v, want error %v\n%s", err, tc.wantErr, out)
			}
			for _, m := range tc.must {
				if !strings.Contains(out, m) {
					t.Errorf("the output lacks %q:\n%s", m, out)
				}
			}
			for _, m := range tc.mustNot {
				if strings.Contains(strings.ToLower(out), m) {
					t.Errorf("the output has %q:\n%s", m, out)
				}
			}
		})
	}
}

// TestSecurityAssessCheckRefusals: a path outside the project, a missing file, a
// file that is not JSON and a schema it does not know are command errors, and
// nothing is read outside the project.
func TestSecurityAssessCheckRefusals(t *testing.T) {
	root, rel := checkProject(t, "{nope")
	cases := []struct {
		name string
		path string
		run  string
		want string
	}{
		{"not JSON", rel, "", "not JSON"},
		{"missing", ".observer/assessments/" + checkRun + "/other.json", "", "no file at"},
		{"outside the project", filepath.Join(filepath.Dir(root), "elsewhere.json"), "", "not inside the project"},
		{"the project itself", ".", "", "not inside the project"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.path
			if !filepath.IsAbs(p) {
				p = filepath.Join(root, filepath.FromSlash(p))
			}
			_, err := runCheck(t, root, p, tc.run, false)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want one containing %q", err, tc.want)
			}
		})
	}
	// An unknown schema names every schema the tasks ask for.
	root, rel = checkProject(t, `{"schema":"other.v1","run_id":"`+checkRun+`"}`)
	_, err := runCheck(t, root, filepath.Join(root, filepath.FromSlash(rel)), "", false)
	for _, m := range secassess.ModelContracts {
		if err == nil || !strings.Contains(err.Error(), m.Schema) {
			t.Fatalf("unknown schema: %v, want one naming %s", err, m.Schema)
		}
	}
	// A file outside a run folder needs the run id.
	tm := secassess.SchemaExample(secassess.SchemaInput{Contract: secassess.ContractThreatModel, RunID: "not a run id", PromptVersion: "tm.2"})
	root = t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.json"), []byte(tm), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runCheck(t, root, filepath.Join(root, "a.json"), "", false); err == nil || !strings.Contains(err.Error(), "no run id") {
		t.Fatalf("no run id: %v", err)
	}
}

// TestSecurityAssessCheckJSON: --json prints the same findings as data.
func TestSecurityAssessCheckJSON(t *testing.T) {
	tm := secassess.SchemaExample(secassess.SchemaInput{Contract: secassess.ContractThreatModel, RunID: checkRun, PromptVersion: "tm.2"})
	root, rel := checkProject(t, strings.Replace(tm, `"type":"service"`, `"type":"microservice"`, 1))
	out, err := runCheck(t, root, rel, "", true)
	if !errors.Is(err, errSecurityAssessCheck) {
		t.Fatalf("err = %v", err)
	}
	var got securityAssessCheckJS
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got.State != "partial" || got.Run != checkRun || got.Schema != secassess.SchemaThreatModel || got.Counts["components"].Refused != 1 || len(got.Issues) == 0 {
		t.Errorf("report = %+v", got)
	}
	for _, is := range got.Issues {
		if !securityAssessCheckRow(secassess.ContractThreatModel, is.Row) {
			t.Errorf("a row outside V1 to V8 was reported: %+v", is)
		}
	}
}

// TestSecurityAssessCheckCommand: the command is registered under
// `observer security assess check`, takes one argument and mints nothing.
func TestSecurityAssessCheckCommand(t *testing.T) {
	cmd := newSecurityCmd()
	var found bool
	for _, c := range cmd.Commands() {
		if c.Name() != "assess" {
			continue
		}
		for _, sub := range c.Commands() {
			if sub.Name() == "check" {
				found = true
				if sub.Args == nil || sub.Flags().Lookup("project") == nil || sub.Flags().Lookup("run") == nil {
					t.Errorf("check = %+v", sub)
				}
			}
		}
	}
	if !found {
		t.Fatal("observer security assess check is not registered")
	}
	// The command the prompt names is the one this verb answers to.
	// Whatever word starts it (the bare command, or the daemon's own path), the
	// rest is the verb this command answers to.
	for _, bin := range []string{"", "/home/u/bin/observer"} {
		want := "observer"
		if bin != "" {
			want = bin
		}
		if got := secassess.SelfCheckCommand(bin, checkRun); !strings.HasPrefix(got, want+" security assess check .observer/assessments/"+checkRun+"/") {
			t.Errorf("prompt command with %q = %q", bin, got)
		}
	}
}

// TestSecurityAssessCheckNotesAFileOverTheDefaultCap: the check reads no
// settings, so it reads a file up to the largest size the setting allows and
// says, in both outputs, that Observer refuses a file over its own cap.
func TestSecurityAssessCheckNotesAFileOverTheDefaultCap(t *testing.T) {
	tm := secassess.SchemaExample(secassess.SchemaInput{Contract: secassess.ContractThreatModel, RunID: checkRun, PromptVersion: "tm.2"})
	// Trailing whitespace keeps the file one valid JSON value.
	big := tm + strings.Repeat(" ", secassess.MaxModelBytes+1024)
	root, rel := checkProject(t, big)
	out, err := runCheck(t, root, rel, "", false)
	if err != nil {
		t.Fatalf("a valid model past the default cap is not a command failure: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Observer refuses a file over its size cap") || !strings.Contains(out, "model_max_mib") {
		t.Errorf("the note is missing:\n%s", out)
	}
	js, err := runCheck(t, root, rel, "", true)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Note string `json:"note"`
	}
	if err := json.Unmarshal([]byte(js), &got); err != nil || !strings.Contains(got.Note, "model_max_mib") {
		t.Errorf("the JSON note = %q (%v)", got.Note, err)
	}
	// A file under the default cap carries no note.
	root, rel = checkProject(t, tm)
	if out, _ := runCheck(t, root, rel, "", false); strings.Contains(out, "size cap") {
		t.Errorf("a small file got a size note:\n%s", out)
	}
}
