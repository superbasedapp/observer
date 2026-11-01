package secmcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestNoForbiddenImports(t *testing.T) {
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{
			"database/sql", "net/http", "os", "os/exec",
			"github.com/fsnotify/fsnotify",
			"github.com/marmutapp/superbased-observer/internal/store",
			"github.com/marmutapp/superbased-observer/internal/mcp",
		},
		Reason: "internal/secmcp takes every I/O injected and satisfies the MCP tool interface structurally",
	})
}

// fakeToken is built at run time so no scanner flags this file.
func fakeToken() string { return "ghp_" + strings.Repeat("a1B2", 9) }

func TestCheckChange(t *testing.T) {
	t.Parallel()
	out := Check("config/app.py", "x = 1\ntoken = \""+fakeToken()+"\"\n")
	if out.Status != "hits" || len(out.Hits) == 0 || out.Hits[0].Line != 2 || out.Hits[0].Rule != "S-721" {
		t.Fatalf("secret: %+v", out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), fakeToken()) || strings.Contains(string(b), "a1B2a1B2") {
		t.Fatalf("the answer carries the value: %s", b)
	}
	if out := Check("a.go", "package a\n"); out.Status != "clean" || len(out.Hits) != 0 {
		t.Fatalf("clean: %+v", out)
	}
	wf := "on: push\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	got := Check(".github/workflows/ci.yml", wf)
	found := false
	for _, h := range got.Hits {
		if h.Rule == "S-775" && h.Kind == "ci_workflow" {
			found = true
		}
	}
	if !found {
		t.Fatalf("workflow: %+v", got)
	}
	if out := Check("big.txt", strings.Repeat("a", maxCheckBytes+10)); out.Status != "incomplete" {
		t.Fatalf("over the cap is not clean: %+v", out.Status)
	}
}

func TestGetSecurityFindings(t *testing.T) {
	t.Parallel()
	var many []secfinding.Finding
	for i := 0; i < 120; i++ {
		many = append(many, secfinding.Finding{
			ID: "F", Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret,
			Severity: policy.FindingSeverityHigh, Location: secfinding.Location{RelPath: "a.py", StartLine: i + 1},
			Message: "S-721: a secret", FixHint: "Move it to an environment variable.", EvidenceRedacted: "[github_token]",
		})
	}
	var gotDir string
	tools := Tools(Deps{WorkDir: "/w/p", Findings: func(_ context.Context, dir string) (string, []secfinding.Finding, error) {
		gotDir = dir
		return dir, many, nil
	}})
	if len(tools) != 2 || tools[0].Name() != "get_security_findings" || tools[1].Name() != "check_change" {
		t.Fatalf("tools %v", tools)
	}
	res, err := tools[0].Invoke(context.Background(), nil)
	if err != nil || gotDir != "/w/p" {
		t.Fatalf("%v %s", err, gotDir)
	}
	out := res.(FindingsOut)
	if out.Open != 120 || len(out.Findings) != maxFindings || !out.Truncated || out.Note == "" {
		t.Fatalf("summary: open %d, listed %d, truncated %v", out.Open, len(out.Findings), out.Truncated)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "github_token") {
		t.Fatalf("evidence in the answer: %s", b)
	}
	for _, tl := range tools {
		if len(tl.Description()) > 220 {
			t.Errorf("%s: description is %d bytes; keep MCP schema cost low", tl.Name(), len(tl.Description()))
		}
	}
}

// TestGetSecurityFindingsOnlyOwnProject (lane sec-gate2 milestone 2b): the
// tool answers for the server's working-directory project; a project_dir
// in that project is accepted, another project's directory is refused and
// its findings are never returned.
func TestGetSecurityFindingsOnlyOwnProject(t *testing.T) {
	t.Parallel()
	rootOf := map[string]string{"/r": "/r", "/r/sub": "/r", "/other": "/other"}
	findings := map[string][]secfinding.Finding{
		"/r":     {{ID: "own", Rule: secfinding.Rule{ID: "S-721"}}},
		"/other": {{ID: "theirs", Rule: secfinding.Rule{ID: "S-721"}}},
	}
	read := func(_ context.Context, dir string) (string, []secfinding.Finding, error) {
		root := rootOf[dir]
		return root, findings[root], nil
	}
	tool := Tools(Deps{WorkDir: "/r", Findings: read})[0]
	for _, tc := range []struct {
		args string
		ok   bool
	}{
		{`{}`, true},
		{`{"project_dir":"/r/sub"}`, true},
		{`{"project_dir":"/other"}`, false},
	} {
		got, err := tool.Invoke(context.Background(), json.RawMessage(tc.args))
		if !tc.ok {
			if err == nil {
				t.Fatalf("%s: answered %+v, want a refusal", tc.args, got)
			}
			continue
		}
		out, _ := got.(FindingsOut)
		if err != nil || len(out.Findings) != 1 || out.Findings[0].ID != "own" {
			t.Fatalf("%s: %+v, %v; want the server's own project's finding", tc.args, got, err)
		}
	}
	if _, err := Tools(Deps{Findings: read})[0].Invoke(context.Background(), json.RawMessage(`{"project_dir":"/other"}`)); err == nil {
		t.Fatal("a server with no working directory answered for a named project")
	}
}
