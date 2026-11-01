package autohand

import (
	"encoding/json"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestClassifyTool(t *testing.T) {
	cases := []struct {
		tool string
		want string
	}{
		// live-observed
		{"read_file", models.ActionReadFile},
		{"list_tree", models.ActionSearchFiles},
		{"fff_find", models.ActionSearchFiles},
		{"git_status", models.ActionRunCommand},
		{"run_command", models.ActionRunCommand},
		{"shell", models.ActionRunCommand},
		{"todo_write", models.ActionTodoUpdate},
		{"write_file", models.ActionWriteFile},
		{"search_replace", models.ActionEditFile},
		{"delete_path", models.ActionEditFile},
		// vendor registry
		{"find_grep", models.ActionSearchText},
		{"apply_patch", models.ActionEditFile},
		{"git_apply_patch", models.ActionEditFile},
		{"git_commit", models.ActionRunCommand},
		{"git_worktree_add", models.ActionRunCommand},
		{"create_directory", models.ActionWriteFile},
		{"rename_path", models.ActionEditFile},
		{"web_search", models.ActionWebSearch},
		{"fetch_url", models.ActionWebFetch},
		{"delegate_task", models.ActionSpawnSubagent},
		{"delegate_parallel", models.ActionSpawnSubagent},
		{"ask_followup_question", models.ActionAskUser},
		{"skill", models.ActionSkillInvoke},
		{"cron_create", models.ActionSchedule},
		{"tool_search", models.ActionToolSearch},
		{"browser_click", models.ActionBrowserAction},
		{"mcp__github__create_issue", models.ActionMCPCall},
		// unmapped: classified unknown, raw name kept by the caller
		{"save_memory", models.ActionUnknown},
		{"sleep", models.ActionUnknown},
		{"", models.ActionUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			if got := classifyTool(tc.tool); got != tc.want {
				t.Errorf("classifyTool(%q) = %q, want %q", tc.tool, got, tc.want)
			}
		})
	}
}

func TestActionMapValuesAreKnownActions(t *testing.T) {
	known := map[string]bool{}
	for _, a := range []string{
		models.ActionReadFile, models.ActionWriteFile, models.ActionEditFile, models.ActionRunCommand,
		models.ActionSearchText, models.ActionSearchFiles, models.ActionWebSearch, models.ActionWebFetch,
		models.ActionBrowserAction, models.ActionMCPCall, models.ActionSpawnSubagent, models.ActionTodoUpdate,
		models.ActionAskUser, models.ActionSkillInvoke, models.ActionSchedule, models.ActionToolSearch,
	} {
		known[a] = true
	}
	for name, action := range actionMap {
		if !known[action] {
			t.Errorf("actionMap[%q] = %q is not a recognised action type", name, action)
		}
	}
}

func TestTargetFromArgs(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args string
		want string
	}{
		{"path", "read_file", `{"path":"a/b.go"}`, "a/b.go"},
		{"command", "shell", `{"command":"go test","description":"d"}`, "go test"},
		{"command with args", "run_command", `{"command":"git","args":["log","-1"]}`, "git log -1"},
		{"query", "find_grep", `{"query":"TODO","path":"src"}`, "TODO"}, // query outranks the optional search dir
		{"query only", "web_search", `{"query":"react 19"}`, "react 19"},
		{"url", "fetch_url", `{"url":"https://example.com"}`, "https://example.com"},
		{"rename from", "rename_path", `{"from":"a","to":"b"}`, "a"},
		{"delegate", "delegate_task", `{"agent_name":"reviewer","task":"t"}`, "reviewer"},
		{"empty args object", "git_status", `{}`, "git_status"},
		{"no args", "git_status", ``, "git_status"},
		{"bad json", "x", `{`, "x"},
		{"blank value", "read_file", `{"path":"  "}`, "read_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := targetFromArgs(tc.tool, json.RawMessage(tc.args)); got != tc.want {
				t.Errorf("targetFromArgs = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAuthoredBytes(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args string
		want int64
	}{
		{"write_file", "write_file", `{"path":"a","contents":"hello"}`, 5},
		{"append_file", "append_file", `{"path":"a","contents":"xy"}`, 2},
		{
			"search_replace replace side", "search_replace",
			`{"path":"a","blocks":"<<<<<<< SEARCH\nold\n=======\nnew\nlines\n>>>>>>> REPLACE"}`, int64(len("new\n") + len("lines\n")),
		},
		{
			"search_replace two blocks", "search_replace",
			`{"path":"a","blocks":"<<<<<<< SEARCH\na\n=======\nb\n>>>>>>> REPLACE\n<<<<<<< SEARCH\nc\n=======\nd\n>>>>>>> REPLACE"}`, 4,
		},
		{
			"apply_patch added lines", "apply_patch",
			`{"path":"a","patch":"--- a\n+++ b\n@@\n-x\n+yy\n+z\n"}`, int64(len("+yy") + len("+z")),
		},
		{"read has none", "read_file", `{"path":"a","contents":"zzz"}`, 0},
		{"bad json", "write_file", `{`, 0},
		{"empty", "write_file", ``, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := authoredBytes(tc.tool, json.RawMessage(tc.args)); got != tc.want {
				t.Errorf("authoredBytes = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestOutputFailed(t *testing.T) {
	cases := []struct {
		tool string
		out  string
		want bool
	}{
		// vendor failure text, any tool
		{"run_command", "Command exited with code 2.", true},
		{"shell", "  Command exited with code 1.\n", true},
		{"write_file", "Error: path escapes workspace", true},
		{"run_command", `Error running "x": spawn failed`, true},
		{"shell", "Pre-tool hook failed.", true},                         // live 2026-10-21 (hook crash)
		{"shell", "Pre-tool hook returned malformed JSON output.", true}, // live 2026-10-21
		{"write_file", "Pre-tool hook denyed execution.", true},
		{"shell", "Hook timed out after 15000ms", true}, // live 2026-10-21
		{"read_file", "Hook blocked execution", true},
		{"write_file", "Permission-request hook failed.", true},
		{"read_file", "Tool execution aborted.", true},
		{"read_file", "Tool execution skipped by user.", true},
		{"write_file", "Tool failed without error message", true},
		{"write_file", "Updated input for 'write_file' was denied by the permission policy.", true},
		// tool refusal
		{"write_file", "Tool 'write_file' was denied by the permission policy.", true},
		{"browser_click", "Tool 'browser_click' is not available in the current context (cli)", true},
		// command tools: anything but the command header is a call that did not run
		{"shell", "user rule U-901: command matches observer-e2e-forbidden", true}, // live 2026-10-22, Observer's own pre-tool block
		{"shell", "SBO-PROBE deny-json on pre-tool tool=shell", true},              // live 2026-10-21, a probe hook's block reason
		{"run_command", "denied", true},
		{"shell", "", true},
		{"shell", "$ Run hello_world.py\n> python3 hello_world.py\nHello, World!\n", false},
		{"run_command", "$ dir /b\nhello_world.py\r\n", false},
		{"shell", "$ Echo test string t-ask-json\n> echo t-ask-json\nt-ask-json\r\n", false},
		// other tools: only the fixed texts
		{"git_status", "This directory is not a git repository. You should call run_command with `git init`", false},
		{"read_file", "user rule U-901: anything", false}, // not detectable off a command tool (known gap)
		{"", "Tool 'x' was denied by the permission policy.", true},
		{"", "", false},
	}
	for _, tc := range cases {
		if got := outputFailed(tc.tool, tc.out); got != tc.want {
			t.Errorf("outputFailed(%q, %q) = %v, want %v", tc.tool, tc.out, got, tc.want)
		}
	}
}

func TestStripANSI(t *testing.T) {
	in := "\x1b[38;5;145m  Added \x1b[0m1 line\n\x1b[?25l\x1b[2Jhello\x1b]0;C:\\WINDOWS\\system32\\cmd.exe\x07"
	if got, want := stripANSI(in), "  Added 1 line\nhello"; got != want {
		t.Errorf("stripANSI = %q, want %q", got, want)
	}
}

func TestContentText(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"string", `"hi"`, "hi"},
		{"null", `null`, ""},
		{"empty", ``, ""},
		{"blocks", `[{"type":"text","text":"a"},{"text":"b"}]`, "a\nb"},
		{"object", `{"x":1}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentText(json.RawMessage(tc.raw)); got != tc.want {
				t.Errorf("contentText = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTruncateKeepsRunes(t *testing.T) {
	if got := truncate("héllo", 2); got != "h" { // 'é' is 2 bytes starting at index 1
		t.Errorf("truncate split a rune: %q", got)
	}
	if got := truncate("abc", 10); got != "abc" {
		t.Errorf("truncate = %q", got)
	}
}

func TestPathFamily(t *testing.T) {
	cases := map[string]string{
		`C:\Users\x\proj`:       "windows",
		`d:/work/p`:             "windows",
		`\\wsl.localhost\U\h\p`: "windows",
		"/home/x/p":             "posix",
		"/mnt/c/Users/x":        "posix",
		"relative/p":            "",
		"":                      "",
		"~/p":                   "",
	}
	for in, want := range cases {
		if got := pathFamily(in); got != want {
			t.Errorf("pathFamily(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMessageKeyIsStableAndDistinct(t *testing.T) {
	ts := parseTime("2026-10-21T03:36:55.352Z")
	a := messageKey(ts, "same")
	if a != messageKey(ts, "same") {
		t.Error("messageKey not deterministic")
	}
	if a == messageKey(ts, "other") || a == messageKey(ts.Add(1_000_000), "same") {
		t.Error("messageKey collides across content/time")
	}
}
