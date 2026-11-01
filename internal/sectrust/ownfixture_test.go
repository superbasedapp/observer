package sectrust

import "testing"

// ownTriggers are the settings developers commonly keep in their own files
// that the check judges (plans decision log P-022, item g): each is one
// reason in a local settings file and carries a digest. Once accepted it
// reads as information, unless it names code that runs or loads files the
// digest cannot cover (runs, plans decision log P-029): that one stays
// flagged, the S-705 warning at every launch.
var ownTriggers = []struct {
	name, file, body, code string
	runs                   bool
}{
	{"dotenv PYTHONPATH", ".env", "PYTHONPATH=./src\n", "process_injection_env", true},
	{"dotenv NODE_OPTIONS heap size", ".env", "NODE_OPTIONS=--max-old-space-size=4096\n", "process_injection_env", false},
	{"dotenv NODE_OPTIONS --require", ".env", "NODE_OPTIONS=--require ./tools/register.js\n", "process_injection_env", true},
	{"dotenv NODE_OPTIONS --import=", ".env", "NODE_OPTIONS=--import=./tools/loader.mjs\n", "process_injection_env", true},
	{"dotenv LD_LIBRARY_PATH", ".env", "LD_LIBRARY_PATH=/opt/oracle/lib\n", "process_injection_env", true},
	{"dotenv remote OPENAI_BASE_URL", ".env", "OPENAI_BASE_URL=https://gateway.corp.example/v1\n", "base_url_override", false},
	{"settings.local enableAllProjectMcpServers", ".claude/settings.local.json", `{"enableAllProjectMcpServers":true}`, "auto_approve", false},
	{"settings.local hook", ".claude/settings.local.json", `{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"make lint"}]}]}}`, "hook_command", true},
	{"git core.sshCommand", ".git/config", "[core]\n\tsshCommand = ssh -i ~/.ssh/work_ed25519\n", "git_command_key", false},
	{"husky core.hooksPath", ".git/config", "[core]\n\thooksPath = .husky/_\n", "git_hookspath", false},
}

// TestOwnFileTriggersQuietAfterAccept: each common own-file trigger raises
// exactly one reason, in a local settings file, with a digest; accepting it
// leaves the repository clean (nothing above information), or flagged for
// code that runs, and a change to the setting asks again.
func TestOwnFileTriggersQuietAfterAccept(t *testing.T) {
	for _, tc := range ownTriggers {
		t.Run(tc.name, func(t *testing.T) {
			files := map[string][]byte{tc.file: []byte(tc.body)}
			res := memCheck(t, MemFS(files))
			if len(res.Reasons) != 1 {
				t.Fatalf("reasons %+v, want exactly one", res.Reasons)
			}
			r := res.Reasons[0]
			if r.Code != tc.code || !r.Local || r.Digest == "" || r.Level < LevelFlagged {
				t.Fatalf("reason %+v, want %s in a local file with a digest", r, tc.code)
			}
			wantVerdict, wantLevel := VerdictClean, LevelInfo
			if tc.runs {
				wantVerdict, wantLevel = VerdictFlagged, LevelFlagged
			}
			acc := memCheck(t, MemFS(files), r.Digest)
			if acc.Verdict != wantVerdict || len(acc.Digests()) != 0 {
				t.Fatalf("after the accept: %s %+v, want %s", acc.Verdict, acc.Reasons, wantVerdict)
			}
			if got := acc.Reasons[0]; !got.Accepted || got.Level != wantLevel {
				t.Fatalf("accepted reason %+v, want %s", got, wantLevel)
			}
			changed := map[string][]byte{tc.file: []byte(tc.body[:len(tc.body)-1] + "x\n")}
			if again := memCheck(t, MemFS(changed), r.Digest); again.Verdict == VerdictClean || again.Reasons[0].Accepted {
				t.Fatalf("a changed setting stayed accepted: %+v", again.Reasons)
			}
		})
	}
}

// TestEnvLoadsCode is the loads-code table, one case per row and the
// variables no row matches.
func TestEnvLoadsCode(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        bool
	}{
		{"PYTHONPATH", "./src", true},
		{"LD_PRELOAD", "/x.so", true},
		{"GIT_SSH_COMMAND", "ssh -i k", true},
		{"NODE_OPTIONS", "-r ./a.js", true},
		{"NODE_OPTIONS", "--experimental-loader=./l.mjs --max-old-space-size=1", true},
		{"NODE_OPTIONS", "--max-old-space-size=4096", false},
		{"GIT_DIR", "/elsewhere", false},
		{"GIT_WORK_TREE", "/elsewhere", false},
	} {
		if got := envLoadsCode(tc.name, tc.value); got != tc.want {
			t.Errorf("envLoadsCode(%s=%s) = %v, want %v", tc.name, tc.value, got, tc.want)
		}
	}
}
