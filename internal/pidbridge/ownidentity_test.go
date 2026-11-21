package pidbridge

import "testing"

// TestProcessIdentityIsOwnProcess (sdk-1f L4, fixes-1 N1): the own-process
// check is an exact executable identity, never a substring of an argument,
// and it finds the program an interpreter runs past its flags, a `-m`
// module, an `env -S` shebang and an npm package's generic entry script.
func TestProcessIdentityIsOwnProcess(t *testing.T) {
	claude := []string{"claude-code", "claude"}
	qwen := []string{"qwen-code", "qwen"}
	gemini := []string{"gemini-cli", "gemini"}
	aider := []string{"aider"}
	cases := []struct {
		name  string
		id    processIdentity
		names []string
		want  bool
	}{
		{"comm set by process.title", processIdentity{comm: "claude\n", argv: []string{"node", "/opt/cli.js"}}, claude, true},
		{"native exe", processIdentity{comm: "x", exe: "/home/u/.local/bin/claude"}, claude, true},
		{"deleted exe after an update", processIdentity{comm: "x", exe: "/home/u/.local/bin/claude (deleted)"}, claude, true},
		{"windows exe", processIdentity{comm: "x", argv: []string{`C:\Users\u\bin\claude.exe`}}, claude, true},
		{"script under an interpreter", processIdentity{comm: "node", argv: []string{"/usr/bin/node", "/usr/lib/claude.js"}}, claude, true},
		// fixes-1 N1: the shapes L4 missed.
		{"node flags before the script (relaunch)", processIdentity{comm: "node", argv: []string{"node", "--max-old-space-size=8192", "--no-warnings", "/usr/lib/node_modules/@qwen-code/qwen-code/cli.js"}}, qwen, true},
		{"node flag with a separate value", processIdentity{comm: "node", argv: []string{"node", "-r", "/tmp/hook.js", "/usr/lib/node_modules/@qwen-code/qwen-code/cli.js"}}, qwen, true},
		{"generic entry script in a scoped npm package", processIdentity{comm: "node", argv: []string{"node", "/usr/local/lib/node_modules/@google/gemini-cli/dist/index.js"}}, gemini, true},
		{"env -S shebang", processIdentity{comm: "node", argv: []string{"/usr/bin/env", "-S node --max-old-space-size=4096", "/usr/lib/node_modules/@qwen-code/qwen-code/cli.js", "--yolo"}}, qwen, true},
		{"env with an assignment", processIdentity{comm: "env", argv: []string{"env", "NODE_OPTIONS=--x", "node", "/usr/lib/node_modules/@google/gemini-cli/dist/index.js"}}, gemini, true},
		{"python -m module", processIdentity{comm: "python3", argv: []string{"python3", "-m", "aider", "--model", "x"}}, aider, true},
		{"python flags then -m", processIdentity{comm: "python3", argv: []string{"/usr/bin/python3.12", "-X", "dev", "-m", "aider.main"}}, aider, true},
		{"python -mmodule", processIdentity{comm: "python3", argv: []string{"python3", "-maider"}}, aider, true},
		{"module with underscores reads as hyphens", processIdentity{comm: "python3", argv: []string{"python3", "-m", "qwen_code"}}, qwen, true},
		{"bun run", processIdentity{comm: "bun", argv: []string{"bun", "run", "--smol", "/x/node_modules/@qwen-code/qwen-code/cli.js"}}, qwen, true},
		// Negatives: still never a substring.
		{"interpreter flag is not a script", processIdentity{comm: "node", argv: []string{"node", "--claude"}}, claude, false},
		{"inline code is not a script", processIdentity{comm: "node", argv: []string{"node", "-e", "require('claude')"}}, claude, false},
		{"path segment names the tool", processIdentity{comm: "python3", argv: []string{"python3", "/home/u/claude-code/agent.py"}}, claude, false},
		{"argument names the tool", processIdentity{comm: "python3", argv: []string{"python3", "agent.py", "claude-code"}}, claude, false},
		{"script name contains the tool id", processIdentity{comm: "bash", argv: []string{"bash", "/tmp/claude-helper.sh"}}, claude, false},
		{"a folder named for the tool is not node_modules", processIdentity{comm: "node", argv: []string{"node", "/home/u/projects/qwen-code/cli.js"}}, qwen, false},
		{"own script beside node_modules is not the package", processIdentity{comm: "node", argv: []string{"node", "/home/u/app/node_modules/x.js"}}, qwen, false},
		{"python -m of another module", processIdentity{comm: "python3", argv: []string{"python3", "-m", "my_agent", "--tool", "aider"}}, aider, false},
		{"no names", processIdentity{comm: "claude"}, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.isOwnProcess(tc.names); got != tc.want {
				t.Fatalf("isOwnProcess = %v, want %v (identities %v)", got, tc.want, tc.id.executableNames())
			}
		})
	}
}
