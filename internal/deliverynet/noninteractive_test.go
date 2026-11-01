package deliverynet

import (
	"testing"
)

// TestSSHBatchCommand pins the batch-mode ssh rule: the user's own ssh
// command is kept, in git's own precedence order, and batch mode is always
// APPENDED, never replaced or skipped.
func TestSSHBatchCommand(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name               string
		env, config, gitSS string
		want               string
	}{
		{"nothing set", "", "", "", "ssh -o BatchMode=yes"},
		{"env command wins", "ssh -i ~/.ssh/work", "ssh -i cfg", "/usr/bin/other", "ssh -i ~/.ssh/work -o BatchMode=yes"},
		{"config command next", "", "ssh -F ~/.ssh/cfg", "/usr/bin/other", "ssh -F ~/.ssh/cfg -o BatchMode=yes"},
		{"GIT_SSH program is quoted", "", "", "/opt/my ssh/ssh", "'/opt/my ssh/ssh' -o BatchMode=yes"},
		{"quote inside a program path", "", "", "/opt/o'x/ssh", `'/opt/o'\''x/ssh' -o BatchMode=yes`},
		{"plink spells it -batch", "", "", `C:\Program Files\PuTTY\plink.exe`, `'C:\Program Files\PuTTY\plink.exe' -batch`},
		{"TortoisePlink command", "TortoisePlink.exe -i k", "", "", "TortoisePlink.exe -i k -batch"},
		{"double-quoted plink path", `"C:\Program Files\PuTTY\plink.exe" -i k`, "", "", `"C:\Program Files\PuTTY\plink.exe" -i k -batch`},
		{"plink only in a directory name", "", "", "/opt/plink tools/ssh", "'/opt/plink tools/ssh' -o BatchMode=yes"},
		{"unterminated quote is not plink", `"plink -batch`, "", "", `"plink -batch -o BatchMode=yes`},
		{"user already asked for batch mode", "ssh -o BatchMode=yes", "", "", "ssh -o BatchMode=yes -o BatchMode=yes"},
		{"whitespace only is unset", "  ", " ", "", "ssh -o BatchMode=yes"},
	} {
		if got := sshBatchCommand(tc.env, tc.config, tc.gitSS); got != tc.want {
			t.Errorf("%s: sshBatchCommand = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestClassifyGitCredentialPrompts pins the git failure table: a refused
// prompt is needs_noninteractive_credentials, a refused credential is
// auth_failed.
func TestClassifyGitCredentialPrompts(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stderr string
		want   Kind
	}{
		{"fatal: could not read Username for 'https://git.example.com': terminal prompts disabled", KindNeedsNonInteractive},
		{"error: unable to read askpass response from '/bin/false'\nfatal: could not read Password for 'https://u@h': No such device", KindNeedsNonInteractive},
		{"Host key verification failed.\nfatal: Could not read from remote repository.", KindNeedsNonInteractive},
		{"remote: Invalid username or password.\nfatal: Authentication failed for 'https://h/x.git/'", KindAuthFailed},
		{"git@h: Permission denied (publickey).", KindAuthFailed},
		{"remote: Repository not found.\nfatal: repository 'https://h/x.git/' not found", KindNotFound},
		{"ssh: Could not resolve hostname h: Name or service not known", KindUnreachable},
	} {
		if got := classifyGit(tc.stderr).Kind; got != tc.want {
			t.Errorf("classifyGit(%q) = %s, want %s", tc.stderr, got, tc.want)
		}
	}
}
