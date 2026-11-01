package hook

import "testing"

func TestRewriteBash(t *testing.T) {
	bin := "/usr/local/bin/observer"
	excl := []string{"curl", "playwright"}

	cases := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		{
			name:    "simple command rewrites",
			in:      "git status",
			want:    bin + " run -- git status",
			changed: true,
		},
		{
			name:    "path-prefixed command rewrites",
			in:      "/usr/bin/git log -n5",
			want:    bin + " run -- /usr/bin/git log -n5",
			changed: true,
		},
		{
			name:    "pipe disqualifies",
			in:      "git status | head -5",
			changed: false,
		},
		{
			name:    "redirect disqualifies",
			in:      "ls > out.txt",
			changed: false,
		},
		{
			name:    "subshell disqualifies",
			in:      "echo $(date)",
			changed: false,
		},
		{
			name:    "backtick disqualifies",
			in:      "echo `date`",
			changed: false,
		},
		{
			name:    "env-var interpolation disqualifies",
			in:      "echo $HOME",
			changed: false,
		},
		{
			name:    "quoted metachar allowed",
			in:      "grep '$foo' file",
			want:    bin + " run -- grep '$foo' file",
			changed: true,
		},
		{
			name:    "double-quoted metachar still unsafe",
			in:      `echo "$HOME"`,
			changed: false, // double quotes don't suppress $
		},
		{
			name:    "excluded command skipped",
			in:      "curl example.com",
			changed: false,
		},
		{
			name:    "excluded command with leading path skipped",
			in:      "/usr/bin/curl example.com",
			changed: false,
		},
		{
			name:    "double-wrap guard",
			in:      "observer run -- git status",
			changed: false,
		},
		{
			name:    "superbased double-wrap guard",
			in:      "superbased run -- git status",
			changed: false,
		},
		{
			name:    "superbased command skipped",
			in:      "superbased start",
			changed: false,
		},
		{
			name:    "superbased with leading path skipped",
			in:      "/usr/local/bin/superbased status",
			changed: false,
		},
		{
			name:    "empty string",
			in:      "",
			changed: false,
		},
		{
			name:    "whitespace-only",
			in:      "   \t  ",
			changed: false,
		},
		{
			name:    "trailing newline ok",
			in:      "git log\n",
			want:    bin + " run -- git log",
			changed: true,
		},
		{
			name:    "unbalanced quote disqualifies",
			in:      "echo 'unterminated",
			changed: false,
		},
		{
			name:    "interior newline disqualifies",
			in:      "cd /tmp\nls",
			changed: false,
		},
		{
			name:    "multi-line non-builtin disqualifies",
			in:      "git status\ngit log",
			changed: false,
		},
		{
			name:    "carriage return disqualifies",
			in:      "git status\r\ngit log",
			changed: false,
		},
		{
			name:    "bare cd builtin skipped",
			in:      "cd /tmp",
			changed: false,
		},
		{
			name:    "export builtin skipped",
			in:      "export FOO=bar",
			changed: false,
		},
		{
			name:    "source builtin skipped",
			in:      "source ./env.sh",
			changed: false,
		},
		{
			name:    "dot-source builtin skipped",
			in:      ". ./env.sh",
			changed: false,
		},
		{
			name:    "eval builtin skipped",
			in:      "eval echo hi",
			changed: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := RewriteBash(bin, tc.in, excl)
			if changed != tc.changed {
				t.Fatalf("changed: got %v want %v (got=%q)", changed, tc.changed, got)
			}
			if changed && got != tc.want {
				t.Fatalf("rewritten: got %q want %q", got, tc.want)
			}
			if !changed && got != tc.in {
				t.Fatalf("unchanged should return original, got %q want %q", got, tc.in)
			}
		})
	}
}

// TestRewriteBashQuotesTheBinary pins FU-163: the binary is one POSIX shell
// word, so a path with a space (Windows `Program Files`) is not split and a
// backslash or a quote reaches exec as written.
func TestRewriteBashQuotesTheBinary(t *testing.T) {
	cases := []struct{ bin, want string }{
		{"/usr/local/bin/observer", "/usr/local/bin/observer run -- git status"},
		{"C:/Users/dev/AppData/Local/SuperBased/Observer/bin/observer.exe", "C:/Users/dev/AppData/Local/SuperBased/Observer/bin/observer.exe run -- git status"},
		{"C:/Program Files/SuperBased/observer.exe", "'C:/Program Files/SuperBased/observer.exe' run -- git status"},
		{"/home/a b/observer", "'/home/a b/observer' run -- git status"},
		{`C:\observer\observer.exe`, `'C:\observer\observer.exe' run -- git status`},
		{"/opt/it's/observer", `'/opt/it'\''s/observer' run -- git status`},
		{"/opt/x=y/observer", "'/opt/x=y/observer' run -- git status"},
		{"~/bin/observer", "'~/bin/observer' run -- git status"},
		{"/opt/$x/observer", "'/opt/$x/observer' run -- git status"},
	}
	for _, tc := range cases {
		got, changed := RewriteBash(tc.bin, "git status", nil)
		if !changed || got != tc.want {
			t.Errorf("RewriteBash(%q) = %q, %v; want %q", tc.bin, got, changed, tc.want)
		}
	}
}

func TestRewriteBashEmptyBinary(t *testing.T) {
	got, changed := RewriteBash("", "git status", nil)
	if changed {
		t.Fatalf("want no rewrite with empty binary, got %q", got)
	}
}
