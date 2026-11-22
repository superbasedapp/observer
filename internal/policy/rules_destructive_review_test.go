package policy

import (
	"strings"
	"testing"
)

// r101Hits turns command lines into R-101 deny rows.
func r101Hits(dialect Dialect, cmds ...string) []destructiveCase {
	out := make([]destructiveCase, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, destructiveCase{name: "R-101 hit: " + c, cmd: c, dialect: dialect, wantRule: "R-101", wantEnforce: DecisionDeny})
	}
	return out
}

// TestR101BehindSudoAssignmentsAndEnvDash pins FR-SEC-4 (review
// 2026-11-22): sudo accepts VAR=value operands before the command (the
// `sudo DEBIAN_FRONTEND=noninteractive cmd` idiom) and GNU env reads a
// lone `-` as `-i`. Both left the assignment (or the dash) as the unit's
// Base, so every Base-keyed rule was blind behind them.
func TestR101BehindSudoAssignmentsAndEnvDash(t *testing.T) {
	t.Parallel()
	cases := r101Hits(DialectPosix,
		"sudo FOO=1 rm -rf ~",
		"sudo DEBIAN_FRONTEND=noninteractive rm -rf ~",
		"sudo -E PATH=/x rm -rf ~",
		"sudo -u root A=1 B=2 rm -rf ~",
		"env - rm -rf ~",
		"env -i - rm -rf ~",
		"env - FOO=1 rm -rf ~",
	)
	cases = append(cases, r101Hits(DialectCmd, "sudo FOO=1 rm -rf ~")...)
	cases = append(cases,
		destructiveCase{name: "R-101 near-miss: sudo assignment inside project", cmd: "sudo DEBIAN_FRONTEND=noninteractive rm -rf ./build"},
		destructiveCase{name: "R-101 near-miss: env - inside project", cmd: "env - rm -rf ./build"},
	)
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// fr7ArgvPrefixes are FR-SEC-7's measured exec prefixes (review
// 2026-11-22) that run their argv as a command, one or more shapes each
// with the value flags and leading operands from the tool's man page.
var fr7ArgvPrefixes = []string{
	"setpriv --reuid=1000 --regid=1000 --init-groups rm -rf ~",
	"setpriv --reuid 1000 --groups 10,20 rm -rf ~",
	"setpriv --nnp --pdeathsig keep rm -rf ~",
	"prlimit --nofile=1024:2048 rm -rf ~",
	"prlimit --cpu=10 -- rm -rf ~",
	"numactl --interleave all rm -rf ~",
	"numactl -N 0 -m 0 rm -rf ~",
	"numactl --physcpubind=0-3 rm -rf ~",
	"numactl -l rm -rf ~",
	"cgexec -g cpu:mygroup rm -rf ~",
	"cgexec -g cpu,memory:/g --sticky rm -rf ~",
	"systemd-inhibit --what=sleep --why backup rm -rf ~",
	"systemd-inhibit --who me --mode block rm -rf ~",
	"unbuffer -p rm -rf ~",
	"chronic -ev rm -rf ~",
	"firejail --noprofile --private=/tmp/x rm -rf ~",
	"firejail rm -rf ~",
	"proxychains rm -rf ~",
	"proxychains4 -q -f /etc/p.conf rm -rf ~",
	"torsocks -a 127.0.0.1 -P 9050 rm -rf ~",
	"torsocks rm -rf ~",
	"setarch x86_64 -R rm -rf ~",
	"setarch -R rm -rf ~",
	"setarch i686 rm -rf ~",
	"linux32 rm -rf ~",
	"linux32 -R rm -rf ~",
	"linux64 rm -rf ~",
	"dbus-run-session -- rm -rf ~",
	"dbus-run-session --config-file=/x.conf rm -rf ~",
	"dbus-run-session --dbus-daemon /usr/bin/dbus-daemon rm -rf ~",
	"xvfb-run -a -s '-screen 0 1024x768x24' rm -rf ~",
	"xvfb-run --server-num=99 -e /tmp/err rm -rf ~",
	"ssh-agent rm -rf ~",
	"ssh-agent -t 60 -a /tmp/s rm -rf ~",
}

// fr7LinePrefixes are FR-SEC-7's prefixes that run a SHELL LINE (sg, GNU
// parallel, sudo -s / -i): the line is parsed one level deeper.
var fr7LinePrefixes = []string{
	"sg wheel -c 'rm -rf ~'",
	"sg wheel 'rm -rf ~'",
	"sg - wheel -c 'rm -rf ~'",
	"parallel rm -rf ~",
	"parallel -j4 rm -rf ::: ~",
	"parallel 'rm -rf {}' ::: ~",
	"parallel --jobs 2 --joblog /tmp/j rm -rf ~",
	"sudo -s -- 'rm -rf ~'",
	"sudo -i 'rm -rf ~'",
	"sudo -iu root 'rm -rf ~'",
	"sudo --login 'rm -rf ~'",
	"sudo -E -s 'rm -rf ~'",
	"sudo -s rm -rf ~",
}

// fr7ValueFlags are FR-SEC-7's missing value flags on prefixes already in
// the table.
var fr7ValueFlags = []string{
	"env -a sh rm -rf ~",
	"env --argv0 sh rm -rf ~",
	"exec -a name rm -rf ~",
	"/usr/bin/time -f %e rm -rf ~",
	"time -o /tmp/t rm -rf ~",
	"/usr/bin/time --format=%e --output /tmp/t rm -rf ~",
	"stdbuf --output L rm -rf ~",
	"stdbuf --input 0 --error L rm -rf ~",
	"strace --trace-fds 3 rm -rf ~",
	"xargs --process-slot-var X rm -rf ~",
	"nsenter -N 3 rm -rf ~",
	"nsenter --net-socket 3 rm -rf ~",
	"unshare --owner 0:0 rm -rf ~",
}

// TestR101BehindMissingExecPrefixes pins the table part of FR-SEC-7: every
// measured prefix, value flag and shell-line form is unwrapped, so R-101
// sees the delete. One row per shape.
func TestR101BehindMissingExecPrefixes(t *testing.T) {
	t.Parallel()
	var cases []destructiveCase
	for _, group := range [][]string{fr7ArgvPrefixes, fr7LinePrefixes, fr7ValueFlags} {
		cases = append(cases, r101Hits(DialectPosix, group...)...)
	}
	cases = append(cases,
		destructiveCase{name: "R-101 near-miss: numactl inside project", cmd: "numactl -l rm -rf ./build"},
		destructiveCase{name: "R-101 near-miss: sudo -s inside project", cmd: "sudo -s 'rm -rf ./build'"},
		destructiveCase{name: "R-101 near-miss: sg inside project", cmd: "sg wheel -c 'rm -rf ./build'"},
	)
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestParseCommand_FR7Prefixes pins how the new rows parse: an argv
// prefix is stripped (the command is the unit's Base, the prefix is in
// Wrappers); a shell-line prefix stays the outer unit and its line is
// parsed one level deeper; a bare prefix stays visible as itself.
func TestParseCommand_FR7Prefixes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in       string
		wantBase string
		wrappers []string
	}{
		{"setpriv --reuid 1000 rm -rf ~", "rm", []string{"setpriv"}},
		{"numactl --interleave all make", "make", []string{"numactl"}},
		{"setarch x86_64 -R make", "make", []string{"setarch"}},
		{"setarch -R make", "make", []string{"setarch"}},
		{"xvfb-run -a -s '-screen 0 1024x768x24' npm test", "npm", []string{"xvfb-run"}},
		{"sudo DEBIAN_FRONTEND=noninteractive apt-get install -y foo", "apt-get", []string{"sudo"}},
		{"ssh-agent -s", "ssh-agent", nil},
		{"sudo -i", "sudo", nil},
		{"dbus-run-session", "dbus-run-session", nil},
	} {
		cmds := ParseCommand(tc.in, DialectPosix)
		if len(cmds) == 0 || cmds[0].Base != tc.wantBase || !equalStrings(cmds[0].Wrappers, tc.wrappers) {
			t.Errorf("ParseCommand(%q) = %s, want Base %q with wrappers %v", tc.in, bases(cmds), tc.wantBase, tc.wrappers)
		}
	}
	for _, tc := range []struct{ in, outer string }{
		{"sudo -i 'rm -rf ~'", "sudo"},
		{"sudo -s -- 'rm -rf ~'", "sudo"},
		{"sg wheel 'rm -rf ~'", "sg"},
		{"parallel 'rm -rf {}' ::: ~", "parallel"},
	} {
		cmds := ParseCommand(tc.in, DialectPosix)
		if len(cmds) < 2 || cmds[0].Base != tc.outer || cmds[1].Base != "rm" || cmds[1].Depth != 1 {
			t.Errorf("ParseCommand(%q) = %s, want outer %s and an inner rm at depth 1", tc.in, bases(cmds), tc.outer)
		}
	}
}

// equalStrings reports whether two string slices hold the same words in
// order (nil and empty are equal).
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// unknownPrefixAsks builds R-102/ask rows: the delete behind an unknown
// command prefix is re-judged and asked about, never denied.
func unknownPrefixAsks(dialect Dialect, cmds ...string) []destructiveCase {
	out := make([]destructiveCase, 0, len(cmds))
	for _, c := range cmds {
		out = append(out, destructiveCase{name: "fallback ask: " + c, cmd: c, dialect: dialect, wantRule: "R-102", wantEnforce: DecisionAsk})
	}
	return out
}

// TestUnknownPrefixFallback pins FR-SEC-7's fallback (operator ruling
// 2026-11-22: build it). The wrapper table will always lag, so a unit whose
// Base is a command the guard does not know is re-judged from the first
// later word that is a delete command (rm, rmdir, rd, del, erase,
// Remove-Item); when that unit is a catastrophic delete (R-101), the verdict
// is ASK under R-102, never deny and never allow, and the reason names the
// unknown prefix. Known commands (wrapper rows, bases a rule keys on, and a
// small table of non-executing commands) are not re-judged.
func TestUnknownPrefixFallback(t *testing.T) {
	t.Parallel()
	cases := unknownPrefixAsks(DialectPosix,
		"mywrap rm -rf ~",
		"mywrap --flag value rm -rf ~",
		"/opt/tools/mywrap rm -rf /",
		"mywrap /bin/rm -rf ~",
		"mywrap rm -rf /*",
		"sudo mywrap rm -rf ~",
		"mywrap sudo rm -rf ~",
		"cpulimit -l 50 rm -rf ~",
		"trickle -d 100 rm -rf ~",
		"catchsegv rm -rf ~",
		"valgrind --leak-check=full rm -rf ~",
		"bwrap --bind / / rm -rf ~",
		"proot -0 rm -rf ~",
		"gdb --args rm -rf ~",
	)
	cases = append(cases, unknownPrefixAsks(DialectPowerShell, "mywrap Remove-Item -Recurse -Force ~")...)
	cases = append(cases, unknownPrefixAsks(DialectCmd, `mywrap rd /s /q C:\`)...)
	cases = append(cases,
		// Near-misses: the delete behind the prefix is not catastrophic.
		destructiveCase{name: "near-miss: inside the project", cmd: "mywrap rm -rf ./build"},
		destructiveCase{name: "near-miss: not recursive", cmd: "mywrap rm ~/x"},
		destructiveCase{name: "near-miss: no delete word", cmd: "mywrap -rf ~"},
		// Honest commands the brief lists keep their verdict (no hit).
		destructiveCase{name: "honest: grep rm file", cmd: "grep rm file"},
		destructiveCase{name: "honest: echo", cmd: "echo rm -rf ~"},
		destructiveCase{name: "honest: printf", cmd: "printf '%s\\n' rm -rf ~"},
		destructiveCase{name: "honest: git rm --cached", cmd: "git rm -r --cached x"},
		destructiveCase{name: "honest: make clean", cmd: "make clean"},
		destructiveCase{name: "honest: npm run rm", cmd: "npm run rm"},
		destructiveCase{name: "honest: man", cmd: "man rm"},
		destructiveCase{name: "honest: which", cmd: "which rm"},
		destructiveCase{name: "honest: type", cmd: "type rm"},
		destructiveCase{name: "honest: command -v", cmd: "command -v rm"},
		destructiveCase{name: "honest: apropos", cmd: "apropos rm"},
		destructiveCase{name: "honest: history | grep", cmd: "history | grep 'rm -rf'"},
		destructiveCase{name: "honest: git commit message", cmd: "git commit -m 'drop rm -rf ~ from setup'"},
	)
	runRuleCases(t, cases, KindShellExec, "run_command")

	// The reason names the unknown prefix, and a known destructive command
	// keeps R-101's deny (the fallback never lowers it).
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	ev := shellEvent("mywrap rm -rf ~")
	if v := eng.Evaluate(ev); !strings.Contains(v.Reason, "mywrap") {
		t.Errorf("reason %q does not name the unknown prefix", v.Reason)
	}
	ev = shellEvent("mywrap rm -rf ~; rm -rf ~")
	if v := eng.Evaluate(ev); v.RuleID != "R-101" || v.Decision != DecisionDeny {
		t.Errorf("Evaluate(mywrap ...; rm -rf ~) = %s/%v, want R-101/deny", v.RuleID, v.Decision)
	}
}
