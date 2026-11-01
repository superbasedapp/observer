package secdiffobs

import (
	"regexp"
	"strings"
	"time"
)

// fixobs.go is the pure half of fix observations (security pillar plan
// section 5.11 (a), lane SEC-G5): facts, never a fix claim. A finding the
// rule no longer reports is already not_reproduced; it moves to
// fixed_verified only when the session that last edited its file was SEEN
// running a test-class command after that edit, the host reported that
// command's success (an exit code of 0, or only a success flag, which the
// record calls "host reported success", never "exit code 0"), and no test
// file was edited in that session's change. The record says "observed test
// command" with the command class and what the host reported, never "tests
// passed": Observer did not run those tests in a defined environment.

// testCommands is the closed test-command class table, walked top-down.
var testCommands = []struct {
	Class string
	Re    *regexp.Regexp
}{
	{"go_test", seg(`(\S*/)?go\s+test\b`)},
	{"pytest", seg(`(py\.?test|python3?\s+-m\s+(pytest|unittest))\b`)},
	{"js_test", seg(`((npm|pnpm|yarn|bun)\s+(run\s+)?test\b|(npx\s+)?(jest|vitest|mocha)\b)`)},
	{"cargo_test", seg(`cargo\s+(test|nextest)\b`)},
	{"dotnet_test", seg(`dotnet\s+test\b`)},
	{"jvm_test", seg(`(mvn\w*|\./mvnw|gradle\w*|\./gradlew)\b[^\n;&|]*\btest\b`)},
	{"ruby_test", seg(`(rspec|(bundle\s+exec\s+)?rake\s+test|rails\s+test)\b`)},
	{"make_test", seg(`make\s+(test|check)\b`)},
}

// seg anchors a test command at the start of a shell command segment (the
// line start, or after ;, &, | or an opening parenthesis), allowing leading
// VAR=value assignments, so `echo pytest` or `cat test.txt` is not a test
// command.
func seg(cmd string) *regexp.Regexp {
	return regexp.MustCompile(`(^|[;&|(])\s*(\w+=\S*\s+)*` + cmd)
}

// TestCommandClass returns the command's test class, "" when it is not a
// test command. Only the class is ever recorded, never the command.
func TestCommandClass(cmd string) string {
	for _, t := range testCommands {
		if t.Re.MatchString(cmd) {
			return t.Class
		}
	}
	return ""
}

// SessionCommand is one command the session ran.
type SessionCommand struct {
	At      time.Time
	Command string
	// ExitKnown: the host reported the command's result, either an exit
	// code (ExitCode) or only a success flag (HostReportedSuccess, with
	// ExitCode 0).
	ExitKnown           bool
	ExitCode            int
	HostReportedSuccess bool
}

// FixEvidence is what the session that last edited a finding's file shows.
type FixEvidence struct {
	// LastEditAt is that session's last edit of the file; zero when no AI
	// edit of the file is known.
	LastEditAt time.Time
	// Commands are the session's commands after LastEditAt, oldest first.
	Commands []SessionCommand
	// EditedPaths are the files the session edited (its change).
	EditedPaths []string
}

// The FixVerdict reasons, one per decision row.
const (
	FixVerified          = "observed_test_command"
	FixNoEdit            = "no_ai_edit_of_file"
	FixTestFileEdited    = "test_file_edited"
	FixNoTestCommand     = "no_test_command_after_edit"
	FixExitUnknown       = "test_exit_unknown"
	FixTestCommandFailed = "test_command_nonzero_exit"
)

// FixVerdict is the decision: Verified only for the observed_test_command
// row; Class and ExitCode name the last test-class command after the edit,
// and HostReportedSuccess says its success came from the host's success
// flag with no exit code recorded.
type FixVerdict struct {
	Verified            bool
	Reason              string
	Class               string
	ExitCode            int
	HostReportedSuccess bool
}

// Detail is the record's wording: an observed command, never "tests passed".
func (v FixVerdict) Detail() string {
	if !v.Verified {
		return v.Reason
	}
	if v.HostReportedSuccess {
		return "observed test command: class " + v.Class + ", host reported success (no exit code recorded); Observer did not run the tests"
	}
	return "observed test command: class " + v.Class + ", exit code 0 (as the host reported it); Observer did not run the tests"
}

// DecideFix walks the decision rows top-down.
func DecideFix(ev FixEvidence) FixVerdict {
	if ev.LastEditAt.IsZero() {
		return FixVerdict{Reason: FixNoEdit}
	}
	for _, p := range ev.EditedPaths {
		if IsTestPath(p) {
			return FixVerdict{Reason: FixTestFileEdited}
		}
	}
	var last *SessionCommand
	class := ""
	for i := range ev.Commands {
		c := &ev.Commands[i]
		if !c.At.After(ev.LastEditAt) {
			continue
		}
		if k := TestCommandClass(c.Command); k != "" {
			last, class = c, k
		}
	}
	switch {
	case last == nil:
		return FixVerdict{Reason: FixNoTestCommand}
	case !last.ExitKnown:
		return FixVerdict{Reason: FixExitUnknown, Class: class}
	case last.ExitCode != 0:
		return FixVerdict{Reason: FixTestCommandFailed, Class: class, ExitCode: last.ExitCode}
	}
	return FixVerdict{Verified: true, Reason: FixVerified, Class: class, HostReportedSuccess: last.HostReportedSuccess}
}

// fixClaim is the closed fix-claim phrase table over a commit subject
// (unverified_fix): a fix verb near a security word, a "security fix" or a
// CVE id.
var fixClaim = []*regexp.Regexp{
	regexp.MustCompile(`\b(fix(es|ed)?|patch(es|ed)?|resolve[sd]?|mitigate[sd]?|harden(s|ed)?|sanitiz(e|es|ed)|close[sd]?)\b.{0,40}\b(security|vulnerab\w*|vuln\w*|injection|xss|csrf|ssrf|traversal|secrets?|leak\w*|auth\w*|tls|cors|sqli|rce|exploit\w*)\b`),
	regexp.MustCompile(`\bsecurity\s+(fix|patch)\b`),
	regexp.MustCompile(`\bcve-\d{4}-\d{4,}\b`),
	regexp.MustCompile(`\bghsa(-[a-z0-9]{4}){3}\b`),
}

// ClaimsFix reports whether a commit subject claims a security fix. Only
// the yes or no leaves this function; the subject is never recorded.
func ClaimsFix(subject string) bool {
	s := strings.ToLower(subject)
	for _, re := range fixClaim {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
