package toolresolve

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The login-shell environment probe (surface-gap CLI-4, lane w4-homes-b). A
// tool home variable (QWEN_HOME, GROK_HOME, COPILOT_HOME, ...) the developer
// exports in a shell profile reaches the tools they run from that shell, but
// not a daemon started some other way, so the daemon's writers and the tool
// can disagree on the home. The probe reads named variables from the login
// shell the way the PATH capture does: a marker pair around NAME=value
// lines, so rc-file banners are discarded. The script and the parser live
// here (pure); the exec lives in internal/toolresolve/host.

// EnvMarkBegin and EnvMarkEnd delimit the captured variables.
const (
	EnvMarkBegin = "__SB_ENV_BEGIN__"
	EnvMarkEnd   = "__SB_ENV_END__"
)

// ErrNoEnvMarkers reports a capture without exactly one well-formed marker
// pair; the attempt is discarded, never half-trusted.
var ErrNoEnvMarkers = errors.New("toolresolve: login capture carried no well-formed environment marker pair")

// envName is the only variable-name shape the probe interpolates into a
// shell script.
var envName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// shellExpand is the shell's parameter-expansion sigil. It is a named
// constant so the script builder reads as what it is (a variable
// reference, not a dollar figure; TestNoBareUSDInDeveloperSurfaces).
const shellExpand = "$"

// LoginEnvScript is the shell snippet that prints each named variable as one
// NAME=value line between the markers. It is valid POSIX sh and fish ("$X"
// is empty for an unset X in both). A name outside [A-Z][A-Z0-9_]* is an
// error: names are spliced into the script.
func LoginEnvScript(names []string) (string, error) {
	var b strings.Builder
	b.WriteString("printf '\\n" + EnvMarkBegin + "\\n'")
	for _, n := range names {
		if !envName.MatchString(n) {
			return "", fmt.Errorf("toolresolve.LoginEnvScript: %q is not a variable name", n)
		}
		b.WriteString("; printf '" + n + "=%s\\n' \"" + shellExpand + n + "\"")
	}
	b.WriteString("; printf '" + EnvMarkEnd + "\\n'")
	return b.String(), nil
}

// ParseEnvMarkers extracts the NAME=value lines a capture printed between
// the markers. A name printed with an empty value is present with "". A
// line that is not NAME=value is ignored.
func ParseEnvMarkers(out string) (map[string]string, error) {
	if strings.Count(out, EnvMarkBegin) != 1 || strings.Count(out, EnvMarkEnd) != 1 {
		return nil, ErrNoEnvMarkers
	}
	i := strings.Index(out, EnvMarkBegin)
	j := strings.Index(out, EnvMarkEnd)
	if j < i {
		return nil, ErrNoEnvMarkers
	}
	got := map[string]string{}
	for _, line := range strings.Split(out[i+len(EnvMarkBegin):j], "\n") {
		line = strings.TrimRight(line, "\r")
		k, v, ok := strings.Cut(line, "=")
		if !ok || !envName.MatchString(k) {
			continue
		}
		got[k] = v
	}
	return got, nil
}
