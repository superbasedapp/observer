package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
)

// box_env_posture.go shows a box's environment in the run's posture (WINFIX2
// audit finding 1, tracker R-167): every backend builds it from the
// allow-list of internal/sandboxenv, and the names the user added with
// [terminal.sandbox].pass_env are said on the tool's terminal, by the
// launcher inside the box, whatever the backend or entry point. The run's
// inner log gets one line either way.

// sandboxEnvPostureLine is the inner log's line for a box whose launch named
// allow (provider variables and pass_env) and passed (pass_env alone).
func sandboxEnvPostureLine(allow, passed []string) string {
	p := "none"
	if len(passed) > 0 {
		p = strings.Join(passed, ",")
	}
	return fmt.Sprintf("box environment: allow-list (the OS table, %d provider or pass_env name(s), Observer's own); pass_env: %s", len(allow), p)
}

// sandboxEnvPostureNotice is the terminal's line, "" when pass_env added
// nothing.
func sandboxEnvPostureNotice(passed []string) string {
	if len(passed) == 0 {
		return ""
	}
	return "observer sandbox: [terminal.sandbox].pass_env passes " + strings.Join(passed, ", ") + " into this box"
}

// sandboxSignInSharedNotice is the terminal's line for a box whose backend
// shares tool's own state, sign-in included (operator ruling P-183), ""
// when there is nothing to say. Set by terminal_sandbox_signin.go; nil in a
// build without the sandbox.
var sandboxSignInSharedNotice func(tool string) string

// sandboxEnvPosture writes both, read from this process's environment (the
// launcher inside the box), and the shared sign-in line when the launch
// named one.
func sandboxEnvPosture(w io.Writer) {
	allow := sandboxenv.Decode(os.Getenv(sandboxenv.EnvAllow))
	passed := sandboxenv.Decode(os.Getenv(sandboxenv.EnvPassed))
	appendBoxInnerLog(sandboxEnvPostureLine(allow, passed))
	if s := sandboxEnvPostureNotice(passed); s != "" && w != nil {
		fmt.Fprintln(w, s)
	}
	if f, tool := sandboxSignInSharedNotice, os.Getenv(sandboxenv.EnvSignInShared); f != nil && tool != "" {
		if s := f(tool); s != "" {
			appendBoxInnerLog(s)
			if w != nil {
				fmt.Fprintln(w, s)
			}
		}
	}
}
