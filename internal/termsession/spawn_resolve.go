package termsession

import (
	"errors"
	"fmt"
	"os/exec"
)

// spawn_resolve.go is the PLATFORM-NEUTRAL half of the Spec argv contract:
// "argv[0] is the program, resolved via PATH". It carries no build tag so the
// table test runs on every OS, and both OS spawners call it — the unix one for
// symmetry (exec.Command would do the same lookup implicitly) and the Windows
// one out of necessity (CreateProcess with a NULL lpApplicationName appends
// only ".exe" and never consults %PATHEXT%, so a bare `npm` — an npm.cmd shim —
// fails with ERROR_FILE_NOT_FOUND; DI-01).

// lookProgram is the PATH (and, on Windows, %PATHEXT%) search the OS spawners
// use to resolve a bare argv[0]. It is a package-level variable ONLY so tests
// can inject a fake PATH; production always uses exec.LookPath.
var lookProgram = exec.LookPath

// resolveSpawnArgv returns argv with argv[0] rewritten to the absolute program
// path [exec.LookPath] finds for it, leaving the arguments untouched. An
// already-absolute argv[0] round-trips through LookPath (which then only
// verifies it is executable), so callers need no special case.
//
// A cwd-only hit ([exec.ErrDot], Go 1.19+) is a REFUSAL, not a resolution: a
// long-lived daemon must never execute a program just because a file of that
// name sits in its working directory.
//
// An empty argv (or an empty argv[0]) is [ErrInvalidSpec] — the same
// fail-closed verdict Manager.Create gives a Spec with no program.
func resolveSpawnArgv(argv []string) ([]string, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, ErrInvalidSpec
	}
	p, err := lookProgram(argv[0])
	if errors.Is(err, exec.ErrDot) {
		return nil, fmt.Errorf("termsession: %q resolves only in the daemon's working directory — refusing to launch it: %w", argv[0], err)
	}
	if err != nil {
		return nil, fmt.Errorf("termsession: cannot find %q on PATH: %w", argv[0], err)
	}
	out := make([]string, 0, len(argv))
	out = append(out, p)
	return append(out, argv[1:]...), nil
}
