package pairing

import (
	"errors"
	"fmt"
	"strings"
)

// How a node takes a pairing code in (plan 06 section 19.3 rule 2): through
// the environment (SBO_PAIR_CODE, which the install one-liner sets for the
// installer) or a file (--pair-file), never as a command-line argument,
// where every local user can read it in the process list and it lands in
// shell history.

// maxPairFileBytes bounds a --pair-file read: a code is at most MaxCodeLen
// characters, plus a line ending.
const maxPairFileBytes = MaxCodeLen + 64

// Source is where a taken code came from.
type Source string

// The sources.
const (
	// SourceNone: no code was supplied.
	SourceNone Source = ""
	// SourceEnv: the SBO_PAIR_CODE environment variable.
	SourceEnv Source = "env"
	// SourceFile: a --pair-file.
	SourceFile Source = "file"
)

// Hand-off errors.
var (
	// ErrTwoSources: both SBO_PAIR_CODE and --pair-file were given.
	ErrTwoSources = errors.New("pairing: both " + EnvVar + " and --pair-file are set; give the code one way")
	// ErrArgument: a pairing code was given as a command-line argument.
	ErrArgument = errors.New("pairing: a pairing code is never passed on the command line (other local users can read it there); set " + EnvVar + " or use --pair-file")
)

// Handoff is everything Take reads. The caller owns the I/O: Env is the
// variable's value, and ReadFile reads PairFile.
type Handoff struct {
	// Env is SBO_PAIR_CODE's value ("" when unset).
	Env string
	// PairFile is the --pair-file path ("" when not given).
	PairFile string
	// ReadFile reads PairFile; it must return at most a few hundred bytes'
	// worth for a valid code (Take refuses anything longer).
	ReadFile func(path string) ([]byte, error)
}

// Taken is a pairing code a node took in.
type Taken struct {
	// Code is the parsed code (zero when Source is SourceNone).
	Code Code
	// Source is where it came from.
	Source Source
}

// handoffRule is one row of the hand-off table, walked top-down.
type handoffRule struct {
	name string
	when func(h Handoff) bool
	take func(h Handoff) (Taken, error)
}

// handoffRules is the ordered hand-off table. One test case per row.
var handoffRules = []handoffRule{
	{
		name: "both sources",
		when: func(h Handoff) bool { return strings.TrimSpace(h.Env) != "" && h.PairFile != "" },
		take: func(Handoff) (Taken, error) { return Taken{}, ErrTwoSources },
	},
	{
		name: "pair file",
		when: func(h Handoff) bool { return h.PairFile != "" },
		take: takeFile,
	},
	{
		name: "environment",
		when: func(h Handoff) bool { return strings.TrimSpace(h.Env) != "" },
		take: func(h Handoff) (Taken, error) {
			c, err := Parse(h.Env)
			if err != nil {
				return Taken{}, fmt.Errorf("%s: %w", EnvVar, err)
			}
			return Taken{Code: c, Source: SourceEnv}, nil
		},
	},
	{
		name: "none",
		when: func(Handoff) bool { return true },
		take: func(Handoff) (Taken, error) { return Taken{}, nil },
	},
}

// Take resolves the pairing code a node was handed, if any. No code is not
// an error (Source is SourceNone); a code that is there but unusable is.
func Take(h Handoff) (Taken, error) {
	for _, r := range handoffRules {
		if r.when(h) {
			return r.take(h)
		}
	}
	return Taken{}, nil // unreachable: the last row matches everything
}

func takeFile(h Handoff) (Taken, error) {
	if h.ReadFile == nil {
		return Taken{}, errors.New("pairing: no file reader")
	}
	raw, err := h.ReadFile(h.PairFile)
	if err != nil {
		return Taken{}, fmt.Errorf("pairing: read --pair-file: %w", err)
	}
	if len(raw) > maxPairFileBytes {
		return Taken{}, fmt.Errorf("%w: --pair-file holds more than a pairing code", ErrMalformed)
	}
	c, err := Parse(string(raw))
	if err != nil {
		return Taken{}, fmt.Errorf("--pair-file: %w", err)
	}
	return Taken{Code: c, Source: SourceFile}, nil
}

// RefuseArgument returns ErrArgument when arg is a pairing code, so a
// command that takes positional arguments never accepts one there.
func RefuseArgument(arg string) error {
	if IsPairingCode(arg) {
		return ErrArgument
	}
	return nil
}
