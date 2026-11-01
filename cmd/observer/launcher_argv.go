// launcher_argv.go — shared manual argv parser for the `observer <tool>`
// launcher family (backlog B6).
//
// The launcher commands run with cobra's DisableFlagParsing=true so that
// arbitrary flags meant for the WRAPPED tool (e.g. `observer claude --model
// sonnet`) survive untouched instead of being rejected by cobra as unknown
// flags on the wrapper command. That means the wrapper's OWN flags (--proxy,
// --config, --verify, ...) are no longer parsed for it either — this file is
// the replacement: it walks argv once, recognizes exactly the flags the
// command itself registered, applies their values the same way pflag would
// have, and returns everything else as passthrough argv for the wrapped
// tool's own exec.
package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// errLauncherHelpShown is the sentinel splitLauncherArgs returns when argv
// contained the command's own help flag (long or short) resolved to true.
// By the time this is returned, cmd.Help() has already been called and its
// output written to cmd.OutOrStdout(). launcherArgsOrDone converts this
// sentinel into (nil, true, nil) so callers can treat "help was shown" as a
// clean, non-error stop condition without stringly-matching an error value.
var errLauncherHelpShown = errors.New("launcher: help flag shown")

// reservedLauncherFlags derives the set of flag spellings a launcher command
// already understands itself, keyed by literal argv form: "--name" for every
// long flag name registered on fs, plus "-x" for any non-empty shorthand.
//
// Flag registration (StringVar/BoolVar/IntVar/... at cobra.Command
// construction, plus cobra's own InitDefaultHelpFlag for -h/--help) happens
// unconditionally of DisableFlagParsing — pflag records the Var binding,
// default value, and NoOptDefVal the moment the flag is declared, regardless
// of whether the FlagSet ever actually parses an argv slice. That means
// deriving the reserved set LIVE from fs.VisitAll here is sound: it always
// reflects exactly what this command would have consumed had
// DisableFlagParsing been false, including any flag whose registration is
// itself gated behind a build or runtime capability check — there is no
// separate list to keep in sync with those call sites.
//
// Caution for anyone adding a new launcher flag: a wrapper shorthand
// PERMANENTLY SHADOWS the same shorthand on every wrapped tool's own CLI.
// If this command reserves "-m" for its own flag and the wrapped tool also
// has a "-m" meaning something else, `observer <tool> -m x` is consumed by
// the wrapper, not passed through — the operator has to spell out the
// tool's long-form flag instead. That's inherent to any argv-splitting
// wrapper and is not something this function can fix; keep wrapper
// shorthands rare and well-known for exactly this reason.
func reservedLauncherFlags(fs *pflag.FlagSet) map[string]*pflag.Flag {
	reserved := make(map[string]*pflag.Flag)
	fs.VisitAll(func(f *pflag.Flag) {
		reserved["--"+f.Name] = f
		if f.Shorthand != "" {
			reserved["-"+f.Shorthand] = f
		}
	})
	return reserved
}

// splitFlagEq splits a single argv token that starts with '-' into a flag
// spelling and an optional '='-joined value, e.g. "--config=/x" splits into
// name="--config", val="/x", hasEq=true, while "--config" (no '=') splits
// into name="--config", val="", hasEq=false. The returned name retains its
// leading dash(es) so it can be looked up directly in the map
// reservedLauncherFlags returns. hasEq distinguishes "no value present" from
// "value is the empty string" (e.g. "--config=") — callers must consult it
// rather than testing val == "".
func splitFlagEq(tok string) (name, val string, hasEq bool) {
	if i := strings.IndexByte(tok, '='); i >= 0 {
		return tok[:i], tok[i+1:], true
	}
	return tok, "", false
}

// splitLauncherArgs is the DisableFlagParsing=true replacement for cobra's
// normal flag parse. It walks argv token by token against cmd's OWN
// already-registered flags (reservedLauncherFlags, derived live from
// cmd.Flags()) and returns the tokens that are NOT this command's own flags,
// in original order, for the caller to hand to the wrapped tool's exec.
//
// Recognized forms for a reserved flag, matching pflag's own parsing:
//   - "--flag value" / "-f value": value is the next argv token. Requires a
//     following token to exist; if argv ends right after the flag this is
//     malformed and returns an error naming the command and the flag.
//   - "--flag=value" / "-f=value": value is the '='-joined text, with no
//     token consumed beyond the one token itself.
//   - Bare "--flag" / "-f" for a flag with a non-empty NoOptDefVal
//     (bool-shaped, e.g. registered via BoolVar): consumes NO following
//     token — the flag's own NoOptDefVal (usually "true") is applied, same
//     as pflag's own bare-boolean-flag behavior. This is what distinguishes
//     `observer claude --verify rest` (verify=true, "rest" passed through)
//     from `observer claude --config rest` (config="rest", nothing passed
//     through for that pair).
//   - Bare "--flag" / "-f" for a flag WITHOUT a NoOptDefVal (value-shaped,
//     e.g. string/int): when nothing is left in argv to supply the value,
//     this is malformed and returns an error naming the command and the flag.
//
// Values are applied via cmd.Flags().Set(name, value) — the same entry
// point pflag's own parser uses — so bound Go variables (StringVar, BoolVar,
// IntVar, ...) populate identically to a normal parse. A value a reserved
// flag's own Set rejects (e.g. a non-integer for an IntVar) is wrapped into
// an error naming the command and flag; it is never silently dropped.
//
// "--" (the bare separator, exactly two dashes and nothing else) ends
// option processing: every token after it is unconditional passthrough
// regardless of spelling, and the "--" token itself is dropped — matching
// pflag's own end-of-flags semantics. This is why `observer claude --
// --config x` passes "--config" and "x" straight through instead of
// consuming them as this command's own --config.
//
// "-" alone, tokens shorter than two characters, and tokens that don't
// start with '-' are always positionals and pass through untouched.
//
// A "-"/"--" token that does NOT match a reserved flag is an unknown flag
// as far as this command is concerned; it passes through verbatim in its
// original position, and — because this function never tries to guess
// whether an unrecognized flag takes a value — so does whatever token
// follows it (it's simply the next token in the walk, evaluated on its own
// merits next iteration).
//
// Help: cobra's InitDefaultHelpFlag registers "help" (shorthand "h") before
// RunE runs, so ordinary argv scanning here reserves it exactly like any
// other bool-shaped flag. After the scan, if that flag resolved to true,
// splitLauncherArgs calls cmd.Help() and returns errLauncherHelpShown so the
// caller can stop without treating this as a hard failure.
func splitLauncherArgs(cmd *cobra.Command, argv []string) ([]string, error) {
	fs := cmd.Flags()
	reserved := reservedLauncherFlags(fs)
	passthrough := make([]string, 0, len(argv))

	for i := 0; i < len(argv); i++ {
		tok := argv[i]

		if tok == "--" {
			passthrough = append(passthrough, argv[i+1:]...)
			break
		}

		if len(tok) < 2 || tok[0] != '-' {
			passthrough = append(passthrough, tok)
			continue
		}

		name, val, hasEq := splitFlagEq(tok)
		flag, ok := reserved[name]
		if !ok {
			passthrough = append(passthrough, tok)
			continue
		}

		switch {
		case hasEq:
			// value is exactly the '='-joined text; no further token consumed.
		case flag.NoOptDefVal != "":
			// bool-shaped: bare form consumes no following token.
			val = flag.NoOptDefVal
		default:
			// value-shaped flag with no '=': the value is the NEXT argv token.
			if i+1 >= len(argv) {
				return nil, fmt.Errorf("observer %s: flag %s requires a value", cmd.Name(), name)
			}
			i++
			val = argv[i] //nolint:gosec // G602: the index is bounds-checked above
		}

		if err := fs.Set(flag.Name, val); err != nil {
			return nil, fmt.Errorf("observer %s: invalid value for %s: %w", cmd.Name(), name, err)
		}
	}

	if helpFlag := fs.Lookup("help"); helpFlag != nil && helpFlag.Changed && helpFlag.Value.String() == "true" {
		_ = cmd.Help()
		// The one flag every launch verb takes before Cobra runs, documented
		// once for all of them (sandboxLauncherHelp).
		if _, launcher := integration.ToolForLaunchSubcommand(cmd.Name()); launcher {
			if note := sandboxLauncherHelp(); note != "" {
				_, _ = fmt.Fprint(cmd.OutOrStdout(), note)
			}
		}
		return nil, errLauncherHelpShown
	}

	return passthrough, nil
}

// launcherArgsOrDone wraps splitLauncherArgs for launcher RunE bodies: it
// converts the help sentinel into a clean (nil, true, nil) "we're done,
// nothing went wrong" result, converts any other parse error into (nil,
// true, err) so the caller returns it as-is, and on success returns (args,
// false, nil) so the caller proceeds with the wrapped tool's exec using
// args as its argv. Callers should check `done` first:
//
//	args, done, err := launcherArgsOrDone(cmd, argv)
//	if done {
//		return err
//	}
func launcherArgsOrDone(cmd *cobra.Command, argv []string) (args []string, done bool, err error) {
	args, err = splitLauncherArgs(cmd, argv)
	if err != nil {
		if errors.Is(err, errLauncherHelpShown) {
			return nil, true, nil
		}
		return nil, true, err
	}
	return args, false, nil
}
