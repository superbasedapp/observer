package scrub

import "strings"

// secretargs.go masks secret-looking values in what a person is shown
// (lane cli-2 fixes-3, audit L3: a held launch's confirm card and
// `observer terminals ls|show` show the tool arguments and request members
// a launch is bound to, and an argument such as `--api-key` carries a
// credential). What runs is never changed; only the text shown is.

// secretNameWords are the lowercase fragments that make a flag or field
// name read as one that carries a secret. Table-driven; extend here.
var secretNameWords = []string{"key", "token", "secret", "password", "passwd", "credential"}

// SecretName reports whether name, a command-line flag ("--api-key",
// "-token") or a field name ("api_key", "OPENAI_API_KEY"), looks like it
// names a secret: its lower-case form contains one of secretNameWords. It
// errs toward masking: "--keymap" matches too.
func SecretName(name string) bool {
	n := strings.ToLower(strings.TrimLeft(name, "-"))
	for _, w := range secretNameWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// MaskCertainSecrets is v with every pattern-certain secret the detectors
// find replaced by its typed marker (MaskSecrets over Certain findings).
func MaskCertainSecrets(v string) string {
	masked, _ := MaskSecrets(v, func(f TypedFinding) bool { return f.Certain })
	return masked
}

// MaskSecretArgs returns a copy of args, an argument vector, for showing:
// the value of every secret-looking flag (SecretName) is Redacted, whether
// it is joined ("--api-key=v" shows "--api-key=[REDACTED]") or the next
// argument ("--token v" shows "--token [REDACTED]"; a next argument that
// is itself a flag is left as it is), and a certain secret the detectors
// find in any other argument is masked too (MaskCertainSecrets).
func MaskSecretArgs(args []string) []string {
	if args == nil {
		return nil
	}
	out := make([]string, len(args))
	maskNext := false
	for i, a := range args {
		isFlag := strings.HasPrefix(a, "-") && a != "-" && a != "--"
		if maskNext && !strings.HasPrefix(a, "-") {
			out[i], maskNext = Redacted, false
			continue
		}
		maskNext = false
		if isFlag {
			name, _, joined := strings.Cut(a, "=")
			if SecretName(name) {
				if joined {
					out[i] = name + "=" + Redacted
				} else {
					out[i], maskNext = a, true
				}
				continue
			}
		}
		out[i] = MaskCertainSecrets(a)
	}
	return out
}
