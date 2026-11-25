package policy

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The rewrite-invariance test (guard-deletes lane, 2026-11-24). The
// per-rule spelling tests pin one spelling each; this replays EVERY hit row
// of the destructive-rule tests (destructiveRuleCases, deleteTableCases,
// execPrefixWrapperCases) under meaning-preserving rewrites of the command
// and asserts the same rule and decision. A rewrite that may legitimately
// raise severity (sudo) is held to "at least as strict". A failure here is a
// bypass: fix it in the parser or the rule, never by weakening a rewrite.
//
// Rewrites that change meaning are left out on purpose: a quoted `~` is a
// literal file named ~, a single-quoted `$HOME` a literal dollar, `exec cd`
// fails, `command FOO=1 x` runs a program named FOO=1.

// invRewrite is one meaning-preserving rewrite of a case's command line.
type invRewrite struct {
	name string
	// class groups rewrites for pairing: two rewrites of the same class are
	// not composed (two prefixes are each other's rewrite already).
	class string
	// apply returns the rewritten line, or ok=false where the rewrite does
	// not apply to the line (or would change its meaning).
	apply func(c destructiveCase) (string, bool)
	// stricter marks a rewrite that may raise severity (sudo): the verdict
	// must be at least as strict as the row's, under any rule.
	stricter bool
}

// invFlagRow is one CLI's short flags for the flag rewrites: the letters
// that take no value (only clusters made of these are split or reordered)
// and each letter's long spelling.
type invFlagRow struct {
	valueless string
	long      map[byte]string
	// permutes marks a CLI that reads options after its operands (GNU
	// getopt permutation, popt), so moving every flag to the end of the
	// line keeps its meaning.
	permutes bool
	// bareLong reports a long option that takes no separate value, which
	// alone may be moved by the permutation (one with "=" carries its own).
	bareLong func(string) bool
}

// invFlags are the CLIs the flag rewrites know. A CLI that is not here (or
// a cluster with a letter not in valueless) is left as written.
var invFlags = map[string]invFlagRow{
	"rm": {
		valueless: "rRfv", permutes: true, bareLong: func(string) bool { return true },
		long: map[byte]string{'r': "--recursive", 'R': "--recursive", 'f': "--force", 'v': "--verbose"},
	},
	"rsync": {
		valueless: "avzrlptgoDh", permutes: true,
		bareLong: func(w string) bool {
			return strings.HasPrefix(w, "--del") || strings.HasPrefix(w, "--remove-") ||
				w == "--archive" || w == "--recursive" || w == "--verbose" || w == "--compress"
		},
		long: map[byte]string{'a': "--archive", 'v': "--verbose", 'z': "--compress", 'r': "--recursive"},
	},
	"shred": {
		valueless: "fuvxz", permutes: true, bareLong: func(w string) bool { return !strings.HasPrefix(w, "--iterations") },
		long: map[byte]string{'u': "--remove", 'z': "--zero", 'v': "--verbose", 'f': "--force", 'x': "--exact"},
	},
	"chmod": {valueless: "Rfv", long: map[byte]string{'R': "--recursive", 'f': "--silent", 'v': "--verbose"}},
	// git's flags are per subcommand ("git <sub>"); -D is --delete --force.
	"git clean":  {valueless: "fdxXnq", long: map[byte]string{'f': "--force", 'n': "--dry-run", 'q': "--quiet"}},
	"git push":   {valueless: "fdnqv", long: map[byte]string{'f': "--force", 'd': "--delete", 'n': "--dry-run"}},
	"git branch": {valueless: "Ddfq", long: map[byte]string{'D': "--delete --force", 'd': "--delete", 'f': "--force", 'q': "--quiet"}},
	"git tag":    {valueless: "d", long: map[byte]string{'d': "--delete"}},
	"chown":      {valueless: "Rfv", long: map[byte]string{'R': "--recursive", 'f': "--silent", 'v': "--verbose"}},
}

// invAbbrev are, per CLI (git per subcommand), long options and an
// unambiguous prefix the CLI reads as them: GNU getopt_long and git's
// parse-options take any unambiguous prefix. Options whose every prefix is
// ambiguous (git push --force: --force-with-lease) are left out.
var invAbbrev = map[string]map[string]string{
	"rm":         {"--recursive": "--recur", "--force": "--forc"},
	"shred":      {"--remove": "--remo", "--zero": "--zer"},
	"chmod":      {"--recursive": "--recur"},
	"chown":      {"--recursive": "--recur"},
	"tar":        {"--remove-files": "--remove", "--directory": "--direc"},
	"git reset":  {"--hard": "--har"},
	"git clean":  {"--force": "--forc"},
	"git push":   {"--delete": "--dele"},
	"git branch": {"--delete": "--dele", "--force": "--forc"},
	"git tag":    {"--delete": "--dele"},
}

// invBusyboxApplets are the commands busybox runs as applets.
var invBusyboxApplets = setOf("rm", "rmdir", "unlink", "shred", "find", "tar", "dd", "chmod", "chown", "xargs")

// invShellWords are shell builtins and keywords: no exec prefix or /bin
// path runs them as the same thing.
var invShellWords = setOf("cd", "pushd", "popd", "eval", "export", "set", "source", ".", "alias", "unset",
	"exec", "command", "builtin", "declare", "typeset", "local", "readonly", "if", "for", "while", "function")

// invPosix reports a case read as a POSIX shell line.
func invPosix(c destructiveCase) bool {
	return c.dialect == "" || c.dialect == DialectPosix
}

// invHome is the case's home directory (runRuleCases' default).
func invHome(c destructiveCase) string {
	if c.home != "" {
		return c.home
	}
	return "/home/u"
}

// invWords splits a simple POSIX line into its words: false when the line
// holds anything a plain space split would mangle (quotes, escapes,
// operators, substitutions, redirects). An escaped `;` word (find's `\;`)
// is kept whole.
func invWords(c destructiveCase) ([]string, bool) {
	if !invPosix(c) {
		return nil, false
	}
	words := strings.Fields(c.cmd)
	for _, w := range words {
		if w == `\;` {
			continue
		}
		if strings.ContainsAny(w, "'\"`\\;|&<>()\n") {
			return nil, false
		}
	}
	return words, len(words) > 0
}

// invSingleUnit reports a POSIX line that is one simple command: no
// unquoted list or pipeline operator and no newline.
func invSingleUnit(line string) bool {
	var quote byte
	for i := 0; i < len(line); i++ {
		ch := line[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			} else if ch == '\\' && quote == '"' {
				i++
			}
		case ch == '\\':
			i++
		case ch == '\'' || ch == '"':
			quote = ch
		case ch == ';' || ch == '&' || ch == '|' || ch == '\n':
			return false
		}
	}
	return true
}

// invBarePrefixes are exec prefixes that, written with no option of their
// own, run the next word as the command.
var invBarePrefixes = setOf("sudo", "env", "nice", "nohup", "command", "exec", "busybox", "builtin")

// invCommandWord returns the index and base of the line's command word:
// the first word past bare exec prefixes.
func invCommandWord(words []string) (int, string) {
	i := 0
	for i+1 < len(words) && invBarePrefixes[canonicalBase(words[i], DialectPosix)] && !strings.HasPrefix(words[i+1], "-") {
		i++
	}
	if i >= len(words) {
		return 0, ""
	}
	return i, canonicalBase(words[i], DialectPosix)
}

// invCommandIndex returns the command word's index and its flag row, when
// the flag rewrites know the command (for git, the subcommand word's).
func invCommandIndex(words []string) (int, invFlagRow, bool) {
	i, base := invCommandWord(words)
	if base == "git" && i+1 < len(words) {
		i, base = i+1, "git "+words[i+1]
	}
	row, ok := invFlags[base]
	return i, row, ok
}

// invCluster reports a short-flag cluster made only of valueless letters.
func invCluster(w string, row invFlagRow) bool {
	if len(w) < 2 || w[0] != '-' || w[1] == '-' {
		return false
	}
	for k := 1; k < len(w); k++ {
		if strings.IndexByte(row.valueless, w[k]) < 0 {
			return false
		}
	}
	return true
}

// invMapClusters rewrites every valueless cluster after the command word
// with f; ok is false when nothing changed.
func invMapClusters(c destructiveCase, f func(w string, row invFlagRow) ([]string, bool)) (string, bool) {
	words, ok := invWords(c)
	if !ok {
		return "", false
	}
	i, row, ok := invCommandIndex(words)
	if !ok {
		return "", false
	}
	out := append([]string(nil), words[:i+1]...)
	changed := false
	for _, w := range words[i+1:] {
		if w == "--" {
			break
		}
		if invCluster(w, row) {
			if nw, ok := f(w, row); ok {
				out = append(out, nw...)
				changed = true
				continue
			}
		}
		out = append(out, w)
	}
	if !changed {
		return "", false
	}
	return strings.Join(append(out, invTail(words, i)...), " "), true
}

// invTail returns the words from the first "--" after the command word on
// (kept as written).
func invTail(words []string, i int) []string {
	for j := i + 1; j < len(words); j++ {
		if words[j] == "--" {
			return words[j:]
		}
	}
	return nil
}

// invHomeWord rewrites a word naming the home directory (`~`, `~/x`) with
// the given spelling of home; ok is false for any other word.
func invHomeWord(w, home string) (string, bool) {
	switch {
	case w == "~":
		return home, true
	case strings.HasPrefix(w, "~/"):
		return home + w[1:], true
	}
	return "", false
}

// invMapWords rewrites each word f accepts; ok is false when nothing
// changed.
func invMapWords(c destructiveCase, f func(w string) (string, bool)) (string, bool) {
	words, ok := invWords(c)
	if !ok {
		return "", false
	}
	changed := false
	out := make([]string, len(words))
	for k, w := range words {
		out[k] = w
		if nw, ok := f(w); ok && nw != w {
			out[k], changed = nw, true
		}
	}
	return strings.Join(out, " "), changed
}

// invPrefix prepends an exec prefix to a single-unit POSIX line whose first
// word is a program (not a builtin or an assignment). applets limits the
// prefix to commands it can run (busybox's applets); nil means any.
func invPrefix(prefix string, applets map[string]bool) func(destructiveCase) (string, bool) {
	return func(c destructiveCase) (string, bool) {
		if !invPosix(c) || !invSingleUnit(c.cmd) {
			return "", false
		}
		first, _, _ := strings.Cut(strings.TrimSpace(c.cmd), " ")
		base := canonicalBase(first, DialectPosix)
		if invShellWords[base] || isEnvAssign(first) || strings.ContainsAny(first, "'\"`$\\") {
			return "", false
		}
		if applets != nil && !applets[base] {
			return "", false
		}
		return prefix + " " + c.cmd, true
	}
}

// invShellC wraps the whole POSIX line in `<shell> -c '<line>'`.
func invShellC(shell string) func(destructiveCase) (string, bool) {
	return func(c destructiveCase) (string, bool) {
		if !invPosix(c) {
			return "", false
		}
		return shell + " -c '" + strings.ReplaceAll(c.cmd, "'", `'\''`) + "'", true
	}
}

// invRewrites is the rewrite table, walked for every hit row.
func invRewrites() []invRewrite {
	return []invRewrite{
		{name: "flags split", class: "flags", apply: func(c destructiveCase) (string, bool) {
			return invMapClusters(c, func(w string, _ invFlagRow) ([]string, bool) {
				if len(w) < 3 {
					return nil, false
				}
				var out []string
				for k := 1; k < len(w); k++ {
					out = append(out, "-"+w[k:k+1])
				}
				return out, true
			})
		}},
		{name: "flags reversed", class: "flags", apply: func(c destructiveCase) (string, bool) {
			return invMapClusters(c, func(w string, _ invFlagRow) ([]string, bool) {
				if len(w) < 3 {
					return nil, false
				}
				b := []byte(w[1:])
				for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
					b[i], b[j] = b[j], b[i]
				}
				return []string{"-" + string(b)}, true
			})
		}},
		{name: "flags long", class: "flags", apply: func(c destructiveCase) (string, bool) {
			return invMapClusters(c, func(w string, row invFlagRow) ([]string, bool) {
				var out []string
				for k := 1; k < len(w); k++ {
					l, ok := row.long[w[k]]
					if !ok {
						return nil, false
					}
					out = append(out, l)
				}
				return out, true
			})
		}},
		{name: "flags after operands", class: "flags", apply: func(c destructiveCase) (string, bool) {
			words, ok := invWords(c)
			if !ok || !invSingleUnit(c.cmd) {
				return "", false
			}
			i, row, ok := invCommandIndex(words)
			if !ok || !row.permutes || invTail(words, i) != nil {
				return "", false
			}
			var flags, ops []string
			for _, w := range words[i+1:] {
				if strings.HasPrefix(w, "-") && len(w) > 1 {
					long := strings.HasPrefix(w, "--")
					if (!long && !invCluster(w, row)) || (long && !strings.Contains(w, "=") && !row.bareLong(w)) {
						return "", false // a flag that may take the next word
					}
					flags = append(flags, w)
				} else {
					ops = append(ops, w)
				}
			}
			if len(flags) == 0 || len(ops) == 0 {
				return "", false
			}
			out := append(append(append([]string(nil), words[:i+1]...), ops...), flags...)
			return strings.Join(out, " "), true
		}},
		{name: "long flags abbreviated", class: "abbrev", apply: func(c destructiveCase) (string, bool) {
			words, ok := invWords(c)
			if !ok {
				return "", false
			}
			i, base := invCommandWord(words)
			key := base
			if base == "git" && i+1 < len(words) {
				key = "git " + words[i+1]
			}
			ab := invAbbrev[key]
			if ab == nil {
				return "", false
			}
			changed := false
			out := append([]string(nil), words...)
			for k := i + 1; k < len(out); k++ {
				if out[k] == "--" {
					break
				}
				name, val, eq := strings.Cut(out[k], "=")
				if short, ok := ab[name]; ok {
					out[k], changed = short, true
					if eq {
						out[k] += "=" + val
					}
				}
			}
			return strings.Join(out, " "), changed
		}},
		{name: "home as $HOME", class: "home", apply: func(c destructiveCase) (string, bool) {
			return invMapWords(c, func(w string) (string, bool) { return invHomeWord(w, "$HOME") })
		}},
		{name: "home as ${HOME}", class: "home", apply: func(c destructiveCase) (string, bool) {
			return invMapWords(c, func(w string) (string, bool) { return invHomeWord(w, "${HOME}") })
		}},
		{name: "home through ..", class: "home", apply: func(c destructiveCase) (string, bool) {
			h := invHome(c)
			i := strings.LastIndexByte(h, '/')
			if i < 0 {
				return "", false
			}
			return invMapWords(c, func(w string) (string, bool) { return invHomeWord(w, h+"/.."+h[i:]) })
		}},
		{name: "home spelled out", class: "home", apply: func(c destructiveCase) (string, bool) {
			return invMapWords(c, func(w string) (string, bool) { return invHomeWord(w, invHome(c)) })
		}},
		{name: "home as ~", class: "home", apply: func(c destructiveCase) (string, bool) {
			h := invHome(c)
			return invMapWords(c, func(w string) (string, bool) {
				for _, sp := range []string{h, "$HOME", "${HOME}"} {
					if w == sp {
						return "~", true
					}
					if rest, ok := strings.CutPrefix(w, sp+"/"); ok {
						return "~/" + rest, true
					}
				}
				return "", false
			})
		}},
		{name: "/bin path", class: "path", apply: func(c destructiveCase) (string, bool) {
			if !invPosix(c) {
				return "", false
			}
			line := strings.TrimSpace(c.cmd)
			first, rest, _ := strings.Cut(line, " ")
			if strings.ContainsAny(first, "/\\'\"`$=") || invShellWords[first] || first == "" {
				return "", false
			}
			return "/bin/" + first + " " + rest, true
		}},
		{name: "env prefix", class: "prefix", apply: invPrefix("env", nil)},
		{name: "command prefix", class: "prefix", apply: invPrefix("command", nil)},
		{name: "exec prefix", class: "prefix", apply: invPrefix("exec", nil)},
		{name: "nice prefix", class: "prefix", apply: invPrefix("nice", nil)},
		{name: "nohup prefix", class: "prefix", apply: invPrefix("nohup", nil)},
		{name: "busybox prefix", class: "prefix", apply: invPrefix("busybox", invBusyboxApplets)},
		{name: "sudo prefix", class: "prefix", apply: invPrefix("sudo", nil), stricter: true},
		{name: "bash -c", class: "shell", apply: invShellC("bash")},
		{name: "sh -c", class: "shell", apply: invShellC("sh")},
	}
}

// invHitRows are every hit row of the destructive-rule tests.
func invHitRows() []destructiveCase {
	var rows []destructiveCase
	add := func(cs []destructiveCase) {
		for _, c := range cs {
			if c.wantRule != "" {
				rows = append(rows, c)
			}
		}
	}
	add(destructiveRuleCases())
	add(execPrefixWrapperCases())
	for _, r := range deleteTable {
		add(deleteTableCases()[r.name])
	}
	return rows
}

// invVariant is one rewritten line of a hit row.
type invVariant struct {
	via      string
	line     string
	stricter bool
}

// invVariants returns every single rewrite of c, and every composition of
// two rewrites of different classes (the second applied to the first's
// line).
func invVariants(c destructiveCase) []invVariant {
	rws := invRewrites()
	var out []invVariant
	for _, a := range rws {
		la, ok := a.apply(c)
		if !ok || la == c.cmd {
			continue
		}
		out = append(out, invVariant{via: a.name, line: la, stricter: a.stricter})
		ca := c
		ca.cmd = la
		for _, b := range rws {
			if b.class == a.class {
				continue
			}
			lb, ok := b.apply(ca)
			if !ok || lb == la {
				continue
			}
			out = append(out, invVariant{via: a.name + " + " + b.name, line: lb, stricter: a.stricter || b.stricter})
		}
	}
	return out
}

// invEngine evaluates one line under a case's fixture in enforce mode.
func invEngine(t testing.TB, c destructiveCase) func(line string) Verdict {
	t.Helper()
	home := invHome(c)
	root := c.root
	if root == "" {
		root = "/home/u/proj"
	}
	cwd := c.cwd
	if cwd == "" {
		cwd = root
	}
	eng, err := New(Config{Mode: ModeEnforce, Home: home})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return func(line string) Verdict {
		return eng.Evaluate(Event{
			Kind: KindShellExec, ActionType: "run_command", Target: line, Dialect: c.dialect,
			Cwd: cwd, ProjectRoot: root, SessionID: "s1",
			Now: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		})
	}
}

// invCheck reports how a rewritten line's verdict falls short of the row.
func invCheck(c destructiveCase, v invVariant, got Verdict) string {
	if v.stricter {
		if got.Decision < c.wantEnforce {
			return fmt.Sprintf("%s/%s, want at least %s", got.RuleID, got.Decision, c.wantEnforce)
		}
		return ""
	}
	if got.RuleID != c.wantRule || got.Decision != c.wantEnforce {
		return fmt.Sprintf("%s/%s, want %s/%s", got.RuleID, got.Decision, c.wantRule, c.wantEnforce)
	}
	return ""
}

// TestDestructiveRewriteInvariance replays every destructive hit row under
// every single rewrite and every two-rewrite composition.
func TestDestructiveRewriteInvariance(t *testing.T) {
	t.Parallel()
	rows := invHitRows()
	if len(rows) < 150 {
		t.Fatalf("only %d hit rows: the case lists moved", len(rows))
	}
	total := 0
	for _, c := range rows {
		vs := invVariants(c)
		total += len(vs)
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			eval := invEngine(t, c)
			if base := eval(c.cmd); base.RuleID != c.wantRule || base.Decision != c.wantEnforce {
				t.Fatalf("row itself = %s/%s, want %s/%s", base.RuleID, base.Decision, c.wantRule, c.wantEnforce)
			}
			for _, v := range vs {
				if why := invCheck(c, v, eval(v.line)); why != "" {
					t.Errorf("%s: %q = %s", v.via, v.line, why)
				}
			}
		})
	}
	if total < 1000 {
		t.Errorf("only %d rewritten lines: a rewrite stopped applying", total)
	}
}

// TestInvarianceRewritesApply pins that each rewrite applies to at least
// one hit row, so a rewrite that silently stops matching is caught.
func TestInvarianceRewritesApply(t *testing.T) {
	t.Parallel()
	rows := invHitRows()
	for _, r := range invRewrites() {
		n := 0
		for _, c := range rows {
			if l, ok := r.apply(c); ok && l != c.cmd {
				n++
			}
		}
		if n == 0 {
			t.Errorf("rewrite %q applies to no hit row", r.name)
		}
	}
}

// FuzzDestructiveRewriteInvariance composes up to four rewrites, chosen by
// the fuzzer, on a hit row chosen by the fuzzer. The seed corpus (one entry
// per hit row) runs under plain `go test`.
func FuzzDestructiveRewriteInvariance(f *testing.F) {
	rows := invHitRows()
	for i := range rows {
		f.Add(uint16(i), []byte{byte(i), byte(i * 7), byte(i * 13)})
	}
	rws := invRewrites()
	f.Fuzz(func(t *testing.T, row uint16, ops []byte) {
		c := rows[int(row)%len(rows)]
		if len(ops) > 4 {
			ops = ops[:4]
		}
		v := invVariant{line: c.cmd}
		cur := c
		for _, op := range ops {
			r := rws[int(op)%len(rws)]
			l, ok := r.apply(cur)
			if !ok {
				continue
			}
			v.via += " + " + r.name
			v.line, v.stricter = l, v.stricter || r.stricter
			cur.cmd = l
		}
		if v.line == c.cmd {
			return
		}
		if why := invCheck(c, v, invEngine(t, c)(v.line)); why != "" {
			t.Errorf("%s:%s: %q = %s", c.name, v.via, v.line, why)
		}
	})
}
