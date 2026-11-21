package dashboard

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// Placeholder vocabulary for pathRedactor. These are the ONLY tokens it
// substitutes in, and they are deliberately readable rather than opaque: the
// whole point of substituting instead of dropping is that "hook_checksums.json
// under ~/.observer is stale" stays an actionable remediation hint after the
// machine's layout and the operator's identity have been taken out of it.
//
// "~" is the local home because that is the form the operator already reads in
// this project's own docs and config; a message that already said "~/.observer"
// and one that quoted the expanded path collapse to the same sentence, which is
// correct — they name the same directory.
const (
	redactHome      = "~"
	redactOtherHome = "<other-home>"
	redactConfig    = "<config>"
	redactDB        = "<db>"
	redactExe       = "<exe>"
	redactTemp      = "<tmp>"
	// redactTokenFile is the ETW capturer's shared-token FILE PATH — never its
	// contents, which no doctor check emits. It has its own placeholder rather
	// than riding "~" because an operator who relocated it outside the home
	// directory (a \\wsl.localhost share, a second volume) would otherwise
	// leave it fully readable, and it is the exact string the sibling ETW
	// status route already withholds.
	redactTokenFile = "<token-file>"
)

// redactRootMinLen is the safety floor on a substitution root. A root shorter
// than this — "", "/", ".", "C:" — would match somewhere in nearly every
// sentence and turn the report into noise, so such a root is DISCARDED rather
// than applied. Discarding leaves the affected text unredacted, which is a
// disclosure, so it is listed in the residue note on pathRedactor rather than
// treated as a safe fallback.
const redactRootMinLen = 4

// pathSub is one root → placeholder substitution.
type pathSub struct {
	root        string
	placeholder string
}

// pathRedactor rewrites free text by replacing filesystem roots the server
// already holds with stable placeholders. It is the disclosure filter for
// GET /api/health/doctor's remote-facing projection.
//
// WHY SUBSTITUTION AND NOT A PATTERN. A regex that "looks like a path" is a
// heuristic predicate, and heuristic predicates in this codebase's filter
// layers have a documented history of failing in BOTH directions (docs/
// security.md H5/H5c/H6): they miss real paths and they mangle innocent text.
// The roots here are exact strings the process already knows — its own home,
// config file, database, executable, temp dir, and the cross-OS homes the
// crossmount bridge enumerates — so a match is a fact, not a guess. It also
// does not rot: a future doctor check that mentions the home directory is
// covered the day it lands, with no per-check allow-list to keep in sync.
//
// ORDER IS LOAD-BEARING. Roots are applied LONGEST FIRST. Several of them nest
// (the config file and the database live under the home directory; the
// executable often does too), and applying the shorter root first would produce
// a mangled hybrid — "~/.observer/config.toml" where "<config>" was meant, or
// "<other-home> User" for a Windows home literally named "Default User".
//
// IT OVER-REDACTS RATHER THAN UNDER-REDACTS. Matching is plain substring, not
// path-component-anchored, so a root that happens to be a string prefix of an
// unrelated path is substituted too ("/tmp" inside "/tmpfs" becomes "<tmp>fs").
// That is the deliberate failure direction for a privacy filter: an
// over-redacted sentence is confusing, an under-redacted one is a disclosure.
//
// RESIDUE — WHAT THIS DOES NOT REMOVE. This is NOT complete redaction and must
// not be described as such anywhere:
//
//  1. A path under no known root. The redactor substitutes roots this process
//     holds; a hook config registered at /opt/other/observer, a project on a
//     second volume quoted by a transcript-reader error, or a database moved
//     outside the home directory are emitted verbatim. Observed, not
//     hypothetical — `hooks.binary` prints "registered=<that path>" for exactly
//     this case.
//  2. OS-convention system paths. /etc/claude-code/managed-settings.json and
//     /etc/codex/*.toml appear in the native-console checks. They carry no
//     identity and no layout beyond the OS's own convention, so they are left
//     readable on purpose.
//  3. Non-path identity. The `org enrolment` check reports the enrolled user's
//     EMAIL, the org name/id and the org server URL. Substitution cannot touch
//     these — they are not paths — and they are left in place deliberately:
//     this endpoint is reachable only by a device the owner paired through a
//     local approval, and the owner's own enrolment readout is the legitimate
//     remote use of that check. Residue all the same, named here rather than
//     glossed over.
//  4. Everything, when no root resolves. With neither a home directory nor a
//     config path available the redactor is empty() and rewrites nothing.
type pathRedactor struct {
	subs []pathSub
}

// newPathRedactor builds a redactor from a set of {root, placeholder}
// candidates. Empty roots, roots below redactRootMinLen, and duplicate roots
// are dropped; the survivors are ordered longest-first (ties broken
// lexicographically) so the result is deterministic across calls and across
// map-iteration order.
func newPathRedactor(candidates []pathSub) pathRedactor {
	seen := make(map[string]bool, len(candidates))
	var subs []pathSub
	add := func(root, placeholder string) {
		if len(root) < redactRootMinLen || placeholder == "" || seen[root] {
			return
		}
		seen[root] = true
		subs = append(subs, pathSub{root: root, placeholder: placeholder})
	}
	for _, c := range candidates {
		trimmed := strings.TrimRight(strings.TrimSpace(c.root), `/\`)
		if trimmed == "" {
			continue
		}
		// BOTH the cleaned and the as-given form are registered. Cleaning
		// normalizes "/a//b" and "/a/./b", but the checks quote whatever string
		// they were handed — so a root that only ever exists in its cleaned
		// form would match nothing at all. Registering both costs one entry and
		// removes a silent-miss class; the dedupe collapses them whenever
		// cleaning was a no-op, which is the normal case.
		cleaned := strings.TrimRight(filepath.Clean(trimmed), `/\`)
		add(cleaned, c.placeholder)
		add(trimmed, c.placeholder)
		// The forward-slash spelling too. On Windows filepath.Clean rewrites
		// every "/" to `\`, yet text quotes a root either way ("C:/Users/x"
		// from a TOML value or a ToSlash'd path, `C:\Users\x` from
		// filepath.Join), so registering only the backslash form would be the
		// same silent miss. On POSIX this equals cleaned and dedupes away.
		add(filepath.ToSlash(cleaned), c.placeholder)
	}
	sort.Slice(subs, func(i, j int) bool {
		if len(subs[i].root) != len(subs[j].root) {
			return len(subs[i].root) > len(subs[j].root)
		}
		return subs[i].root < subs[j].root
	})
	return pathRedactor{subs: subs}
}

// empty reports whether the redactor would rewrite nothing at all. A caller
// that gets true has NOT been handed safe text — it has been handed a redactor
// with no roots to work from, which is a reason to disclose less, never more.
func (p pathRedactor) empty() bool { return len(p.subs) == 0 }

// redact rewrites one free-text string. Paths reach these strings two ways —
// written into the message by the check itself, and carried in verbatim by
// err.Error() (a Go *PathError stringifies the whole path, so a check whose
// source line contains no path literal still emits one) — and this treats both
// identically, because it never looks at where the text came from.
func (p pathRedactor) redact(s string) string {
	for _, sub := range p.subs {
		if strings.Contains(s, sub.root) {
			s = strings.ReplaceAll(s, sub.root, sub.placeholder)
		}
	}
	return s
}

// redactAll rewrites a slice, returning nil for nil so an absent Details list
// stays absent on the wire rather than becoming an empty array.
func (p pathRedactor) redactAll(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = p.redact(s)
	}
	return out
}

// doctorRedactor assembles the redactor for a doctor report from the roots this
// server already holds. exe is the running binary's path as the handler
// resolved it — passed in rather than re-resolved, so the redactor and the
// report that quotes it can never disagree.
//
// The home directory is resolved the SAME way diag.Run resolves it (the
// setupWizardHome sandbox override first, os.UserHomeDir() otherwise), because
// a redactor that resolved a different home than the checks used would silently
// redact nothing.
//
// crossmount.AllHomes() supplies the cross-OS homes. On this project's primary
// topology — a WSL daemon beside a Windows install — doctor emits
// "/mnt/c/Users/<windows-user>/.claude/settings.json" from at least two checks
// in the HEALTHY state (measured on a live host, not assumed). That is exactly
// the Windows user name the sibling ETW status route already withholds, so
// leaving it here would keep the two routes inconsistent — which is the gap
// this filter exists to close. The call is a stat plus one directory read, and
// diag.Run has already made the same call inside this request.
func (s *Server) doctorRedactor(cfg config.Config, exe string) pathRedactor {
	home := setupWizardHome
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = h
		}
	}

	// Longest-first ordering is imposed by newPathRedactor, so this slice is
	// ordered for READING, not for precedence. Duplicates are expected and
	// harmless (the configured db_path and the dashboard's own DBPath are
	// usually the same file); the first one wins.
	cands := []pathSub{
		{exe, redactExe},
		{s.opts.ConfigPath, redactConfig},
		{s.opts.DBPath, redactDB},
		{expandHomePath(cfg.Observer.DBPath, home), redactDB},
		// The `process observability` check embeds the daemon's verbatim
		// transport-unavailable reason, which can quote this path — the same
		// string /api/process/etw/status drops. An empty value is the default
		// (the token lands next to the DB, already under home) and is
		// discarded by newPathRedactor.
		{expandHomePath(cfg.Observer.Process.ETW.TokenPath, home), redactTokenFile},
		{home, redactHome},
		{os.TempDir(), redactTemp},
	}

	// Cross-OS homes get INDEXED placeholders. Collapsing several of them onto
	// one token would destroy a distinction the checks actually make: the
	// ownership warning exists to say "several Windows homes carry this
	// config", and rendering that as the same placeholder twice would turn a
	// real warning into a nonsense one.
	var foreign []string
	for _, h := range crossmount.AllHomes() {
		if h.Path == "" || h.Path == home {
			continue
		}
		foreign = append(foreign, h.Path)
	}
	sort.Strings(foreign) // AllHomes' order is explicitly not guaranteed
	for i, p := range foreign {
		ph := redactOtherHome
		if i > 0 {
			ph = redactOtherHome + "-" + strconv.Itoa(i+1)
		}
		cands = append(cands, pathSub{p, ph})
	}

	return newPathRedactor(cands)
}

// expandHomePath resolves a leading "~/" against home, mirroring what
// diag.checkDBSize does with the configured db_path. Config values are
// routinely written in tilde form, and a root that never appears verbatim in
// the report's text would substitute nothing.
func expandHomePath(p, home string) string {
	if home == "" || !strings.HasPrefix(p, "~/") {
		return p
	}
	return filepath.Join(home, p[2:])
}
