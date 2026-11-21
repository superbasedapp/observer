package guard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// User-policy load verdict (T-323).
//
// A user guard-policy.toml that does not load is DROPPED by New: the
// guard runs the built-in rules plus the signed org bundle, and records
// a load issue nobody reads. Under enforcement that meant the
// developer's own rules were silently off. The orchestrator ruling is
// deliberately NOT fail-closed (built-ins and the org bundle stay in
// force), but the failure must be loud: `observer doctor` errors, a
// guard event reaches the org, and the Security page shows a banner.
// CheckUserPolicy is the ONE derivation all three read, so they can
// never disagree about whether the file loads.

// UserPolicyInvalidDegradedFrom is the guard_events.degraded_from value
// for the "user policy file does not load" event.
const UserPolicyInvalidDegradedFrom = "user_policy_invalid"

// UserPolicyStatus is the load verdict on the configured user policy
// file.
type UserPolicyStatus struct {
	// Path is the resolved file (empty when no user policy is
	// configured).
	Path string `json:"path"`
	// Present reports the file exists (or exists but is unreadable).
	Present bool `json:"present"`
	// Valid reports the file loads: it parses, compiles and builds an
	// engine. Meaningful only when Present.
	Valid bool `json:"valid"`
	// Line is the 1-based line the problem was found on; 0 when it
	// cannot be placed (an unreadable file, an engine error naming no
	// entry).
	Line int `json:"line,omitempty"`
	// Error is the problem, as New would record it.
	Error string `json:"error,omitempty"`
	// ContentHash is the sha256 of the file bytes (empty when
	// unreadable): the event de-duplication key.
	ContentHash string `json:"content_hash,omitempty"`
}

// Invalid reports a file that exists and that New would drop.
func (s UserPolicyStatus) Invalid() bool { return s.Present && !s.Valid }

// CheckUserPolicy resolves the configured user policy exactly as New
// does and reports whether it loads. readFile is injected (os.ReadFile
// in production). The checks are the ones that make New drop the
// layer: a read failure other than "not found", a parse/compile error
// (parsePolicyFile), and an engine construction error over the layer as
// the engine sees it (RC-4): the file folded with its applied recipe
// sibling (readLayerWithRecipe's fold, recipe rows first, an unknown
// recipe target dropped) under the config's [guard.rules] disable list.
// A recipe file that does not parse is skipped, as New skips it (the own
// file still loads). Merge issues that New records but does not drop the
// layer for (a row dropped alone) are not invalidity. Path, Line and
// ContentHash stay the own file's: it is the file the person edits.
func CheckUserPolicy(cfg config.GuardConfig, home string, readFile func(string) ([]byte, error)) UserPolicyStatus {
	st := UserPolicyStatus{Path: UserPolicyPath(cfg, home)}
	if st.Path == "" {
		return st
	}
	raw, err := readFile(st.Path)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrNotExist):
		return st
	default:
		st.Present = true
		st.Error = fmt.Sprintf("read: %v", err)
		return st
	}
	st.Present = true
	st.ContentHash = sha256hex(raw)
	pf, perr := parsePolicyFile(raw, layerUser)
	if perr != nil {
		st.Error = perr.Error()
		st.Line = problemLine(raw, perr)
		return st
	}
	recipePath := recipeSibling(st.Path)
	var recipe *policyFile
	if rraw, rerr := readFile(recipePath); rerr == nil {
		if rpf, perr := parsePolicyFile(rraw, layerUser); perr == nil {
			recipe, _ = (&Guard{}).dropUnknownRecipeTargets(rpf, pf, recipePath)
		}
	}
	builds := func(layer *policyFile) error {
		extra, overrides, _, _ := mergeLayersWithDisable(nil, cfg.Rules.Disable, nil, layer, nil, nil)
		_, err := policy.New(policy.Config{ExtraRules: extra, Overrides: overrides, Disabled: cfg.Rules.Disable})
		return err
	}
	if eerr := builds(foldRecipeLayer(recipe, pf)); eerr != nil {
		st.Error = eerr.Error()
		if recipe != nil && builds(pf) == nil {
			st.Error = "with the applied recipe " + recipePath + ": " + st.Error
		}
		st.Line = problemLine(raw, eerr)
		return st
	}
	st.Valid = true
	return st
}

// entryRef matches the "rule N" / "override N" prefix parsePolicyFile
// puts on a per-entry error.
var entryRef = regexp.MustCompile(`^(rule|override) (\d+)\b`)

// quotedRef pulls the first quoted token out of an error ("override
// references unknown rule \"R-999\"").
var quotedRef = regexp.MustCompile(`"([^"]+)"`)

// problemLine places an error on a line of raw, best effort:
//
//  1. a TOML syntax error carries its own position;
//  2. "rule N" / "override N" is the line of the N-th [[rule]] /
//     [[override]] table header;
//  3. "unknown keys: a.b, c" is the first line assigning the last
//     component of the first key;
//  4. otherwise the first line containing the error's first quoted
//     token.
//
// 0 when none applies.
func problemLine(raw []byte, err error) int {
	var pe toml.ParseError
	if errors.As(err, &pe) {
		return pe.Position.Line
	}
	msg := err.Error()
	if m := entryRef.FindStringSubmatch(msg); m != nil {
		n, _ := strconv.Atoi(m[2])
		return nthHeaderLine(raw, "[["+m[1]+"]]", n)
	}
	if rest, ok := strings.CutPrefix(msg, "unknown keys: "); ok {
		key := strings.TrimSpace(strings.Split(rest, ",")[0])
		if i := strings.LastIndexByte(key, '.'); i >= 0 {
			key = key[i+1:]
		}
		return firstLineMatching(raw, func(l string) bool {
			k, _, found := strings.Cut(l, "=")
			return found && strings.TrimSpace(k) == key
		})
	}
	if m := quotedRef.FindStringSubmatch(msg); m != nil {
		return firstLineMatching(raw, func(l string) bool { return strings.Contains(l, m[1]) })
	}
	return 0
}

// nthHeaderLine returns the line of the n-th (1-based) occurrence of a
// table-array header.
func nthHeaderLine(raw []byte, header string, n int) int {
	seen := 0
	return firstLineMatching(raw, func(l string) bool {
		if strings.TrimSpace(l) == header {
			seen++
			return seen == n
		}
		return false
	})
}

// firstLineMatching returns the 1-based number of the first line for
// which match is true (comment lines skipped); 0 when none.
func firstLineMatching(raw []byte, match func(string) bool) int {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		l := sc.Text()
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		if match(l) {
			return n
		}
	}
	return 0
}
