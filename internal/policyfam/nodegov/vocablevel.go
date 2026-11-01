package nodegov

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Vocabulary levels: the mixed-fleet compatibility rail for node.governance.
//
// Every released agent compiles a node.governance body STRICTLY: one section
// id, pinned key, share key or feature id it has never heard of fails the
// whole compile, and so does a body declaring a schema newer than the build
// decodes. The accept gate answers decode_failed and the node keeps its
// previous body. So an org admin who hides a page that only newer builds have
// (projects in v1.34.0, agent-config after it), exposes a page (schema 3), or
// pins a key added after a node's release would otherwise silently stop
// delivering EVERY later governance change to that node. Two halves close
// that:
//
//   - The server projects the body it serves onto what the fetching node
//     compiles (ProjectToTarget, target.go), then re-signs it at serve time.
//     A node names its Target on the policy GET as capability tokens
//     (CapabilityTokens); a node that names none is an older build, and the
//     server falls back to the lowest agent version the member has reported
//     (TargetForAgentVersion), and to LastUncappedTarget when it knows
//     nothing.
//   - This build and later compile leniently on the accept path
//     (CompileBodyLenient): an unknown section id is dropped with a note
//     instead of failing the body, so the next skew degrades to "that one page
//     is not governed here" rather than "nothing is".
//
// Dropping an id a node does not know is safe in every list: a page the build
// does not have cannot be shown, hidden or locked on it. The same holds for a
// pinned key, share key or feature a build does not have: that build cannot
// apply it whether the body is projected or refused, and refusing would cost
// it every other directive as well.

// CurrentVocabLevel is the vocabulary level this build compiles. Bump it, and
// add each new id to navSince / settingsSince at the new level, whenever
// NavSectionIDs or SettingsSectionIDs grows. vocablevel_test.go fails when an
// id is missing from both the first-level baseline and the since tables.
const CurrentVocabLevel = 10

// FirstTabVocabLevel is the level at which page TABS ("<page>/<tab>",
// vocab.go) joined the nav vocabulary (per-tab visibility, T-132). Every tab
// in navtabs_gen.go is at this level unless tabSince names a later one: a tab
// added after this build goes into tabSince at a new, bumped level.
const FirstTabVocabLevel = 5

// FirstVocabLevel is the vocabulary of the first node.governance build
// (v1.31.0). It is what the server assumes about a node it knows nothing
// about.
const FirstVocabLevel = 1

// navSince / settingsSince name the level at which each id joined its
// vocabulary. An id absent from the table has been there since
// FirstVocabLevel. The two vocabularies are separate tables because they share
// ids ("tools", "routing", "compression") with different histories.
var (
	navSince = map[string]int{
		"projects":     3, // v1.34.0
		"agent-config": 4, // after v1.34.0 (adapter config P4/P5)
		// Integration 6: the request-grants page joined on a lane that never
		// advertised a level; level-5 (tabs) builds lack it. It is on the T8
		// floor, so no body names it, but the level stays truthful.
		"requests": 6,
		// The Plans & limits page (subscription and balance tracking).
		"plans": 7,
		// The admin and developer Messages page (T-854). It is on the T8
		// floor (D-695), so no body names it, but the level stays truthful.
		"messages": 8,
		// The security pillar's Code security page (security pillar plan
		// section 4.10).
		"code-security": 10,
	}
	settingsSince = map[string]int{
		"cloud": 2, // v1.33.0
		"tasks": 2, // v1.33.0
		// Integration 6: the org Cloud Intelligence settings section
		// (ci-parity) is unknown to the level-4/5 lane builds.
		"intel": 6,
	}
	// tabSince names the tabs that joined AFTER FirstTabVocabLevel. A tab
	// absent from it has been there since FirstTabVocabLevel.
	tabSince = map[string]int{
		// Integration 6: the AI tool settings Organization tab (adapter
		// config P6/P7) is unknown to level-5 (tabs lane) builds.
		"agent-config/organization": 6,
		// T-935: the Tools page gained tabs (Activity, and the Coverage
		// list of every supported AI tool); level-8 builds have a tabless
		// Tools page.
		"tools/activity": 9,
		"tools/coverage": 9,
		// The Code security page's tabs (lane sec-c3) join at the page's own
		// level: the page and its tabs ship together in the same unreleased
		// batch (the Security Core preview), so no level-10 build has the
		// page without them.
		"code-security/findings":   9,
		"code-security/exceptions": 10,
		"code-security/baselines":  9,
	}
)

// LastUncappedVocabLevel is the newest level a build that does NOT advertise
// VocabCapabilityToken can compile (v1.34.x). It is the Level of
// LastUncappedTarget.
const LastUncappedVocabLevel = 3

// vocabCapabilityPrefix is the policy_caps token prefix. The token is
// "nodegov-vocab-<level>".
const vocabCapabilityPrefix = "nodegov-vocab-"

// VocabCapabilityToken renders the policy_caps token a node sends to say which
// vocabulary level it compiles.
func VocabCapabilityToken(level int) string {
	return vocabCapabilityPrefix + strconv.Itoa(level)
}

// ParseVocabCapability returns the highest vocabulary level named in a set of
// capability tokens, and false when none names one. A level above
// CurrentVocabLevel is clamped to it: a newer node than this server can only
// receive ids this server knows.
func ParseVocabCapability(tokens []string) (int, bool) {
	return parseCapability(tokens, vocabCapabilityPrefix, FirstVocabLevel, CurrentVocabLevel)
}

// parseCapability returns the highest "<prefix><n>" level in tokens with
// n >= minimum, clamped to maximum, and false when no token names one.
func parseCapability(tokens []string, prefix string, minimum, maximum int) (int, bool) {
	best, found := 0, false
	for _, tok := range tokens {
		rest, ok := strings.CutPrefix(strings.TrimSpace(tok), prefix)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(rest)
		if err != nil || n < minimum {
			continue
		}
		if n > best {
			best, found = n, true
		}
	}
	if best > maximum {
		best = maximum
	}
	return best, found
}

// NavSectionSince returns the level at which a nav section id, or a page tab
// id, joined the vocabulary. Any "<page>/<tab>" shaped id this build does not
// know is treated as a tab from a newer build (CurrentVocabLevel+1), so a
// projection never serves it to a node that cannot know it either.
func NavSectionSince(id string) int {
	if IsNavTab(id) {
		if lvl, ok := tabSince[id]; ok {
			return lvl
		}
		return FirstTabVocabLevel
	}
	if strings.Contains(id, NavTabSep) {
		return CurrentVocabLevel + 1
	}
	return sinceIn(navSince, id)
}

// SettingsSectionSince returns the level at which a Settings section id joined
// the vocabulary.
func SettingsSectionSince(id string) int { return sinceIn(settingsSince, id) }

func sinceIn(table map[string]int, id string) int {
	if lvl, ok := table[id]; ok {
		return lvl
	}
	return FirstVocabLevel
}

// sectionListRefs addresses the six section lists of a body together with the
// since-table that governs each, so projection and lenient compile walk one
// table rather than six hand-written branches.
func sectionListRefs(s *SectionsV1) []struct {
	name  string
	ids   *[]string
	since func(string) int
	known func(string) bool
} {
	return []struct {
		name  string
		ids   *[]string
		since func(string) int
		known func(string) bool
	}{
		{"sections.hidden", &s.Hidden, NavSectionSince, IsNavSectionOrTab},
		{"sections.read_only", &s.ReadOnly, NavSectionSince, IsNavSection},
		{"sections.settings_hidden", &s.SettingsHidden, SettingsSectionSince, IsSettingsSection},
		{"sections.settings_read_only", &s.SettingsReadOnly, SettingsSectionSince, IsSettingsSection},
		{"sections.visible", &s.Visible, NavSectionSince, IsNavSection},
		{"sections.settings_visible", &s.SettingsVisible, SettingsSectionSince, IsSettingsSection},
	}
}

// ProjectToVocab is ProjectToTarget on the section vocabulary alone: the
// body schema and the key vocabulary are this build's own, so it never fails.
// b is not modified.
func ProjectToVocab(b Body, level int) (Body, []string) {
	out, removed, err := ProjectToTarget(b, Target{Level: level, MaxSchema: MaxSchema, KeyGen: CurrentKeyGen})
	if err != nil {
		// Unreachable: only a schema below MaxSchema can make a body
		// inexpressible. Serve the input unchanged rather than half a body.
		return b, nil
	}
	return out, removed
}

// IsVocabProjection reports whether held is exactly what ProjectToTarget makes
// of full for some OLDER target that removes something. The accept path uses
// it for the one legitimate equal-version, different-bytes delivery: a node
// that was served a projected body, upgraded, and now advertises a newer
// target is served the same version with what it used to lack. Anything else
// at an equal version is still a replay.
func IsVocabProjection(full, held Body) bool {
	heldCanon, err := CanonicalJSON(held)
	if err != nil {
		return false
	}
	current := CurrentTarget()
	for level := FirstVocabLevel; level <= CurrentVocabLevel; level++ {
		for schema := 1; schema <= MaxSchema; schema++ {
			for keys := FirstKeyGen; keys <= CurrentKeyGen; keys++ {
				t := Target{Level: level, MaxSchema: schema, KeyGen: keys}
				if t == current {
					continue
				}
				projected, removed, err := ProjectToTarget(full, t)
				if err != nil || len(removed) == 0 {
					continue
				}
				canon, err := CanonicalJSON(projected)
				if err != nil {
					continue
				}
				if bytes.Equal(canon, heldCanon) {
					return true
				}
			}
		}
	}
	return false
}

func cloneSections(s SectionsV1) SectionsV1 {
	cp := func(in []string) []string {
		if in == nil {
			return nil
		}
		return append([]string(nil), in...)
	}
	return SectionsV1{
		Hidden: cp(s.Hidden), ReadOnly: cp(s.ReadOnly),
		SettingsHidden: cp(s.SettingsHidden), SettingsReadOnly: cp(s.SettingsReadOnly),
		Visible: cp(s.Visible), SettingsVisible: cp(s.SettingsVisible),
	}
}

// CompileBodyLenient is CompileBody for the AGENT accept path: a section id
// outside this build's vocabulary is dropped and reported in
// PolicySpec.IgnoredIDs (as "<list>:<id>") instead of failing the whole body.
// Every other rule stays hard, including the T8 floor, duplicate and conflict
// checks on known ids, the pin grammar and the schema gate. The publish lint
// keeps the strict CompileBody: an admin must still be told when they name a
// page the SERVER does not know.
func CompileBodyLenient(raw []byte, maxBytes int64) (spec PolicySpec, canonicalBody []byte, err error) {
	body, err := DecodeBody(raw, maxBytes)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	body.Sections = cloneSections(body.Sections)
	var ignored []string
	for _, ref := range sectionListRefs(&body.Sections) {
		kept := (*ref.ids)[:0:0]
		for _, id := range *ref.ids {
			trimmed := strings.TrimSpace(id)
			if trimmed != "" && !ref.known(trimmed) {
				ignored = append(ignored, ref.name+":"+trimmed)
				continue
			}
			kept = append(kept, id)
		}
		if len(kept) == 0 {
			kept = nil
		}
		*ref.ids = kept
	}
	spec, err = Compile(body.ToPolicyInput())
	if err != nil {
		return PolicySpec{}, nil, fmt.Errorf("policyfam/nodegov.CompileBodyLenient: %w", err)
	}
	canon, err := CanonicalJSON(body)
	if err != nil {
		return PolicySpec{}, nil, err
	}
	spec.IgnoredIDs = ignored
	return spec, canon, nil
}
