package announce

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// Severity is the announcement's display tier. Three values only — the
// banner is a slim strip, not a notification centre (plan §1).
type Severity string

const (
	// SeverityInfo is the default, neutral tier: "here is something we
	// changed". Renders in the banner's neutral styling.
	SeverityInfo Severity = "info"
	// SeverityNotice is the accent tier: something the operator should
	// act on eventually (a deprecation, a changed default).
	SeverityNotice Severity = "notice"
	// SeverityCritical is the red tier, RESERVED for security
	// advisories. Overusing it is how a banner surface dies.
	SeverityCritical Severity = "critical"
)

// Source records which rail an announcement arrived on. It is carried
// on the wire so the dashboard can be honest about provenance ("from
// your org" vs "from the release").
type Source string

const (
	// SourceRelease is rail R1 (compiled in) or rail R2 (the piggyback
	// field on our own published package.json). Both are authored by us
	// at release time and are indistinguishable to the reader.
	SourceRelease Source = "release"
	// SourceOrg is rail R3: authored by the operator's own org admin and
	// distributed over the Teams rail the node already polls.
	SourceOrg Source = "org"
)

// MaxBodyChars is the hard cap on Body, counted in runes. A banner is a
// one-glance surface; anything longer belongs behind URL.
const MaxBodyChars = 280

// MaxTitleChars caps Title. The plan specifies "one line"; this is the
// enforceable reading of that.
const MaxTitleChars = 120

// MaxIDChars caps ID. Ids are date-prefixed slugs
// ("2026-07-31-example"), never free text.
const MaxIDChars = 128

// Announcement is the single shape carried by every rail (plan §1) —
// the compiled-in release slice, the npm-registry piggyback field, and
// (later) the org document all decode to exactly this. The JSON tags
// are the wire contract: changing one is a breaking change on three
// rails at once.
type Announcement struct {
	// ID is the stable dismissal key. The frontend records acked ids in
	// localStorage under sb_announce_ack, so an id must never be reused
	// for different content — a reused id is a silently-unshown banner.
	ID string `json:"id"`
	// Severity is the display tier (info | notice | critical).
	Severity Severity `json:"severity"`
	// Title is the one-line headline, plain text.
	Title string `json:"title"`
	// Body is the plain-text detail, <= MaxBodyChars runes. Never HTML,
	// never markdown — the frontend renders it as text and the plan
	// (§6) records that as a deliberate non-goal.
	Body string `json:"body"`
	// URL is an optional https link (release notes, advisory). Rendered
	// as a single "Details →" anchor. http:// is rejected outright.
	URL string `json:"url,omitempty"`
	// ExpiresAt is RFC3339 and REQUIRED on every rail: the banner
	// self-retires, because a stale banner is worse than no banner.
	ExpiresAt string `json:"expires_at"`
	// Source is the originating rail (release | org).
	Source Source `json:"source"`
	// FixedIn, optional, is the release ("1.32.0") from which the
	// announcement no longer applies: a node at or past it does not show
	// it (WINNODE2 16b, a "v1.32.0 fixes ..." banner on a v1.36.0 node).
	// Additive on every rail: an older reader ignores the field.
	FixedIn string `json:"fixed_in,omitempty"`
}

// releaseAnnouncements is rail R1: the announcements compiled into this
// binary. It is EMPTY on purpose and is empty in most releases.
//
// HOW TO AUTHOR ONE (release time, not feature time): append a literal
// to this slice in the release commit, e.g.
//
//	{
//		ID:        "2026-08-14-proxy-default",
//		Severity:  SeverityNotice,
//		Title:     "Conversation compression is now off by default",
//		Body:      "v1.30 flips [compression.conversation].enabled to false ...",
//		URL:       "https://superbased.app/docs/reference/compression",
//		ExpiresAt: "2026-10-01T00:00:00Z",
//		Source:    SourceRelease,
//	}
//
// Rules that are not negotiable: ExpiresAt is required and should be
// weeks-to-months out, never open-ended; ID must be new (a reused id is
// pre-dismissed for every operator who acked the old one); SeverityCritical
// is for security advisories only. Run the package tests after
// editing — TestReleaseAnnouncementsAreValid validates every literal
// here, so a malformed announcement fails the build, not the dashboard.
//
// This slice reaches only dashboards running THIS release. The rail that
// reaches older installs is R2 (the npm-registry piggyback field in
// npm/observer/package.json), and the rail that reaches a fleet in
// minutes is R3 (org). See plan §0 for why no fourth rail can exist.
//
// The plugin-coverage banner's copy was operator-signed-off 2026-08-26 for
// the v1.32.0 release (it had shipped in npm metadata as a draft earlier).
// It deliberately names NO version: the plugins tree it describes reached
// users in the 1.28.0 refresh, but this text stays true whenever it
// ships, so it cannot go stale against a retag or a slipped release.
//
// The disk-maintenance banner pairs with the 2026-08-26 disk/compute
// remediation (CHANGELOG v1.32.0); its R2 copy in npm/observer/package.json
// takes that rail's single slot because older installs — the audience that
// still has the bug — are exactly who R2 reaches.
var releaseAnnouncements = []Announcement{
	{
		ID:        "2026-08-26-disk-maintenance-fix",
		Severity:  SeverityNotice,
		Title:     "v1.32.0 fixes unbounded database maintenance that could fill the disk",
		Body:      "Large databases could trigger automatic full-database VACUUM and integrity scans, silently consuming tens of GB of disk plus sustained CPU. v1.32.0 removes the unbounded paths, bounds SQLite memory and temp use, and adds a watchdog. Upgrade any machines on older versions.",
		URL:       "https://github.com/superbasedapp/observer/releases",
		ExpiresAt: "2026-11-01T00:00:00Z",
		Source:    SourceRelease,
		FixedIn:   "1.32.0",
	},
	{
		ID:        "2026-08-plugin-coverage",
		Severity:  SeverityInfo,
		Title:     "SuperBased now installs as a native plugin in 22 AI coding tools",
		Body:      "Claude Code, Codex, Cursor, Copilot, Gemini, OpenCode and 16 more now have a native SuperBased plugin. See the plugins repo for the install command for your tool.",
		URL:       "https://github.com/superbasedapp/plugins",
		ExpiresAt: "2026-10-01T00:00:00Z",
		Source:    SourceRelease,
	},
	{
		ID:        "v1.37.0-macos13-codesec",
		Severity:  SeverityNotice,
		Title:     "v1.37.0 needs macOS 13 or later, and code security is now on",
		Body:      "This release needs macOS 13 Ventura or later. On macOS 12, stay on v1.36.0. Code security is now on by default in the developer and full editions, so an agent commit or push can ask you first. Run observer guard status to see it.",
		URL:       "https://github.com/superbasedapp/observer/releases/tag/v1.37.0",
		ExpiresAt: "2026-12-30T00:00:00Z",
		Source:    SourceRelease,
	},
}

// Release returns rail R1's compiled-in announcements. The returned
// slice is a copy — callers (the dashboard handler) must not be able to
// mutate the binary's own data.
func Release() []Announcement {
	out := make([]Announcement, len(releaseAnnouncements))
	copy(out, releaseAnnouncements)
	return out
}

// ErrInvalid is the sentinel every Validate failure wraps, so callers
// can errors.Is on the class without matching on message text.
var ErrInvalid = errors.New("announce: invalid announcement")

// Validate enforces the plan §1 constraints. It is total: every rail
// runs it before an announcement can reach a banner, including the
// compiled-in one (a test asserts it), so no rail can be the one that
// smuggles HTML, an http:// link, or an open-ended banner through.
func Validate(a Announcement) error {
	if strings.TrimSpace(a.ID) == "" {
		return fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if utf8.RuneCountInString(a.ID) > MaxIDChars {
		return fmt.Errorf("%w: id exceeds %d chars", ErrInvalid, MaxIDChars)
	}
	switch a.Severity {
	case SeverityInfo, SeverityNotice, SeverityCritical:
	default:
		return fmt.Errorf("%w: unknown severity %q", ErrInvalid, a.Severity)
	}
	switch a.Source {
	case SourceRelease, SourceOrg:
	default:
		return fmt.Errorf("%w: unknown source %q", ErrInvalid, a.Source)
	}
	if strings.TrimSpace(a.Title) == "" {
		return fmt.Errorf("%w: title is required", ErrInvalid)
	}
	if utf8.RuneCountInString(a.Title) > MaxTitleChars {
		return fmt.Errorf("%w: title exceeds %d chars", ErrInvalid, MaxTitleChars)
	}
	if hasControlChars(a.Title) {
		return fmt.Errorf("%w: title must be a single plain-text line", ErrInvalid)
	}
	if strings.TrimSpace(a.Body) == "" {
		return fmt.Errorf("%w: body is required", ErrInvalid)
	}
	if n := utf8.RuneCountInString(a.Body); n > MaxBodyChars {
		return fmt.Errorf("%w: body is %d chars, max %d", ErrInvalid, n, MaxBodyChars)
	}
	if hasControlChars(a.Body) {
		return fmt.Errorf("%w: body must be plain text (no control characters)", ErrInvalid)
	}
	if a.URL != "" {
		u, err := url.Parse(a.URL)
		if err != nil {
			return fmt.Errorf("%w: url is unparseable: %w", ErrInvalid, err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("%w: url must be https, got %q", ErrInvalid, u.Scheme)
		}
		if u.Host == "" {
			return fmt.Errorf("%w: url has no host", ErrInvalid)
		}
	}
	if a.FixedIn != "" {
		if _, ok := parseRelease(a.FixedIn); !ok {
			return fmt.Errorf("%w: fixed_in %q is not a release version (1.2.3)", ErrInvalid, a.FixedIn)
		}
	}
	if strings.TrimSpace(a.ExpiresAt) == "" {
		return fmt.Errorf("%w: expires_at is required (banners self-retire)", ErrInvalid)
	}
	if _, err := time.Parse(time.RFC3339, a.ExpiresAt); err != nil {
		return fmt.Errorf("%w: expires_at is not RFC3339: %w", ErrInvalid, err)
	}
	return nil
}

// hasControlChars reports whether s contains a newline, tab, or other
// C0/C1 control character. Bodies are rendered as plain text in a
// one-line strip; a newline there is either an authoring mistake or an
// attempt at layout we don't support.
func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return true
		}
	}
	return false
}

// ErrMalformedDocument is the sentinel Decode failures wrap. Distinct
// from ErrInvalid: that one means "this announcement breaks a §1 rule",
// this one means "this is not an announcement document at all".
var ErrMalformedDocument = errors.New("announce: malformed announcement document")

// Decode parses a rail-R3 announcement DOCUMENT body — the JSON string
// the org server signs and the node caches — into announcements.
//
// Three accepted shapes, in the order a caller will meet them:
//
//   - "" (or whitespace) → (nil, nil). An empty body is the RETRACTION
//     document: signed, versioned, and deliberately saying nothing.
//     It is not an error and callers must not treat it as one.
//   - a single JSON object → a one-element slice. This is what the
//     web2 composer publishes today.
//   - a NON-EMPTY JSON array of objects → all of them. Nothing
//     publishes this yet; it is accepted from day one so that shipping
//     a multi-announcement composer later needs no wire change and no
//     version negotiation against already-deployed nodes.
//
// Retraction has exactly ONE representation: the empty body. "[]" and
// "null" are ERRORS, not synonyms for it. They used to decode to
// "nothing to show" — the same OUTCOME by three different byte strings,
// each with its own hash and its own signature, which is precisely the
// ambiguity Encode's "zero announcements encode as ”" rule exists to
// prevent. One representation means an operator comparing two
// retraction documents compares equal bytes, and a rail that dedupes or
// audits on BodyHash sees one value rather than three.
//
// Decoding is deliberately TOLERANT of unknown fields (a newer server
// adding a field must not brick an older node) and deliberately does
// NOT validate: Validate is the caller's call, because the two callers
// want opposite failure modes. The org server validates and REFUSES to
// sign (a bad announcement never reaches the fleet); the node dashboard
// hands the result to Merge, which silently drops anything invalid (a
// bad announcement degrades to no banner, never a broken one).
func Decode(body string) ([]Announcement, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, nil
	}
	if trimmed == "null" {
		return nil, fmt.Errorf("%w: %q is not a document - the retraction is the EMPTY body", ErrMalformedDocument, "null")
	}
	if strings.HasPrefix(trimmed, "[") {
		var many []Announcement
		if err := json.Unmarshal([]byte(trimmed), &many); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedDocument, err)
		}
		if len(many) == 0 {
			return nil, fmt.Errorf("%w: %q is not a document - the retraction is the EMPTY body", ErrMalformedDocument, "[]")
		}
		return many, nil
	}
	var one Announcement
	if err := json.Unmarshal([]byte(trimmed), &one); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedDocument, err)
	}
	return []Announcement{one}, nil
}

// Encode renders announcements back into a document body suitable for
// signing. A single announcement encodes as a bare object (the shape
// the composer publishes and the shape a human reading an audit row
// expects); zero announcements encode as "" — the retraction document,
// NOT "[]" — so retraction has exactly one byte-level representation
// and therefore exactly one hash.
func Encode(list []Announcement) (string, error) {
	if len(list) == 0 {
		return "", nil
	}
	var (
		raw []byte
		err error
	)
	if len(list) == 1 {
		raw, err = json.Marshal(list[0])
	} else {
		raw, err = json.Marshal(list)
	}
	if err != nil {
		return "", fmt.Errorf("announce.Encode: %w", err)
	}
	return string(raw), nil
}

// Merge folds any number of rail sources into the ordered list the
// dashboard serves. Behaviour, all of it deliberate:
//
//   - Invalid announcements are DROPPED, not surfaced. Sources include
//     data that will arrive over a wire (rail R3), so malformed input
//     must degrade to "no banner", never to a broken one.
//   - Expired announcements are dropped: an announcement is live only
//     while now is strictly before ExpiresAt (expiry instant == retired).
//   - Duplicate ids collapse to the FIRST occurrence, so callers express
//     precedence purely by source order.
//   - Ordering is severity descending (critical > notice > info), then
//     "newest" first, then id for total determinism.
//
// On "newest": the §1 shape carries no created_at, by design (fewer
// fields, one shape on three rails). ExpiresAt descending is the proxy —
// announcements are authored with a forward expiry, so the later expiry
// is, in practice, the more recently written one. The frontend banner
// mirrors this exact ordering so the one announcement it shows matches
// the head of this list.
//
// The returned slice is never nil, so a JSON encoding of it is [] and
// never null.
func Merge(now time.Time, sources ...[]Announcement) []Announcement {
	out := make([]Announcement, 0, 4)
	seen := make(map[string]struct{}, 4)
	for _, src := range sources {
		for _, a := range src {
			if _, dup := seen[a.ID]; dup {
				continue
			}
			if Validate(a) != nil {
				continue
			}
			exp, err := time.Parse(time.RFC3339, a.ExpiresAt)
			if err != nil || !now.Before(exp) {
				continue
			}
			seen[a.ID] = struct{}{}
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := severityRank(out[i].Severity), severityRank(out[j].Severity); ri != rj {
			return ri > rj
		}
		ei := mustExpiry(out[i].ExpiresAt)
		ej := mustExpiry(out[j].ExpiresAt)
		if !ei.Equal(ej) {
			return ei.After(ej)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// severityRank orders the display tiers. Unknown severities cannot
// reach here (Merge validates first), but rank 0 keeps the comparator
// total if one ever does.
func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityNotice:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// mustExpiry parses an already-validated ExpiresAt. A parse failure is
// impossible on the Merge path (Validate ran first); the zero time keeps
// the sort total rather than panicking in library code.
func mustExpiry(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// ForVersion drops the announcements a node running version no longer
// needs: those whose FixedIn is at or below it. A running version that is
// not a release (a dev build, an empty string) keeps every announcement,
// so a developer build is never told it is fixed by guesswork.
func ForVersion(list []Announcement, running string) []Announcement {
	have, ok := parseRelease(running)
	if !ok {
		return list
	}
	out := list[:0:0]
	for _, a := range list {
		if fixed, ok := parseRelease(a.FixedIn); ok && compareRelease(have, fixed) >= 0 {
			continue
		}
		out = append(out, a)
	}
	return out
}

// parseRelease reads "1.2.3" (a leading "v" and any "-pre" or "+build"
// suffix allowed) into its three numbers.
func parseRelease(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		if p == "" {
			return out, false
		}
		n := 0
		for _, r := range p {
			if r < '0' || r > '9' {
				return out, false
			}
			n = n*10 + int(r-'0')
			if n > 1<<20 {
				return out, false
			}
		}
		out[i] = n
	}
	return out, true
}

// compareRelease orders two parsed releases.
func compareRelease(a, b [3]int) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
