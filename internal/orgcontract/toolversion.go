package orgcontract

import (
	"regexp"
	"strings"
)

// MaxToolVersionRunes bounds a captured tool/CLI version token
// (SessionRow.ToolVersion). A real vendor-stamped version — "1.2.3",
// "2026.8.2", "v0.130.0", "1.8.1-rc.1", "0.45.0+build.7", "2.1.0_beta" — is
// well under this; anything longer is a mis-decoded free-text field, not a
// version. It is also the grammar's own ceiling: toolVersionPattern's
// longest match (an optional leading "v"/"V", a digit, then up to 62 more
// characters) is exactly 64 runes.
const MaxToolVersionRunes = 64

// toolVersionPattern is the ONE grammar for "version-shaped" (TOOLVERSION-1,
// docs/security.md), enforced identically at both boundaries that ever write
// a tool_version column: the node (internal/store/toolversion.go, on
// capture) and the org server (internal/orgserver/ingest/ingest.go, on
// landing a pushed row). It is deliberately NOT a semver validator — real
// adapters stamp all sorts of shapes, not just MAJOR.MINOR.PATCH — but it
// narrows the grammar to the shapes actually observed rather than "any
// alphanumeric token", because that laxer grammar was found (2026-09-23
// review, TOOLVERSION-1 follow-up) to also admit compact secrets:
// "AKIAIOSFODNN7EXAMPLE" (an AWS access key id) and
// "ghp_abcdefghijklmnopqrstuvwxyz1234567890" (a GitHub PAT) both pass a
// bare `^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$` charset check.
//
// The grammar is now: an optional leading "v"/"V" (CLI tools commonly
// self-report "v0.130.0"), then a DIGIT (a version token always starts with
// a number, optionally after that one letter), then up to 62 more
// characters from the alphanumeric+"."+"_"+"+"+"-" charset — AND (checked
// separately by ValidToolVersion, a regexp charset class can't express "at
// least one, anywhere") the value must contain at least one ".". The
// rationale: every real version family below is digit-led and dot-bearing
// (MAJOR.MINOR[.PATCH] is the one structural feature every scheme shares,
// even CalVer and build-suffixed semver), while a compact secret is
// alphanumeric noise with no such structure — no leading digit, or no dot,
// or both. A hex sha, a UUID, and a base64-shaped token likewise carry no
// dot. This is exactly why the exclusion works: it is not a blocklist of
// secret shapes, it is a positive requirement (digit-led, dot-bearing) that
// the secret shapes above happen not to satisfy.
//
// Checked against every adapter that stamps a SessionToolVersion today
// (2026-09-22; internal/adapter/{claudecode,codex,cline,kilocode,qoder,
// copilotcli,qwencode}): each reads a vendor-authored version field
// verbatim off disk, and every observed shape — plain semver ("1.2.3"), a
// "v"-prefixed CLI version ("v0.130.0"), a date-based CalVer release
// ("2026.8.2"), and semver with a prerelease or build-metadata suffix
// ("1.8.1-rc.1", "0.45.0+build.7", "2.1.0_beta") — is digit-led (after an
// optional "v"/"V") and dot-bearing, so all of them still match.
var toolVersionPattern = regexp.MustCompile(`^[vV]?[0-9][0-9A-Za-z._+-]{0,62}$`)

// ValidToolVersion reports whether v is a plausible, ASCII, version-shaped
// token: see toolVersionPattern's doc comment for the exact grammar and the
// rationale for why it excludes compact-secret shapes ("AKIA...", "ghp_...",
// a JWT, a hex sha, a UUID) as well as the previously-excluded attack shapes
// ("https://x", "user@example", "../../client", anything carrying "/", "=",
// or whitespace). A value must ALSO contain at least one "." — a regexp
// character class can require a character to appear, but not require it to
// appear at least once anywhere in the string, so that half of the grammar
// is checked here rather than folded into toolVersionPattern. An empty
// string is never valid — the honest "unknown" is the caller
// writing/landing NULL, not this function reporting a pass on "".
func ValidToolVersion(v string) bool {
	return toolVersionPattern.MatchString(v) && strings.Contains(v, ".")
}
