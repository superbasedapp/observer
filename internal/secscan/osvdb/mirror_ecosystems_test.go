package osvdb

import (
	"regexp"
	"testing"
)

// mirroredExportBytes are the language exports the signed mirror carries
// (deploy/feed-publisher/publish.sh ALL_ECOSYSTEMS), each with its all.zip
// Content-Length on the OSV bucket on 2026-11-06, the day the last six
// joined. They are the honesty check of ApproxDownloadMB, the size the
// accept text states.
var mirroredExportBytes = []struct {
	eco   string
	bytes int64
}{
	{"npm", 220014496},
	{"PyPI", 37642129},
	{"Go", 12721431},
	{"crates.io", 3785190},
	{"RubyGems", 5213495},
	{"Packagist", 11107494},
	{"NuGet", 2695287},
	{"Maven", 10523288},
	{"GitHub Actions", 100334},
	{"Pub", 25896},
	{"SwiftURL", 113094},
	{"Hex", 889872},
	{"Hackage", 58359},
	{"Julia", 2143646},
	{"CRAN", 11944},
}

// TestApproxDownloadMBHonest: the size the accept states is within 10% of
// what the mirrored exports weigh, so adding an ecosystem that moves the
// first download materially fails here and asks for a new figure (and,
// per ConsentVersion's rule, a new accept when the download grew a lot).
func TestApproxDownloadMBHonest(t *testing.T) {
	t.Parallel()
	var sum int64
	for _, e := range mirroredExportBytes {
		if !ValidEcosystem(e.eco) || e.bytes <= 0 || e.bytes > MaxExportBytes {
			t.Errorf("%s: %d bytes", e.eco, e.bytes)
		}
		sum += e.bytes
	}
	stated := int64(ApproxDownloadMB) * 1000 * 1000
	if diff := sum - stated; diff*10 > stated || -diff*10 > stated {
		t.Errorf("the exports weigh %d bytes, the accept text says about %d MB", sum, ApproxDownloadMB)
	}
}

// TestConsentTextNamesNoEcosystem: the accept text names no ecosystem, so
// one accept covers every ecosystem the store downloads, including the
// ones added after it was given (no new accept for Pub, SwiftURL, Hex,
// Hackage, Julia and CRAN on 2026-11-06). A text that started listing
// ecosystems would make a later addition a material change.
func TestConsentTextNamesNoEcosystem(t *testing.T) {
	t.Parallel()
	for _, e := range mirroredExportBytes {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(e.eco) + `\b`).MatchString(ConsentText) {
			t.Errorf("the accept text names %s: %s", e.eco, ConsentText)
		}
	}
}

// TestMirroredEcosystemArtifacts: every mirrored ecosystem has a base and a
// delta artifact name the site worker serves (website/_worker.js
// SECURITY_FEED_FILE_RE, publish.sh FILE_RE), none of them collides with
// another's or with an OS release artifact, and the six added on
// 2026-11-06 keep their bucket spelling.
func TestMirroredEcosystemArtifacts(t *testing.T) {
	t.Parallel()
	served := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	seen := map[string]string{}
	for _, e := range mirroredExportBytes {
		for _, art := range []string{ExportArtifact(e.eco), DeltaArtifact(e.eco)} {
			if art == "" || !served.MatchString(art) {
				t.Errorf("%s: artifact %q is not a name the site serves", e.eco, art)
				continue
			}
			if prev, dup := seen[art]; dup {
				t.Errorf("%s and %s share the artifact %s", prev, e.eco, art)
			}
			seen[art] = e.eco
		}
		base, ok := ArtifactBase(e.eco)
		if !ok {
			t.Errorf("%s: no artifact base", e.eco)
			continue
		}
		if _, isRelease := ReleaseByArtifact(base); isRelease {
			t.Errorf("%s: artifact base %s is an OS release's", e.eco, base)
		}
	}
	for eco, want := range map[string]string{
		"Pub": "Pub.zip", "SwiftURL": "SwiftURL.zip", "Hex": "Hex.zip",
		"Hackage": "Hackage.zip", "Julia": "Julia.zip", "CRAN": "CRAN.zip",
	} {
		if got := ExportArtifact(eco); got != want {
			t.Errorf("ExportArtifact(%q) = %q, want %q", eco, got, want)
		}
	}
}
