package update

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/announce"
)

// TestNotesCapMatchesAnnouncementBanner pins the one-owner claim in
// manifest.go: the update notice renders through the announcement
// banner component, so the two caps must agree. The dependency is
// TEST-ONLY on purpose — the production package stays stdlib-only
// (imports_test.go) while the invariant still fails loudly if either
// side moves.
func TestNotesCapMatchesAnnouncementBanner(t *testing.T) {
	if MaxNotesChars != announce.MaxBodyChars {
		t.Fatalf("MaxNotesChars = %d, announce.MaxBodyChars = %d — the banner shares the cap",
			MaxNotesChars, announce.MaxBodyChars)
	}
}

// TestCanonicalJSONIsDeterministicAndSorted proves the property the
// whole signature rests on: the same manifest always encodes to the
// same bytes, with sorted keys and no insignificant whitespace.
func TestCanonicalJSONIsDeterministicAndSorted(t *testing.T) {
	m := baseManifest()
	a, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	b, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(a) != string(b) {
		t.Fatal("CanonicalJSON is not deterministic")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, a); err != nil {
		t.Fatalf("compact: %v", err)
	}
	if compact.String() != string(a) {
		t.Errorf("CanonicalJSON emitted insignificant whitespace:\n got %s\nwant %s", a, compact.String())
	}
	// Sorted keys: "artifacts" precedes "channel" precedes "schema".
	iA, iC, iS := strings.Index(string(a), `"artifacts"`), strings.Index(string(a), `"channel"`), strings.Index(string(a), `"schema"`)
	if !(iA < iC && iC < iS) {
		t.Errorf("keys are not sorted: artifacts@%d channel@%d schema@%d", iA, iC, iS)
	}
	// A large manifest_version survives as an integer, not a float.
	big := m
	big.ManifestVersion = 9007199254740993
	raw, err := CanonicalJSON(big)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if !strings.Contains(string(raw), "9007199254740993") {
		t.Errorf("large manifest_version was mangled: %s", raw)
	}
}

// TestCanonicalJSONRoundTrips checks that canonical bytes decode back
// into the same manifest.
func TestCanonicalJSONRoundTrips(t *testing.T) {
	m := baseManifest()
	raw, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	got, err := DecodeManifest(raw)
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	want, _ := json.Marshal(m)
	gotJSON, _ := json.Marshal(got)
	if string(want) != string(gotJSON) {
		t.Errorf("round trip changed the manifest:\n got %s\nwant %s", gotJSON, want)
	}
}

// TestDecodeManifestRefusesTrailingValue pins the exactly-one-value
// rule at the manifest layer too.
func TestDecodeManifestRefusesTrailingValue(t *testing.T) {
	raw, _ := CanonicalJSON(baseManifest())
	if _, err := DecodeManifest(append(raw, []byte(`{"schema":"x"}`)...)); err == nil {
		t.Fatal("expected a trailing-value refusal")
	}
}

// TestProbeSchemaSurvivesAnUnparseableBody is the forward-compat
// property rule 5 depends on: a v2 manifest may change any other
// field's SHAPE, and the schema must still be readable.
func TestProbeSchemaSurvivesAnUnparseableBody(t *testing.T) {
	got, err := ProbeSchema([]byte(`{"schema":"sbo.update-manifest.v2","artifacts":{"not":"an array"}}`))
	if err != nil {
		t.Fatalf("ProbeSchema: %v", err)
	}
	if got != "sbo.update-manifest.v2" {
		t.Fatalf("schema = %q", got)
	}
	if _, err := DecodeManifest([]byte(`{"artifacts":{"not":"an array"}}`)); err == nil {
		t.Fatal("DecodeManifest should fail on that body — the probe is what makes rule 5 answerable")
	}
}

// TestValidate is the structural table: one row per rule Validate
// enforces.
func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Manifest)
		wantErr bool
	}{
		{"the golden manifest is valid", func(*Manifest) {}, false},
		{"unknown schema", func(m *Manifest) { m.Schema = "sbo.update-manifest.v2" }, true},
		{"unknown channel", func(m *Manifest) { m.Channel = "nightly" }, true},
		{"lts is a known channel", func(m *Manifest) { m.Channel = ChannelLTS }, false},
		{"zero manifest_version", func(m *Manifest) { m.ManifestVersion = 0 }, true},
		{"negative manifest_version", func(m *Manifest) { m.ManifestVersion = -1 }, true},
		{"version without a leading v", func(m *Manifest) { m.Version = "1.33.0" }, true},
		{"version that is not semver", func(m *Manifest) { m.Version = "v1.33" }, true},
		{"missing expires_at", func(m *Manifest) { m.ExpiresAt = "" }, true},
		{"expires_at before released_at", func(m *Manifest) { m.ExpiresAt = "2026-01-01T00:00:00Z" }, true},
		{"non-RFC3339 released_at", func(m *Manifest) { m.ReleasedAt = "2026-09-10" }, true},
		{"non-RFC3339 eos_at", func(m *Manifest) { m.EOSAt = "soon" }, true},
		{"notes over the cap", func(m *Manifest) { m.Notes = strings.Repeat("x", MaxNotesChars+1) }, true},
		{"notes exactly at the cap", func(m *Manifest) { m.Notes = strings.Repeat("x", MaxNotesChars) }, false},
		{"http notes_url", func(m *Manifest) { m.NotesURL = "http://superbased.app/x" }, true},
		{"no artifacts", func(m *Manifest) { m.Artifacts = nil }, true},
		{"duplicate artifact rows", func(m *Manifest) {
			m.Artifacts = []Artifact{linuxArtifact(), linuxArtifact()}
		}, true},
		{"duplicate rows under different platform spellings", func(m *Manifest) {
			alt := linuxArtifact()
			alt.Arch = "x64"
			m.Artifacts = []Artifact{linuxArtifact(), alt}
		}, true},
		{"unknown archive_type", func(m *Manifest) { m.Artifacts[0].ArchiveType = "7z" }, true},
		{"filename with a path separator", func(m *Manifest) { m.Artifacts[0].Filename = "../observer.tar.gz" }, true},
		{"filename that is a traversal element", func(m *Manifest) { m.Artifacts[0].Filename = ".." }, true},
		{"zero size_bytes", func(m *Manifest) { m.Artifacts[0].SizeBytes = 0 }, true},
		{"short sha256", func(m *Manifest) { m.Artifacts[0].SHA256 = "abcd" }, true},
		{"non-hex member_sha256", func(m *Manifest) {
			m.Artifacts[0].MemberSHA256 = strings.Repeat("z", 64)
		}, true},
		{"absolute member", func(m *Manifest) { m.Artifacts[0].Member = "/usr/bin/observer" }, true},
		{"traversal member", func(m *Manifest) { m.Artifacts[0].Member = "../observer" }, true},
		{"windows-absolute member", func(m *Manifest) { m.Artifacts[0].Member = `C:\observer.exe` }, true},
		{"nested member is allowed", func(m *Manifest) { m.Artifacts[0].Member = "bin/observer" }, false},
		{"alias repeating the member", func(m *Manifest) {
			m.Artifacts[0].AliasMembers = []string{"observer"}
		}, true},
		{"signature without a type", func(m *Manifest) { m.Artifacts[0].UpstreamSigType = "" }, true},
		{"unknown signature type", func(m *Manifest) { m.Artifacts[0].UpstreamSigType = "pgp" }, true},
		{"cosign-bundle is not spellable", func(m *Manifest) { m.Artifacts[0].UpstreamSigType = "cosign-bundle" }, true},
		{"minisign is not spellable", func(m *Manifest) { m.Artifacts[0].UpstreamSigType = "minisign" }, true},
		{"no signature at all is structurally VALID (rule 9 blocks it, not Validate)", func(m *Manifest) {
			m.Artifacts[0].UpstreamSig = ""
			m.Artifacts[0].UpstreamSigType = ""
		}, false},
		{"min_from_version that is not semver", func(m *Manifest) { m.MinFromVersion = "old" }, true},
		{"allow_downgrade_to that is not semver", func(m *Manifest) { m.AllowDowngradeTo = "previous" }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := baseManifest()
			tc.mutate(&m)
			err := Validate(m)
			if tc.wantErr && err == nil {
				t.Fatal("expected a validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

// TestSigTypeVocabularyIsOnlyWhatIsVerified pins the honesty rule this
// package's vocabulary exists to keep: a scheme a node cannot verify must
// not be spellable in a manifest at all.
//
// It used to be spellable. `cosign-bundle` and `minisign` were declared
// here with no verifier anywhere in the tree, which meant a manifest could
// carry a label that read as a stronger guarantee than the check anyone
// actually performs (raw Ed25519 over the archive bytes, and nothing
// else). Declaring a scheme is a promise; the promise was never kept, so
// the declaration is gone. Adding a scheme back means adding its verifier
// in the same change, and this test is what will fail if it does not.
func TestSigTypeVocabularyIsOnlyWhatIsVerified(t *testing.T) {
	if !KnownSigType(SigTypeEd25519) {
		t.Fatalf("KnownSigType(%q) = false, but it is the scheme the pipeline produces and the node verifies", SigTypeEd25519)
	}
	for _, bad := range []string{"cosign-bundle", "minisign", "pgp", "gpg", "ED25519", " ed25519", ""} {
		if KnownSigType(bad) {
			t.Errorf("KnownSigType(%q) = true, but nothing in this tree verifies it", bad)
		}
	}
}

// TestSortArtifactsIsStableAcrossPublishers proves two servers building
// the same release canonicalise identically.
func TestSortArtifactsIsStableAcrossPublishers(t *testing.T) {
	a := []Artifact{windowsArtifact(), linuxArtifact()}
	b := []Artifact{linuxArtifact(), windowsArtifact()}
	SortArtifacts(a)
	SortArtifacts(b)
	ma, mb := baseManifest(), baseManifest()
	ma.Artifacts, mb.Artifacts = a, b
	ca, err := CanonicalJSON(ma)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	cb, err := CanonicalJSON(mb)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if string(ca) != string(cb) {
		t.Fatal("sorted artifacts did not canonicalise identically")
	}
}

// TestHashBytesMatchesTheEnvelopeGolden ties the hash spelling to the
// committed corpus.
func TestHashBytesMatchesTheEnvelopeGolden(t *testing.T) {
	var env Envelope
	if err := json.Unmarshal(loadEnvelope(t, "valid"), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.ManifestB64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if HashBytes(raw) != env.ManifestHash {
		t.Fatal("HashBytes disagrees with the committed envelope")
	}
}
