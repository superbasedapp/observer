package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// The golden corpus (plan §4 W1 bullet 3) lives in testdata/ as real
// files rather than as literals, for one reason that matters: the
// signature is over BYTES. A corpus built in memory would verify
// whatever this package's encoder happened to emit that day, which is
// exactly the drift the canonical encoding exists to prevent. Committed
// bytes make an encoder change fail here instead of failing on a fleet.
//
// Regenerate with:
//
//	OBSERVER_UPDATE_REGEN=1 go test ./internal/update/ -run TestGoldenCorpus
//
// and READ THE DIFF: a changed envelope means either the canonical
// encoding or the signing message moved, and both are wire-visible.

// goldenSeedPhrase derives the corpus signing key deterministically, so
// the committed key fixture can be rebuilt from this file alone. It is
// a TEST key: it signs nothing real and is not the org distribution key
// any node pins.
const goldenSeedPhrase = "superbased-observer update-manifest golden corpus key v1"

// goldenKeyFixture is testdata/signing-key.json.
type goldenKeyFixture struct {
	SeedB64      string `json:"seed"`
	PublicKeyB64 string `json:"public_key"`
	KeyID        string `json:"key_id"`
}

// goldenKey returns the corpus key, deriving it from goldenSeedPhrase.
func goldenKey() (ed25519.PrivateKey, goldenKeyFixture) {
	seed := sha256.Sum256([]byte(goldenSeedPhrase))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	idSum := sha256.Sum256(pub)
	return priv, goldenKeyFixture{
		SeedB64:      base64.StdEncoding.EncodeToString(seed[:]),
		PublicKeyB64: base64.StdEncoding.EncodeToString(pub),
		KeyID:        hex.EncodeToString(idSum[:8]),
	}
}

// goldenCase is one corpus entry: a manifest, and how its envelope is
// signed (correctly, or in one of the two attack shapes).
type goldenCase struct {
	// name is the file stem: testdata/manifest-<name>.json and
	// testdata/envelope-<name>.json.
	name string
	// manifest is the document.
	manifest Manifest
	// corruptHash flips a byte of manifest_hash after signing (the
	// mirror-tampering shape, verify rule 2).
	corruptHash bool
	// crossRailSig signs the ANNOUNCEMENT rail's message instead of
	// this rail's, i.e. an announcement document re-presented as a
	// manifest (verify rule 4).
	crossRailSig bool
}

// linuxArtifact is the POSIX tarball the release pipeline emits, alias
// carried as a relative symlink (npm-release.yml:1181-1183).
func linuxArtifact() Artifact {
	return Artifact{
		Kind: KindAgent, OS: "linux", Arch: "amd64",
		ArchiveType: ArchiveTarGz,
		Filename:    "observer-v1.33.0-linux-x64.tar.gz",
		SizeBytes:   41234567,
		SHA256:      "1111111111111111111111111111111111111111111111111111111111111111",
		Member:      "observer", MemberSHA256: "2222222222222222222222222222222222222222222222222222222222222222",
		AliasMembers:    []string{"superbased"},
		UpstreamSigType: SigTypeEd25519,
		UpstreamSig:     "ZWQyNTUxOS1zaWduYXR1cmUtcGxhY2Vob2xkZXItbGludXg=",
	}
}

// windowsArtifact is the win32 zip, alias carried as a byte COPY
// (npm-release.yml:1186-1189).
func windowsArtifact() Artifact {
	return Artifact{
		Kind: KindAgent, OS: "windows", Arch: "amd64",
		ArchiveType: ArchiveZip,
		Filename:    "observer-v1.33.0-win32-x64.zip",
		SizeBytes:   43112233,
		SHA256:      "3333333333333333333333333333333333333333333333333333333333333333",
		Member:      "observer.exe", MemberSHA256: "4444444444444444444444444444444444444444444444444444444444444444",
		AliasMembers:    []string{"superbased.exe"},
		UpstreamSigType: SigTypeEd25519,
		UpstreamSig:     "ZWQyNTUxOS1zaWduYXR1cmUtcGxhY2Vob2xkZXItd2luMzI=",
	}
}

// baseManifest is the valid document every negative case mutates.
func baseManifest() Manifest {
	return Manifest{
		Schema:           SchemaV1,
		Channel:          ChannelStable,
		ManifestVersion:  17,
		Version:          "v1.33.0",
		ReleasedAt:       "2026-09-10T00:00:00Z",
		ExpiresAt:        "2026-12-10T00:00:00Z",
		MinFromVersion:   "v1.28.0",
		MinServerVersion: "v1.33.0",
		EOSAt:            "2027-03-10T00:00:00Z",
		Notes:            "Enterprise update management: signed manifests, staged rings, node rollback.",
		NotesURL:         "https://superbased.app/docs/releases/v1.33.0",
		Artifacts:        []Artifact{linuxArtifact(), windowsArtifact()},
	}
}

// goldenCases is the corpus, one entry per §4 W1 bullet.
func goldenCases() []goldenCase {
	unsigned := baseManifest()
	unsigned.ManifestVersion = 18
	ua := linuxArtifact()
	ua.UpstreamSig = ""
	ua.UpstreamSigType = ""
	unsigned.Artifacts = []Artifact{ua, windowsArtifact()}

	noPlatform := baseManifest()
	noPlatform.ManifestVersion = 19
	noPlatform.Artifacts = []Artifact{{
		Kind: KindAgent, OS: "darwin", Arch: "arm64",
		ArchiveType: ArchiveTarGz,
		Filename:    "observer-v1.33.0-darwin-arm64.tar.gz",
		SizeBytes:   40111222,
		SHA256:      "5555555555555555555555555555555555555555555555555555555555555555",
		Member:      "observer", MemberSHA256: "6666666666666666666666666666666666666666666666666666666666666666",
		AliasMembers:    []string{"superbased"},
		UpstreamSigType: SigTypeEd25519,
		UpstreamSig:     "ZWQyNTUxOS1zaWduYXR1cmUtcGxhY2Vob2xkZXItZGFyd2lu",
	}}

	expired := baseManifest()
	expired.ManifestVersion = 20
	expired.ReleasedAt = "2026-01-01T00:00:00Z"
	expired.ExpiresAt = "2026-04-01T00:00:00Z"

	replay := baseManifest()
	replay.ManifestVersion = 12

	downgrade := baseManifest()
	downgrade.ManifestVersion = 21
	downgrade.Version = "v1.20.0"
	downgrade.MinFromVersion = ""

	requiredStop := baseManifest()
	requiredStop.ManifestVersion = 22
	requiredStop.MinFromVersion = "v1.30.0"

	unknownSchema := baseManifest()
	unknownSchema.ManifestVersion = 23
	unknownSchema.Schema = "sbo.update-manifest.v2"

	return []goldenCase{
		{name: "valid", manifest: baseManifest()},
		{name: "wrong-hash", manifest: baseManifest(), corruptHash: true},
		{name: "wrong-domain-tag", manifest: baseManifest(), crossRailSig: true},
		{name: "replayed-lower-version", manifest: replay},
		{name: "expired", manifest: expired},
		{name: "downgrade", manifest: downgrade},
		{name: "required-stop", manifest: requiredStop},
		{name: "unknown-schema", manifest: unknownSchema},
		{name: "no-artifact-for-platform", manifest: noPlatform},
		{name: "empty-upstream-sig", manifest: unsigned},
	}
}

// announcementSigningMessage reproduces the ANNOUNCEMENT rail's message
// layout (orgcontract/signing.go:129,147-155) so the corpus can hold a
// genuinely-signed document from another rail. This is the cross-rail
// replay verify rule 4 must refuse; it is spelled out here rather than
// imported so this package keeps no dependency on orgcontract.
func announcementSigningMessage(version int64, body string) []byte {
	h := sha256.New()
	h.Write([]byte("superbased-org-announcement"))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatInt(version, 10)))
	h.Write([]byte{0})
	h.Write([]byte(body))
	return h.Sum(nil)
}

// buildEnvelope canonicalises, hashes, signs and (for the two attack
// cases) corrupts.
func buildEnvelope(t *testing.T, priv ed25519.PrivateKey, key goldenKeyFixture, c goldenCase) ([]byte, Envelope) {
	t.Helper()
	raw, err := CanonicalJSON(c.manifest)
	if err != nil {
		t.Fatalf("%s: canonical: %v", c.name, err)
	}
	hash := HashBytes(raw)
	msg := ManifestSigningMessage(c.manifest.ManifestVersion, hash)
	if c.crossRailSig {
		msg = announcementSigningMessage(c.manifest.ManifestVersion, string(raw))
	}
	env := Envelope{
		ManifestB64:  base64.StdEncoding.EncodeToString(raw),
		ManifestHash: hash,
		KeyID:        key.KeyID,
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}
	if c.corruptHash {
		// Flip one hex character: the declared hash no longer matches
		// the bytes, which is the mirror-tampering shape.
		b := []byte(env.ManifestHash)
		if b[0] == '0' {
			b[0] = '1'
		} else {
			b[0] = '0'
		}
		env.ManifestHash = string(b)
	}
	return raw, env
}

// TestGoldenCorpus asserts the committed corpus is byte-identical to
// what this package produces today, and regenerates it under
// OBSERVER_UPDATE_REGEN=1.
func TestGoldenCorpus(t *testing.T) {
	regen := os.Getenv("OBSERVER_UPDATE_REGEN") == "1"
	priv, key := goldenKey()

	keyJSON, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		t.Fatalf("key fixture: %v", err)
	}
	compareOrWrite(t, filepath.Join("testdata", "signing-key.json"), append(keyJSON, '\n'), regen)

	for _, c := range goldenCases() {
		t.Run(c.name, func(t *testing.T) {
			raw, env := buildEnvelope(t, priv, key, c)
			compareOrWrite(t, filepath.Join("testdata", "manifest-"+c.name+".json"), append(raw, '\n'), regen)
			envJSON, err := json.MarshalIndent(env, "", "  ")
			if err != nil {
				t.Fatalf("envelope: %v", err)
			}
			compareOrWrite(t, filepath.Join("testdata", "envelope-"+c.name+".json"), append(envJSON, '\n'), regen)
		})
	}
}

// compareOrWrite is the golden-file primitive.
func compareOrWrite(t *testing.T, path string, want []byte, regen bool) {
	t.Helper()
	if regen {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
		return
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with OBSERVER_UPDATE_REGEN=1)", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s drifted from what this package produces.\n got: %s\nwant: %s", path, got, want)
	}
}

// loadEnvelope reads one committed envelope file as RAW BYTES, which is
// what verify rule 1 consumes.
func loadEnvelope(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "envelope-"+name+".json"))
	if err != nil {
		t.Fatalf("load envelope %s: %v", name, err)
	}
	return b
}
