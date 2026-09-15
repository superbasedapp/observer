package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// releaseKey derives a deterministic test keypair from a phrase, so a case
// can name "the key that signed it" and "some other key" without a fixture.
func releaseKey(phrase string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte(phrase))
	return ed25519.NewKeyFromSeed(seed[:])
}

// pub is the public half, as VerifyReleaseManifest wants it.
func pub(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// signRelease produces the envelope bytes a release publishes: the canonical
// manifest, its hash, and an Ed25519 signature over this rail's domain-tagged,
// version-bound message. It is the same composition scripts/vendorsign uses,
// spelled out here so a drift on either side fails a test rather than a fleet.
func signRelease(t *testing.T, m Manifest, priv ed25519.PrivateKey) []byte {
	t.Helper()
	body, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	hash := HashBytes(body)
	env := Envelope{
		ManifestB64:  base64.StdEncoding.EncodeToString(body),
		ManifestHash: hash,
		KeyID:        "release-test-key",
		Signature: base64.StdEncoding.EncodeToString(
			ed25519.Sign(priv, ManifestSigningMessage(m.ManifestVersion, hash))),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

// releaseManifest is a well-formed published release: two platforms, real
// hashes, a real (if meaningless) vendor signature blob.
func releaseManifest() Manifest {
	return Manifest{
		Schema:          SchemaV1,
		Channel:         ChannelStable,
		ManifestVersion: 1757000000,
		Version:         "v1.33.0",
		ReleasedAt:      "2026-09-08T00:00:00Z",
		ExpiresAt:       "2026-12-07T00:00:00Z",
		SchemaVersion:   105,
		Artifacts:       []Artifact{linuxArtifact(), windowsArtifact()},
	}
}

// TestVerifyReleaseManifest is the table the mirror's two fill paths share.
// Every row is a way a release manifest can be wrong, and the point of the
// function is that `update import` and `update sync` cannot disagree about
// any of them.
func TestVerifyReleaseManifest(t *testing.T) {
	t.Parallel()
	signer := releaseKey("release manifest signer")
	other := releaseKey("some other key entirely")
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

	base := func() ReleaseManifestInput {
		return ReleaseManifestInput{
			EnvelopeBytes: signRelease(t, releaseManifest(), signer),
			Keys:          []ed25519.PublicKey{pub(signer)},
			Channel:       ChannelStable,
			Version:       "v1.33.0",
			Now:           now,
		}
	}

	cases := []struct {
		name    string
		mutate  func(*ReleaseManifestInput)
		wantErr error
	}{
		{"a good manifest verifies", nil, nil},
		{
			"an older key in the accepted set still verifies",
			func(in *ReleaseManifestInput) {
				in.Keys = []ed25519.PublicKey{pub(other), pub(signer)}
			},
			nil,
		},
		{
			"no channel or version constraint accepts what the document declares",
			func(in *ReleaseManifestInput) { in.Channel, in.Version = "", "" },
			nil,
		},
		{
			"an unknown key is refused",
			func(in *ReleaseManifestInput) { in.Keys = []ed25519.PublicKey{pub(other)} },
			ErrSignatureInvalid,
		},
		{
			"an EMPTY key set is refused, not waved through",
			func(in *ReleaseManifestInput) { in.Keys = nil },
			ErrNoVendorKey,
		},
		{
			"an empty key set with an explicit opt-out is allowed",
			func(in *ReleaseManifestInput) { in.Keys, in.AllowUnpinnedKey = nil, true },
			nil,
		},
		{
			"a tampered artifact hash breaks the signature",
			func(in *ReleaseManifestInput) {
				m := releaseManifest()
				env := signRelease(t, m, signer)
				m.Artifacts[0].SHA256 = strings.Repeat("9", 64)
				body, _ := CanonicalJSON(m)
				in.EnvelopeBytes = reseat(t, env, body, HashBytes(body))
			},
			ErrSignatureInvalid,
		},
		{
			"a tampered manifest whose hash was updated too still breaks the signature",
			func(in *ReleaseManifestInput) {
				m := releaseManifest()
				m.Artifacts[0].SHA256 = strings.Repeat("9", 64)
				in.EnvelopeBytes = signRelease(t, m, other)
			},
			ErrSignatureInvalid,
		},
		{
			"a manifest hash that does not cover the bytes is refused",
			func(in *ReleaseManifestInput) {
				m := releaseManifest()
				env := signRelease(t, m, signer)
				body, _ := CanonicalJSON(m)
				in.EnvelopeBytes = reseat(t, env, body, strings.Repeat("a", 64))
			},
			ErrManifestHashMismatch,
		},
		{
			"an expired manifest is refused",
			func(in *ReleaseManifestInput) { in.Now = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC) },
			ErrManifestExpired,
		},
		{
			"a manifest for another version is refused",
			func(in *ReleaseManifestInput) { in.Version = "v1.34.0" },
			ErrManifestMismatch,
		},
		{
			"a manifest for another channel is refused",
			func(in *ReleaseManifestInput) { in.Channel = ChannelEdge },
			ErrManifestMismatch,
		},
		{
			"a future schema is ignored rather than treated as corrupt",
			func(in *ReleaseManifestInput) {
				m := releaseManifest()
				m.Schema = "sbo.update-manifest.v2"
				in.EnvelopeBytes = signRelease(t, m, signer)
			},
			ErrUnknownSchema,
		},
		{
			"a structurally invalid manifest is refused even when correctly signed",
			func(in *ReleaseManifestInput) {
				m := releaseManifest()
				m.Artifacts[0].UpstreamSigType = "cosign-bundle"
				in.EnvelopeBytes = signRelease(t, m, signer)
			},
			ErrInvalidManifest,
		},
		{
			"an empty envelope is refused",
			func(in *ReleaseManifestInput) { in.EnvelopeBytes = nil },
			ErrEnvelopeDecode,
		},
		{
			"a trailing second document is refused",
			func(in *ReleaseManifestInput) {
				in.EnvelopeBytes = append(in.EnvelopeBytes, []byte("{}")...)
			},
			ErrEnvelopeDecode,
		},
		{
			"an oversized envelope is refused before it is parsed",
			func(in *ReleaseManifestInput) {
				in.EnvelopeBytes = make([]byte, MaxEnvelopeBytes+1)
			},
			ErrEnvelopeDecode,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := base()
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			m, err := VerifyReleaseManifest(in)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("VerifyReleaseManifest: %v", err)
				}
				if m.Version != "v1.33.0" || len(m.Artifacts) != 2 {
					t.Fatalf("verified manifest = %+v, want the two-artifact v1.33.0 release", m)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// reseat rewrites an envelope's manifest bytes and hash while KEEPING the
// original signature, which is the mirror-tampering shape: an attacker who
// controls the served document but not the key.
func reseat(t *testing.T, envelope, body []byte, hash string) []byte {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(envelope, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	env.ManifestB64 = base64.StdEncoding.EncodeToString(body)
	env.ManifestHash = hash
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return raw
}

// TestArtifactByFilename pins the lookup the mirror uses to answer "is this
// file one the signed manifest actually names". A file the manifest does not
// name has no signed claim behind it, which is the whole reason the lookup is
// by filename rather than by platform.
func TestArtifactByFilename(t *testing.T) {
	t.Parallel()
	m := releaseManifest()
	got, ok := ArtifactByFilename(m, "observer-v1.33.0-linux-x64.tar.gz")
	if !ok || got.OS != "linux" {
		t.Fatalf("ArtifactByFilename(linux) = %+v, %t", got, ok)
	}
	for _, miss := range []string{"", "observer-v1.33.0-linux-arm64.tar.gz", "SHA256SUMS", "OBSERVER-V1.33.0-LINUX-X64.TAR.GZ"} {
		if _, ok := ArtifactByFilename(m, miss); ok {
			t.Errorf("ArtifactByFilename(%q) matched, but the manifest does not name it", miss)
		}
	}
}
