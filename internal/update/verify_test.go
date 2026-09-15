package update

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// goldenPubKey is the corpus key's public half, base64 — what a node
// would have pinned.
func goldenPubKey(t *testing.T) string {
	t.Helper()
	_, key := goldenKey()
	return key.PublicKeyB64
}

// goldenKeyID is the corpus key's id.
func goldenKeyID(t *testing.T) string {
	t.Helper()
	_, key := goldenKey()
	return key.KeyID
}

// mutateEnvelope loads a committed envelope and applies f to the
// decoded form, returning re-encoded bytes. Used for the rules whose
// input is an envelope-level defect rather than a manifest.
func mutateEnvelope(t *testing.T, name string, f func(*Envelope)) []byte {
	t.Helper()
	var env Envelope
	if err := json.Unmarshal(loadEnvelope(t, name), &env); err != nil {
		t.Fatalf("decode envelope %s: %v", name, err)
	}
	f(&env)
	b, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("re-encode envelope: %v", err)
	}
	return b
}

// TestVerifyRules is the §3.2 table walked one row at a time: every
// numbered rule gets at least one PASS-through and one refusal case, so
// a rule that stops firing (or starts firing early) fails here.
//
// The corpus is loaded from committed bytes on purpose — a signature is
// over bytes, and a table built in memory would only ever agree with
// itself (see golden_test.go).
func TestVerifyRules(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	pub := goldenPubKey(t)
	keyID := goldenKeyID(t)

	base := func() VerifyInput {
		return VerifyInput{
			EnvelopeBytes:               loadEnvelope(t, "valid"),
			PinnedKeyID:                 keyID,
			PinnedPublicKey:             pub,
			InstalledVersion:            "v1.32.0",
			LastAcceptedManifestVersion: 16,
			Now:                         now,
			GOOS:                        "linux",
			GOARCH:                      "amd64",
		}
	}

	cases := []struct {
		name string
		// mutate adjusts the base input for this row.
		mutate func(*VerifyInput)
		// wantErr is the sentinel expected, nil for the happy paths.
		wantErr error
		// wantRule is the rule name the result must name.
		wantRule string
		// wantState / wantReason are the reported posture.
		wantState  State
		wantReason Reason
	}{
		// ---- happy paths -------------------------------------------------
		{
			name:     "1-9 valid linux manifest verifies end to end",
			mutate:   func(*VerifyInput) {},
			wantRule: "verified", wantState: StateAvailable,
		},
		{
			name: "9 the same manifest selects the win32 zip artifact",
			mutate: func(in *VerifyInput) {
				in.GOOS, in.GOARCH = "windows", "amd64"
			}, wantRule: "verified", wantState: StateAvailable,
		},
		{
			name: "9 release-asset platform spellings normalize (win32/x64)",
			mutate: func(in *VerifyInput) {
				in.GOOS, in.GOARCH = "win32", "x64"
			}, wantRule: "verified", wantState: StateAvailable,
		},
		{
			name: "3 a first pin (no pinned key id) is TOFU-accepted",
			mutate: func(in *VerifyInput) {
				in.PinnedKeyID = ""
			}, wantRule: "verified", wantState: StateAvailable,
		},

		// ---- rule 1: envelope --------------------------------------------
		{
			name: "1 an empty envelope is refused",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = nil
				in.Envelope = Envelope{}
			},
			wantErr: ErrEnvelopeDecode, wantRule: "1-envelope", wantState: StateIdle,
		},
		{
			name: "1 a trailing second JSON value is refused",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = append(loadEnvelope(t, "valid"), []byte("{\"manifest\":\"\"}")...)
			},
			wantErr: ErrEnvelopeDecode, wantRule: "1-envelope", wantState: StateIdle,
		},
		{
			name: "1 an envelope beyond the size cap is refused before parsing",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = []byte("{\"manifest\":\"" + strings.Repeat("A", MaxEnvelopeBytes) + "\"}")
			},
			wantErr: ErrEnvelopeDecode, wantRule: "1-envelope", wantState: StateIdle,
		},
		{
			name: "2 a non-base64 manifest field is refused",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = mutateEnvelope(t, "valid", func(e *Envelope) { e.ManifestB64 = "not base64 !!" })
			},
			wantErr: ErrEnvelopeDecode, wantRule: "2-manifest-hash", wantState: StateIdle,
		},

		// ---- rule 2: manifest hash ---------------------------------------
		{
			name: "2 a declared hash that does not match the bytes is refused",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "wrong-hash")
			},
			wantErr: ErrManifestHashMismatch, wantRule: "2-manifest-hash", wantState: StateIdle,
		},

		// ---- rule 3: key agreement ---------------------------------------
		{
			name: "3 a key id that disagrees with the pinned one is refused, never TOFU-accepted",
			mutate: func(in *VerifyInput) {
				in.PinnedKeyID = "a different org key"
			},
			wantErr: ErrKeyDisagreement, wantRule: "3-key-agreement", wantState: StateIdle,
		},

		// ---- rule 4: signature -------------------------------------------
		{
			name: "4 an announcement-rail signature cannot be replayed as a manifest",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "wrong-domain-tag")
			},
			wantErr: ErrSignatureInvalid, wantRule: "4-signature", wantState: StateIdle,
		},
		{
			name: "4 a signature checked against the wrong key is refused",
			mutate: func(in *VerifyInput) {
				other := make([]byte, 32)
				other[0] = 9
				in.PinnedPublicKey = base64.StdEncoding.EncodeToString(other)
			},
			wantErr: ErrSignatureInvalid, wantRule: "4-signature", wantState: StateIdle,
		},
		{
			name: "4 a malformed pinned key is refused (never verified against the offered one)",
			mutate: func(in *VerifyInput) {
				in.PinnedPublicKey = "%%%"
			},
			wantErr: ErrSignatureInvalid, wantRule: "4-signature", wantState: StateIdle,
		},
		{
			name: "4 a truncated signature is refused",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = mutateEnvelope(t, "valid", func(e *Envelope) {
					e.Signature = base64.StdEncoding.EncodeToString([]byte("short"))
				})
			},
			wantErr: ErrSignatureInvalid, wantRule: "4-signature", wantState: StateIdle,
		},

		// ---- rule 5: schema ------------------------------------------------
		{
			name: "5 an unknown schema is IGNORED (fail-open), not reported as an error state",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "unknown-schema")
				in.LastAcceptedManifestVersion = 0
			},
			wantErr: ErrUnknownSchema, wantRule: "5-schema", wantState: StateIdle,
		},

		// ---- rule 6: replay ------------------------------------------------
		{
			name: "6 a manifest_version at or below the last accepted one is refused",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "replayed-lower-version")
			},
			wantErr: ErrManifestReplay, wantRule: "6-replay", wantState: StateIdle,
		},
		{
			name: "6 replaying the SAME manifest_version is refused too",
			mutate: func(in *VerifyInput) {
				in.LastAcceptedManifestVersion = 17
			},
			wantErr: ErrManifestReplay, wantRule: "6-replay", wantState: StateIdle,
		},

		// ---- rule 7: downgrade ---------------------------------------------
		{
			name: "7 a lower version without allow_downgrade_to is blocked",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "downgrade")
			},
			wantErr: ErrDowngradeRefused, wantRule: "7-downgrade",
			wantState: StateBlocked, wantReason: ReasonDowngrade,
		},
		{
			name: "7 node consent alone does not permit a downgrade the manifest did not authorise",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "downgrade")
				in.AllowDowngrade = true
			},
			wantErr: ErrDowngradeRefused, wantRule: "7-downgrade",
			wantState: StateBlocked, wantReason: ReasonDowngrade,
		},
		{
			name: "7 an equal installed version is not an update",
			mutate: func(in *VerifyInput) {
				in.InstalledVersion = "v1.33.0"
			},
			wantErr: ErrDowngradeRefused, wantRule: "7-downgrade",
			wantState: StateBlocked, wantReason: ReasonDowngrade,
		},
		{
			name: "7 a dev build is never told it is behind and is never downgraded",
			mutate: func(in *VerifyInput) {
				in.InstalledVersion = "dev"
			},
			wantErr: ErrDowngradeRefused, wantRule: "7-downgrade", wantState: StateIdle,
		},
		{
			name: "7 a pre-release build is left alone",
			mutate: func(in *VerifyInput) {
				in.InstalledVersion = "v1.33.0-rc.1"
			},
			wantErr: ErrDowngradeRefused, wantRule: "7-downgrade", wantState: StateIdle,
		},

		// ---- rule 8: freshness ---------------------------------------------
		{
			name: "8 an expired manifest reports stale_manifest",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "expired")
				in.LastAcceptedManifestVersion = 0
			},
			wantErr: ErrManifestExpired, wantRule: "8-freshness", wantState: StateStaleManifest,
		},
		{
			name: "8 an installed version below min_from_version is a required stop",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "required-stop")
				in.InstalledVersion = "v1.29.0"
			},
			wantErr: ErrRequiredStop, wantRule: "8-freshness",
			wantState: StateBlocked, wantReason: ReasonRequiredStop,
		},
		{
			name: "8 an installed version exactly at min_from_version passes",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "required-stop")
				in.InstalledVersion = "v1.30.0"
			},
			wantRule: "verified", wantState: StateAvailable,
		},

		// ---- rule 9: artifact ----------------------------------------------
		{
			name: "9 a platform the release did not build is blocked, not silently idle",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "no-artifact-for-platform")
				in.LastAcceptedManifestVersion = 0
			},
			wantErr: ErrNoArtifact, wantRule: "9-artifact",
			wantState: StateBlocked, wantReason: ReasonNoArtifact,
		},
		{
			name: "9 an artifact with an empty upstream_sig is blocked{unsigned_artifact} (H0 fail-closed)",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "empty-upstream-sig")
				in.LastAcceptedManifestVersion = 0
			},
			wantErr: ErrUnsignedArtifact, wantRule: "9-artifact",
			wantState: StateBlocked, wantReason: ReasonUnsignedArtifact,
		},
		{
			name: "9 the same unsigned manifest still applies on a platform whose artifact IS signed",
			mutate: func(in *VerifyInput) {
				in.EnvelopeBytes = loadEnvelope(t, "empty-upstream-sig")
				in.LastAcceptedManifestVersion = 0
				in.GOOS, in.GOARCH = "windows", "amd64"
			},
			wantRule: "verified", wantState: StateAvailable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			res, err := Verify(in)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify: unexpected error: %v", err)
				}
				if !res.UpdateAvailable {
					t.Errorf("UpdateAvailable = false, want true")
				}
			} else {
				if err == nil {
					t.Fatalf("Verify: expected %v, got nil", tc.wantErr)
				}
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Verify: error = %v, want %v", err, tc.wantErr)
				}
				if res.UpdateAvailable {
					t.Errorf("UpdateAvailable = true on a failed verification")
				}
			}
			if res.Rule != tc.wantRule {
				t.Errorf("Rule = %q, want %q", res.Rule, tc.wantRule)
			}
			if res.State != tc.wantState {
				t.Errorf("State = %q, want %q", res.State, tc.wantState)
			}
			if res.Reason != tc.wantReason {
				t.Errorf("Reason = %q, want %q", res.Reason, tc.wantReason)
			}
		})
	}
}

// TestVerifyRuleOrderIsTheSpecification pins the table itself: the nine
// rules of §3.2 in order. A reordering is a security change (content
// judged before authorship), so it must break a test, not a review.
func TestVerifyRuleOrderIsTheSpecification(t *testing.T) {
	want := []string{
		"1-envelope", "2-manifest-hash", "3-key-agreement", "4-signature",
		"5-schema", "6-replay", "7-downgrade", "8-freshness", "9-artifact",
	}
	if len(verifyRules) != len(want) {
		t.Fatalf("verifyRules has %d rows, want %d", len(verifyRules), len(want))
	}
	for i, w := range want {
		if verifyRules[i].name != w {
			t.Errorf("rule %d = %q, want %q", i, verifyRules[i].name, w)
		}
	}
}

// TestVerifySelectsTheRightArtifact checks the platform selection the
// happy path silently relies on.
func TestVerifySelectsTheRightArtifact(t *testing.T) {
	in := VerifyInput{
		EnvelopeBytes:    loadEnvelope(t, "valid"),
		PinnedKeyID:      goldenKeyID(t),
		PinnedPublicKey:  goldenPubKey(t),
		InstalledVersion: "v1.32.0",
		Now:              time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
		GOOS:             "windows", GOARCH: "amd64",
	}
	res, err := Verify(in)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Artifact.ArchiveType != ArchiveZip || res.Artifact.Member != "observer.exe" {
		t.Fatalf("selected artifact = %+v, want the win32 zip", res.Artifact)
	}
	if res.Manifest.Version != "v1.33.0" {
		t.Errorf("manifest version = %q", res.Manifest.Version)
	}
}

// TestManifestSigningMessageIsDomainAndVersionBound proves the two
// replay properties the message layout exists for.
func TestManifestSigningMessageIsDomainAndVersionBound(t *testing.T) {
	hash := HashBytes([]byte("body"))
	a := ManifestSigningMessage(17, hash)
	if string(a) == string(ManifestSigningMessage(18, hash)) {
		t.Error("signing message does not bind manifest_version")
	}
	if string(a) == string(announcementSigningMessage(17, hash)) {
		t.Error("signing message does not separate this rail from the announcement rail")
	}
	if string(a) != string(ManifestSigningMessage(17, hash)) {
		t.Error("signing message is not deterministic")
	}
}
