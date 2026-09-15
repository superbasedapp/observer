package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update"
)

const fixtureVersion = "v9.9.9"

// tarMember is one entry the fixture tarball carries.
type tarMember struct {
	name    string
	kind    byte // tar.TypeReg / TypeDir / TypeSymlink
	link    string
	content string
}

// writeTarGz builds a .tar.gz from an explicit member list, so a test
// can reproduce BOTH the shape the release job produces and the shapes
// it must never produce (a "./" root entry, an undeclared file).
func writeTarGz(t *testing.T, path string, members []tarMember) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		h := &tar.Header{Name: m.name, Typeflag: m.kind, Mode: 0o755, Linkname: m.link}
		if m.kind == tar.TypeReg {
			h.Size = int64(len(m.content))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatalf("tar header %s: %v", m.name, err)
		}
		if m.kind == tar.TypeReg {
			if _, err := tw.Write([]byte(m.content)); err != nil {
				t.Fatalf("tar body %s: %v", m.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeZip builds a .zip with the two members the win32 release carries.
func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeSums writes a SHA256SUMS covering every archive in dir.
func writeSums(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".tar.gz") && !strings.HasSuffix(n, ".zip") {
			continue
		}
		body, rerr := os.ReadFile(filepath.Join(dir, n))
		if rerr != nil {
			t.Fatal(rerr)
		}
		sum := sha256.Sum256(body)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	if err := os.WriteFile(filepath.Join(dir, SumsFileName), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// testKey returns a deterministic-per-run Ed25519 keypair.
func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// fixtureRelease builds a release-assets directory shaped exactly like
// the one npm-release.yml produces: the linux tarball with its symlink
// alias AND the antigravity bridge, the win32 zip with its byte-copy
// alias, SHA256SUMS, and a `.sig` beside each archive.
func fixtureRelease(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	writeTarGz(t, filepath.Join(dir, "observer-"+fixtureVersion+"-linux-x64.tar.gz"), []tarMember{
		{name: "observer", kind: tar.TypeReg, content: "the linux daemon"},
		{name: "superbased", kind: tar.TypeSymlink, link: "observer"},
		{name: CompanionBridge, kind: tar.TypeReg, content: "the wsl2 bridge"},
	})
	writeZip(t, filepath.Join(dir, "observer-"+fixtureVersion+"-win32-x64.zip"), map[string]string{
		"observer.exe":   "the windows daemon",
		"superbased.exe": "the windows daemon",
	})
	// An org-server archive rides in the same directory on a real
	// release and must NOT end up in the agent manifest.
	writeTarGz(t, filepath.Join(dir, "observer-org-"+fixtureVersion+"-linux-x64.tar.gz"), []tarMember{
		{name: "observer-org", kind: tar.TypeReg, content: "the org server"},
	})
	writeSums(t, dir)
	for _, n := range []string{
		"observer-" + fixtureVersion + "-linux-x64.tar.gz",
		"observer-" + fixtureVersion + "-win32-x64.zip",
	} {
		if _, err := signArchive(filepath.Join(dir, n), priv); err != nil {
			t.Fatalf("signArchive %s: %v", n, err)
		}
	}
	return dir
}

// buildFixtureManifest is the happy path every test starts from.
func buildFixtureManifest(t *testing.T, dir string, priv ed25519.PrivateKey) (update.Envelope, update.Manifest) {
	t.Helper()
	env, m, err := buildManifest(BuildOptions{
		Dir: dir, Version: fixtureVersion, Channel: "stable",
		ReleasedAt: time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC),
		Key:        priv,
	})
	if err != nil {
		t.Fatalf("buildManifest: %v", err)
	}
	return env, m
}

// TestManifestVerifiesWithUpdateVerify is the W6 acceptance test: the
// document this producer emits passes the NODE's nine ordered rules,
// selects a real artifact for a real platform, and every artifact it
// names carries a non-empty vendor signature (rule 9's fail-closed
// clause is satisfied by construction, not by a comment).
func TestManifestVerifiesWithUpdateVerify(t *testing.T) {
	pub, priv := testKey(t)
	dir := fixtureRelease(t, priv)
	env, m := buildFixtureManifest(t, dir, priv)

	if len(m.Artifacts) != 2 {
		t.Fatalf("manifest names %d artifacts, want 2 (the org-server archive must be excluded)", len(m.Artifacts))
	}
	for _, a := range m.Artifacts {
		if a.UpstreamSig == "" {
			t.Errorf("%s carries no upstream_sig — a node would refuse it as blocked{unsigned_artifact}", a.Filename)
		}
		if a.UpstreamSigType != update.SigTypeEd25519 {
			t.Errorf("%s upstream_sig_type = %q, want %q", a.Filename, a.UpstreamSigType, update.SigTypeEd25519)
		}
		if !update.KnownSigType(a.UpstreamSigType) {
			t.Errorf("%s upstream_sig_type %q is outside the manifest vocabulary", a.Filename, a.UpstreamSigType)
		}
	}

	res, err := update.Verify(update.VerifyInput{
		Envelope:         env,
		PinnedPublicKey:  base64.StdEncoding.EncodeToString(pub),
		InstalledVersion: "v1.0.0",
		Now:              time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC),
		GOOS:             "linux", GOARCH: "amd64",
	})
	if err != nil {
		t.Fatalf("update.Verify rejected the manifest at rule %s: %v", res.Rule, err)
	}
	if !res.UpdateAvailable {
		t.Error("UpdateAvailable = false")
	}
	if res.Artifact.Filename != "observer-"+fixtureVersion+"-linux-x64.tar.gz" {
		t.Errorf("selected artifact = %q", res.Artifact.Filename)
	}
	if res.Artifact.SizeBytes <= 0 || len(res.Artifact.SHA256) != 64 || len(res.Artifact.MemberSHA256) != 64 {
		t.Errorf("artifact row is incomplete: %+v", res.Artifact)
	}
}

// TestArtifactSignatureVerifiesOverArchiveBytes reproduces the NODE's
// vendor check (cmd/observer/update_vendorsig.go) against the manifest
// this producer emitted, and then MUTATES the signature file to prove
// the check is doing work: a flipped byte must fail, and the failure
// must come from the crypto rather than from a missing field.
func TestArtifactSignatureVerifiesOverArchiveBytes(t *testing.T) {
	pub, priv := testKey(t)
	dir := fixtureRelease(t, priv)
	_, m := buildFixtureManifest(t, dir, priv)

	for _, a := range m.Artifacts {
		body, err := os.ReadFile(filepath.Join(dir, a.Filename))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := base64.StdEncoding.DecodeString(a.UpstreamSig)
		if err != nil {
			t.Fatalf("%s: upstream_sig is not base64: %v", a.Filename, err)
		}
		if !ed25519.Verify(pub, body, sig) {
			t.Fatalf("%s: the recorded vendor signature does not verify over the archive bytes", a.Filename)
		}
		// Mutation: flip one bit of the signature.
		sig[0] ^= 0x01
		if ed25519.Verify(pub, body, sig) {
			t.Fatalf("%s: a tampered signature still verified", a.Filename)
		}
		// Mutation: keep the signature, change the archive.
		if ed25519.Verify(pub, append(body, 'x'), sig) {
			t.Fatalf("%s: the signature verified over different bytes", a.Filename)
		}
	}
}

// TestTamperedSigFileIsCarriedIntoTheManifest pins the honest division
// of labour between the two gates. Rule 9 only asks whether a signature
// is PRESENT, so a tampered `.sig` still produces a structurally valid,
// verifiable manifest — and is then refused at apply time by the byte
// check. Asserting both halves keeps anyone from "fixing" rule 9 into a
// crypto check it cannot perform (it has no archive bytes).
func TestTamperedSigFileIsCarriedIntoTheManifest(t *testing.T) {
	pub, priv := testKey(t)
	dir := fixtureRelease(t, priv)
	name := "observer-" + fixtureVersion + "-linux-x64.tar.gz"
	sigPath := filepath.Join(dir, name+SigSuffix)
	raw, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[10] ^= 0xff
	if err := os.WriteFile(sigPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	env, m := buildFixtureManifest(t, dir, priv)
	if _, err := update.Verify(update.VerifyInput{
		Envelope:         env,
		PinnedPublicKey:  base64.StdEncoding.EncodeToString(pub),
		InstalledVersion: "v1.0.0",
		Now:              time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC),
		GOOS:             "linux", GOARCH: "amd64",
	}); err != nil {
		t.Fatalf("a tampered artifact signature must still pass the DOCUMENT rules: %v", err)
	}
	a, ok := update.SelectArtifact(m, update.KindAgent, "linux", "amd64")
	if !ok {
		t.Fatal("no linux/amd64 artifact")
	}
	body, err := os.ReadFile(filepath.Join(dir, a.Filename))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(a.UpstreamSig)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub, body, sig) {
		t.Fatal("the tampered signature verified at the apply-time gate")
	}
}

// TestManifestSignedByAnotherKeyIsRejected is the mutation proof for
// the manifest signature: the same document, verified against the key
// this build actually compiles in (VendorPublicKeyV1), must fail at
// rule 4. If this ever passes, the pinned-key check has stopped
// checking the pin.
func TestManifestSignedByAnotherKeyIsRejected(t *testing.T) {
	_, priv := testKey(t)
	dir := fixtureRelease(t, priv)
	env, _ := buildFixtureManifest(t, dir, priv)

	res, err := update.Verify(update.VerifyInput{
		Envelope:         env,
		PinnedPublicKey:  update.VendorPublicKeyV1,
		InstalledVersion: "v1.0.0",
		Now:              time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC),
		GOOS:             "linux", GOARCH: "amd64",
	})
	if err == nil {
		t.Fatal("a manifest signed by a different key verified against the compiled-in key")
	}
	if !errors.Is(err, update.ErrSignatureInvalid) {
		t.Errorf("error = %v (rule %s), want ErrSignatureInvalid", err, res.Rule)
	}
}

// TestManifestBodyTamperIsRejected mutates the signed manifest bytes
// inside the envelope. The hash check (rule 2) must catch it before the
// signature is even consulted.
func TestManifestBodyTamperIsRejected(t *testing.T) {
	pub, priv := testKey(t)
	dir := fixtureRelease(t, priv)
	env, _ := buildFixtureManifest(t, dir, priv)

	body, err := base64.StdEncoding.DecodeString(env.ManifestB64)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(body, []byte(`"channel":"stable"`), []byte(`"channel":"edge"  `), 1)
	if bytes.Equal(tampered, body) {
		t.Fatal("fixture no longer contains the field this test mutates")
	}
	env.ManifestB64 = base64.StdEncoding.EncodeToString(tampered)

	if _, err := update.Verify(update.VerifyInput{
		Envelope:         env,
		PinnedPublicKey:  base64.StdEncoding.EncodeToString(pub),
		InstalledVersion: "v1.0.0",
		Now:              time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC),
		GOOS:             "linux", GOARCH: "amd64",
	}); !errors.Is(err, update.ErrManifestHashMismatch) {
		t.Fatalf("error = %v, want ErrManifestHashMismatch", err)
	}
}

// TestBuildManifestRefusals walks the shapes a release directory must
// never produce. Each is a REFUSAL at build time rather than a manifest
// the fleet discovers it cannot apply.
func TestBuildManifestRefusals(t *testing.T) {
	linux := "observer-" + fixtureVersion + "-linux-x64.tar.gz"
	cases := []struct {
		name    string
		mutate  func(t *testing.T, dir string)
		wantSub string
	}{
		{
			// `tar -C dir .` records a "./" root entry, which
			// update.SelectMember refuses as an empty entry name — so an
			// archive built that way is un-appliable however well signed.
			name: "root dot entry",
			mutate: func(t *testing.T, dir string) {
				writeTarGz(t, filepath.Join(dir, linux), []tarMember{
					{name: "./", kind: tar.TypeDir},
					{name: "./observer", kind: tar.TypeReg, content: "the linux daemon"},
					{name: "./superbased", kind: tar.TypeSymlink, link: "observer"},
				})
			},
			wantSub: "explicit member names",
		},
		{
			name: "undeclared entry",
			mutate: func(t *testing.T, dir string) {
				writeTarGz(t, filepath.Join(dir, linux), []tarMember{
					{name: "observer", kind: tar.TypeReg, content: "the linux daemon"},
					{name: "superbased", kind: tar.TypeSymlink, link: "observer"},
					{name: "surprise.sh", kind: tar.TypeReg, content: "curl | sh"},
				})
			},
			wantSub: "undeclared entry",
		},
		{
			name: "missing member",
			mutate: func(t *testing.T, dir string) {
				writeTarGz(t, filepath.Join(dir, linux), []tarMember{
					{name: "superbased", kind: tar.TypeReg, content: "not the daemon"},
				})
			},
			wantSub: "archive does not contain",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, priv := testKey(t)
			dir := fixtureRelease(t, priv)
			tc.mutate(t, dir)
			// Re-checksum and re-sign so the failure under test is the
			// only one in play.
			writeSums(t, dir)
			if _, err := signArchive(filepath.Join(dir, linux), priv); err != nil {
				t.Fatal(err)
			}
			_, _, err := buildManifest(BuildOptions{
				Dir: dir, Version: fixtureVersion, Channel: "stable", Key: priv,
			})
			if err == nil {
				t.Fatalf("buildManifest accepted a %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantSub)
			}
		})
	}
}

// TestBuildManifestRefusesUnsignedAndMismatched covers the two failures
// that come from the directory rather than from an archive's insides.
func TestBuildManifestRefusesUnsignedAndMismatched(t *testing.T) {
	linux := "observer-" + fixtureVersion + "-linux-x64.tar.gz"

	t.Run("no signature", func(t *testing.T) {
		_, priv := testKey(t)
		dir := fixtureRelease(t, priv)
		if err := os.Remove(filepath.Join(dir, linux+SigSuffix)); err != nil {
			t.Fatal(err)
		}
		if _, _, err := buildManifest(BuildOptions{
			Dir: dir, Version: fixtureVersion, Channel: "stable", Key: priv,
		}); err == nil {
			t.Fatal("buildManifest accepted an unsigned archive")
		}
	})

	t.Run("sums mismatch", func(t *testing.T) {
		_, priv := testKey(t)
		dir := fixtureRelease(t, priv)
		sums, err := os.ReadFile(filepath.Join(dir, SumsFileName))
		if err != nil {
			t.Fatal(err)
		}
		broken := append([]byte("0000000000000000000000000000000000000000000000000000000000000000  "+linux+"\n"),
			bytes.Split(sums, []byte("\n"))[1]...)
		if err := os.WriteFile(filepath.Join(dir, SumsFileName), broken, 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, err = buildManifest(BuildOptions{
			Dir: dir, Version: fixtureVersion, Channel: "stable", Key: priv,
		})
		if err == nil || !strings.Contains(err.Error(), SumsFileName) {
			t.Fatalf("error = %v, want a %s disagreement", err, SumsFileName)
		}
	})

	t.Run("unknown channel", func(t *testing.T) {
		_, priv := testKey(t)
		dir := fixtureRelease(t, priv)
		if _, _, err := buildManifest(BuildOptions{
			Dir: dir, Version: fixtureVersion, Channel: "nightly", Key: priv,
		}); err == nil {
			t.Fatal("buildManifest accepted an unknown channel")
		}
	})
}

// TestParsePrivateKey is the key-loading decision table. The trailing
// newline case is the one that matters operationally: a secret pasted
// into the GitHub UI usually carries one, and refusing it would break a
// release for a reason nobody would guess.
func TestParsePrivateKey(t *testing.T) {
	_, priv := testKey(t)
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	full := base64.StdEncoding.EncodeToString(priv)

	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"seed", seed, false},
		{"seed with newline", seed + "\n", false},
		{"seed with spaces", "  " + seed + "  ", false},
		{"full private key", full, false},
		{"empty", "", true},
		{"not base64", "!!!!", true},
		{"wrong length", base64.StdEncoding.EncodeToString([]byte("short")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parsePrivateKey(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePrivateKey: %v", err)
			}
			if !bytes.Equal(got, priv) {
				t.Error("parsed key does not match the original")
			}
		})
	}
}

// TestKeyIDMatchesTheCompiledInKey proves the id this tool stamps into
// a manifest is the id the agent's own key material produces, so an
// operator comparing key_id against the README beside the private key
// is comparing like with like.
func TestKeyIDMatchesTheCompiledInKey(t *testing.T) {
	pub, err := update.ParseVendorKey(update.VendorPublicKeyV1)
	if err != nil {
		t.Fatalf("ParseVendorKey: %v", err)
	}
	if got, want := keyID(pub), "7595a73e343e517a07c8d944ba75be91"; got != want {
		t.Errorf("keyID = %s, want %s", got, want)
	}
}

// --- review fix round 2 -----------------------------------------------------

// TestSigningRefusesAKeyTheFleetDoesNotAccept is M5.
//
// A node verifies an artifact against a key compiled into the agent, so
// signing with anything else produces a release that is green in CI, green at
// the org's import, and refused by every node at the customer's first ring.
// The producer is where that must fail, and it must fail LOUDLY rather than
// silently stamping a key_id nobody accepts.
func TestSigningRefusesAKeyTheFleetDoesNotAccept(t *testing.T) {
	fleetPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restore := acceptedVendorKeys
	acceptedVendorKeys = func() []ed25519.PublicKey { return []ed25519.PublicKey{fleetPub} }
	t.Cleanup(func() { acceptedVendorKeys = restore })

	if _, err := checkKeyIsPinned(wrongPriv, false); err == nil {
		t.Fatal("a key the fleet does not accept was allowed to sign a release")
	} else if !strings.Contains(err.Error(), "not among the vendor public keys") {
		t.Errorf("refusal does not say what is wrong: %v", err)
	}

	// -allow-unpinned-key is the deliberate rotation step: permitted, and
	// loud about what it permitted.
	warn, err := checkKeyIsPinned(wrongPriv, true)
	if err != nil {
		t.Fatalf("-allow-unpinned-key must permit the rotation step: %v", err)
	}
	if !strings.Contains(warn, "NOT among") {
		t.Errorf("the rotation step signed silently: %q", warn)
	}

	// The matching key signs with no warning at all.
	fleetPriv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	acceptedVendorKeys = func() []ed25519.PublicKey {
		return []ed25519.PublicKey{fleetPriv.Public().(ed25519.PublicKey)}
	}
	if warn, err := checkKeyIsPinned(fleetPriv, false); err != nil || warn != "" {
		t.Errorf("the accepted key was not recognised: warn=%q err=%v", warn, err)
	}
}

// TestSigningWithNoCompiledKeyWarnsRatherThanRefuses: this tree carries no
// vendor key yet, and a guard that made the tool unusable in exactly the state
// it exists to fix would be worse than the bug.
func TestSigningWithNoCompiledKeyWarnsRatherThanRefuses(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	restore := acceptedVendorKeys
	acceptedVendorKeys = func() []ed25519.PublicKey { return nil }
	t.Cleanup(func() { acceptedVendorKeys = restore })
	warn, err := checkKeyIsPinned(priv, false)
	if err != nil {
		t.Fatalf("an empty accepted set must not refuse: %v", err)
	}
	if !strings.Contains(warn, "NO vendor public key") {
		t.Errorf("the empty-key-set state was not stated: %q", warn)
	}
}

// TestKeygenRefusesToOverwriteAnExistingKey pins L8's O_EXCL: the refusal and
// the write are one operation, not a Stat something else can win.
func TestKeygenRefusesToOverwriteAnExistingKey(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := generateKeypair(dir); err != nil {
		t.Fatalf("first keygen: %v", err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "vendor-signing-key.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := generateKeypair(dir); err == nil {
		t.Fatal("a second keygen overwrote a live signing key")
	}
	after, err := os.ReadFile(filepath.Join(dir, "vendor-signing-key.key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("the existing key was modified by a refused keygen")
	}
}

// TestSchemaVersionMatchesTheMigrationsOnDisk pins the number the release
// pipeline stamps into every manifest.
//
// A manifest with no schema_version declares "unknown", and a node treats
// unknown as "may advance the schema" — so it VACUUM INTOs its whole database
// before every apply, which on a 14 GB node is minutes of disk it did not need
// to spend. The pipeline could not declare the number because nothing computed
// it; this verb does, from the same embedded migrations the agent runs, so the
// declaration cannot drift from the code.
//
// The assertion deliberately recomputes from the migrations DIRECTORY rather
// than from the embed, so a change to the embed pattern that silently dropped
// a migration fails here instead of shipping a number that is too low.
func TestSchemaVersionMatchesTheMigrationsOnDisk(t *testing.T) {
	got, err := agentSchemaVersion()
	if err != nil {
		t.Fatalf("agentSchemaVersion: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join("..", "..", "internal", "db", "migrations"))
	if err != nil {
		t.Fatalf("read the migrations directory: %v", err)
	}
	want := 0
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		n, cerr := strconv.Atoi(strings.SplitN(name, "_", 2)[0])
		if cerr != nil {
			t.Fatalf("unparseable migration %q", name)
		}
		if n > want {
			want = n
		}
	}
	if want == 0 {
		t.Fatal("no migrations found on disk — the pin would pass vacuously")
	}
	if got != want {
		t.Fatalf("agentSchemaVersion() = %d, but the highest migration on disk is %d", got, want)
	}
}

// TestSchemaVersionVerbPrintsOnlyTheNumber pins the CONTRACT the workflow
// depends on: `SCHEMA_VERSION=$(go run ./scripts/vendorsign schema-version)`
// is fed straight into `-schema-version`, so one stray word of prose would
// make the manifest step fail at flag parsing.
func TestSchemaVersionVerbPrintsOnlyTheNumber(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out")
	f, err := os.Create(out) //nolint:gosec // a temp path this test composed
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"schema-version"}, f); err != nil {
		t.Fatalf("run: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(out) //nolint:gosec // a temp path this test composed
	if err != nil {
		t.Fatal(err)
	}
	text := strings.TrimSpace(string(body))
	n, err := strconv.Atoi(text)
	if err != nil {
		t.Fatalf("schema-version printed %q, which is not a bare integer: %v", text, err)
	}
	if n <= 0 {
		t.Fatalf("schema-version printed %d, want the migration high-water mark", n)
	}
}
