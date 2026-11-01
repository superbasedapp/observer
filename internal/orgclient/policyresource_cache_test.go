package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPolicyResourceCacheStoredAndReadBack is the regression test at the
// policy-resource cache seam (WINNODE item 1). On v1.36.0 Windows the cache
// write (writeFileAtomicFsync, Fsync on) failed after its rename, so the
// fenced install rolled back and no family was ever stored. Here a fetched,
// verified resource must land byte for byte as served, commit its durable
// floor, and be read back from the cache by the next poll's 304 path, which
// re-runs every accept gate against the stored file. No build tag: it also
// runs as a Windows test binary.
func TestPolicyResourceCacheStoredAndReadBack(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r1 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r1

	c, s, cacheDir := enrolledPRClient(t, ps.srv.URL)
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput}}
	ctx := context.Background()
	res, err := c.FetchAndAcceptPolicyResource(ctx, policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if res.Status != PRApplied || res.CachePath == "" {
		t.Fatalf("result = %+v, want applied with a cache path", res)
	}
	stored, err := os.ReadFile(res.CachePath)
	if err != nil {
		t.Fatalf("cache not stored: %v", err)
	}
	served, err := json.Marshal(r1)
	if err != nil {
		t.Fatal(err)
	}
	var a, b orgcontract.SignedPolicyResource
	if json.Unmarshal(stored, &a) != nil || json.Unmarshal(served, &b) != nil || a.Signature != b.Signature || a.Body != b.Body {
		t.Fatalf("stored envelope differs from the served one:\n%s\n%s", stored, served)
	}
	entries, err := os.ReadDir(filepath.Dir(res.CachePath))
	if err != nil || len(entries) != 1 {
		t.Fatalf("cache directory entries = %d (%v), want 1 (no temp file left)", len(entries), err)
	}
	st, ok, err := s.LoadPolicyResourceState(ctx, res.OrgKey, policyfamAdmissionInput)
	if err != nil || !ok || st.FloorVersion != 1 {
		t.Fatalf("durable state = %+v ok=%v err=%v, want floor 1 (the install must commit)", st, ok, err)
	}

	// Next poll: 304, so the result is built from the stored file.
	again, err := c.FetchAndAcceptPolicyResource(ctx, policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if again.Status != PRUnchanged || again.Spec == nil || again.Version != 1 || again.BodyHash != r1.BodyHash {
		t.Fatalf("read back = %+v, want unchanged v1 with the compiled spec", again)
	}
	if after, _ := os.ReadFile(res.CachePath); !bytes.Equal(after, stored) {
		t.Fatal("a 304 rewrote the stored cache")
	}
}

// TestWriteFileAtomicFsyncReplaces pins the cache writer itself: it creates
// the generation directory, replaces an existing cache in place and leaves
// no temp file.
func TestWriteFileAtomicFsyncReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "org", "1", "node.governance.json")
	for _, want := range [][]byte{[]byte(`{"version":1}`), []byte(`{"version":2}`)} {
		if err := writeFileAtomicFsync(path, want); err != nil {
			t.Fatalf("writeFileAtomicFsync: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("read back = %q (%v), want %q", got, err, want)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %d (%v), want 1", len(entries), err)
	}
}
