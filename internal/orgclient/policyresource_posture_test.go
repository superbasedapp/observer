package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policyfam"
)

// TestFetchAndAcceptPolicyResource_PostureLoosened pins the F0-8 result
// gate: a body the bound CheckPosture refuses is rejected posture_loosened
// naming the axis, is never cached, and the prior LKG survives; a nil gate is
// today's behaviour.
func TestFetchAndAcceptPolicyResource_PostureLoosened(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	r1 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 1, observeAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r1

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	var calls []string
	opts := PolicyResourceOptions{
		CacheDir: cacheDir, AcceptFamilies: []string{policyfamAdmissionInput},
		CheckPosture: func(family string, spec any) (string, error) {
			calls = append(calls, family)
			return "", nil
		},
	}
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil || res.Status != PRApplied {
		t.Fatalf("v1 with a passing gate: %+v %v", res, err)
	}
	if len(calls) != 1 || calls[0] != policyfamAdmissionInput {
		t.Fatalf("CheckPosture calls %v", calls)
	}
	lkg := filepath.Join(cacheDir, orgKeyForTest(t, c), "1", policyfamAdmissionInput+".json")
	before, err := os.ReadFile(lkg)
	if err != nil {
		t.Fatal(err)
	}

	r2 := signedTestResource(t, priv, pub, policyfamAdmissionInput, 2, enforceAdmissionBody, nil)
	ps.resources[policyfamAdmissionInput] = &r2
	opts.CheckPosture = func(string, any) (string, error) {
		return "prelaunch_trust", errors.New("ask -> warn")
	}
	res, err = c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != PRRejected || res.RejectCode != PRRejectPostureLoosened || !strings.Contains(res.Detail, "prelaunch_trust") {
		t.Fatalf("result %+v, want rejected posture_loosened naming the axis", res)
	}
	after, err := os.ReadFile(lkg)
	if err != nil || string(after) != string(before) {
		t.Fatal("the last known good must be kept on posture_loosened")
	}

	// Nil gate: today's behaviour, the same body applies.
	opts.CheckPosture = nil
	res, err = c.FetchAndAcceptPolicyResource(context.Background(), policyfamAdmissionInput, opts)
	if err != nil || res.Version != 2 || (res.Status != PRApplied && res.Status != PRAppliedInert) {
		t.Fatalf("nil gate: %+v %v", res, err)
	}
}

// TestFetchAndAcceptPolicyResource_UnknownFamilyIsNone: an org server older
// than a family answers 400 unknown_family for its name; the node reads that
// as "nothing published" (keep, never clear), not as an error on every poll.
func TestFetchAndAcceptPolicyResource_UnknownFamilyIsNone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_family", "message": "family must be one of ..."})
	}))
	t.Cleanup(srv.Close)
	c, _, cacheDir := enrolledPRClient(t, srv.URL)
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfam.FamilySecurityScanning, PolicyResourceOptions{CacheDir: cacheDir})
	if err != nil || res.Status != PRNone {
		t.Fatalf("unknown_family: %+v %v, want PRNone", res, err)
	}
}
