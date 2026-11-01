package main

// WINNODE item 1: a daemon adopts a verified org policy layer it never
// installed itself, at its next start (the last-known-good loader) and at its
// next poll (the policy-resource poller). No build tag: this runs in every
// build, and as a Windows test binary.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodefeatures"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPolicyLayerAdopterTable pins, one row per case, what the poller
// publishes for a fetch result given what it already installed.
func TestPolicyLayerAdopterTable(t *testing.T) {
	const fam = policyfam.FamilyNodeFeatures
	spec := struct{}{}
	v3 := orgclient.PolicyResourceResult{OrgKey: "k", Generation: 1, Version: 3, BodyHash: "h3", Spec: spec, EnforceAllowed: true}
	with := func(r orgclient.PolicyResourceResult, st orgclient.PolicyResourceStatus) orgclient.PolicyResourceResult {
		r.Status = st
		return r
	}
	inert := v3
	inert.EnforceAllowed = false
	noSpec := v3
	noSpec.Spec = nil
	v4 := v3
	v4.Version, v4.BodyHash = 4, "h4"

	cases := []struct {
		name  string
		held  *orgclient.PolicyResourceResult // installed before the result
		res   orgclient.PolicyResourceResult
		want  orgclient.PolicyResourceStatus
		holds bool // the adopter holds a record for the family afterwards
	}{
		{"unchanged never installed here installs", nil, with(v3, orgclient.PRUnchanged), orgclient.PRApplied, true},
		{"unchanged not preauthorized installs inert", nil, with(inert, orgclient.PRUnchanged), orgclient.PRAppliedInert, true},
		{"unchanged already installed keeps", &v3, with(v3, orgclient.PRUnchanged), orgclient.PRUnchanged, true},
		{"unchanged at another version installs", &v3, with(v4, orgclient.PRUnchanged), orgclient.PRApplied, true},
		{"unchanged without a compiled spec keeps", nil, with(noSpec, orgclient.PRUnchanged), orgclient.PRUnchanged, false},
		{"applied passes through", nil, with(v3, orgclient.PRApplied), orgclient.PRApplied, true},
		{"unsigned 404 keeps", nil, with(v3, orgclient.PRNone), orgclient.PRNone, false},
		{"signed withdrawal clears and forgets", &v3, with(v3, orgclient.PRWithdrawn), orgclient.PRWithdrawn, false},
		{"rejection keeps", nil, with(v3, orgclient.PRRejected), orgclient.PRRejected, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newPolicyLayerAdopter()
			if tc.held != nil {
				a.record(fam, *tc.held)
			}
			got := a.resolve(fam, tc.res)
			if policyResourceDisposition(got) == prDispositionInstall {
				a.record(fam, got) // what adoptAndPublish does once publish installed it
			}
			if got.Status != tc.want {
				t.Errorf("status = %q, want %q", got.Status, tc.want)
			}
			if _, ok := a.installed[fam]; ok != tc.holds {
				t.Errorf("holds a record = %v, want %v", ok, tc.holds)
			}
		})
	}
	a := newPolicyLayerAdopter()
	a.record(fam, v3)
	a.forget(fam)
	if got := a.resolve(fam, with(v3, orgclient.PRUnchanged)); got.Status != orgclient.PRApplied {
		t.Errorf("after forget, unchanged = %q, want applied", got.Status)
	}
}

// adoptBearer is a bearer store that holds a bearer, so the poller fetches.
type adoptBearer struct{ identNoBearer }

func (adoptBearer) LoadBearer() (string, error) { return "bearer-adopt", nil }

// adoptNodeFeaturesResource signs a node.features envelope.
func adoptNodeFeaturesResource(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, version int64) orgcontract.SignedPolicyResource {
	t.Helper()
	body := `{"remote":{"enabled":false}}`
	sum := sha256.Sum256([]byte(body))
	res := orgcontract.SignedPolicyResource{
		ID: "default", Version: version, Family: policyfam.FamilyNodeFeatures,
		CompilerVersion: "v1", Body: body, BodyHash: hex.EncodeToString(sum[:]),
		SelectorsJSON: "{}", PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		SignedAt: "2026-10-28T00:00:00Z",
	}
	sig, err := orgcontract.SignPolicyResource(priv, res)
	if err != nil {
		t.Fatalf("SignPolicyResource: %v", err)
	}
	res.Signature = sig
	return res
}

// adoptSetup is a node enrolled with orgURL whose node.features cache (and,
// when withState, the matching durable floor) another process already wrote,
// with the org signing key pinned.
func adoptSetup(t *testing.T, orgURL string, withState bool) (config.Config, *store.Store, string, orgcontract.SignedPolicyResource) {
	t.Helper()
	cfg, st := identTestStore(t)
	cfg.OrgClient.OrgServerURL = orgURL
	orgKey := seedLKGEnrolment(t, st, orgURL)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pinLKGKey(t, st, orgURL, pub)
	res := adoptNodeFeaturesResource(t, priv, pub, 3)
	dir := filepath.Join(policyResourceCacheDir(cfg), orgKey, strconv.FormatInt(1, 10))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	raw, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, policyfam.FamilyNodeFeatures+".json"), raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if withState {
		digest, err := orgcontract.PolicyResourceMessageDigest(res)
		if err != nil {
			t.Fatalf("digest: %v", err)
		}
		if err := st.WithPolicyResourceFence(context.Background(), orgKey, policyfam.FamilyNodeFeatures,
			func(context.Context, store.PolicyResourceFence) (*store.PolicyResourceCommit, error) {
				return &store.PolicyResourceCommit{
					Generation: 1, FloorVersion: res.Version, LastVersion: res.Version,
					BodyHash: res.BodyHash, MsgDigest: digest,
				}, nil
			}); err != nil {
			t.Fatalf("WithPolicyResourceFence: %v", err)
		}
	}
	return cfg, st, orgKey, res
}

// TestLKGAdoptsCacheWithNoDurableState is the v1.36.0 Windows shape at the
// next daemon start: the cache file was renamed into place but the write
// reported an error, so the durable floor was rolled back. The loader must
// install the verified cache and commit the floor, with no network.
func TestLKGAdoptsCacheWithNoDurableState(t *testing.T) {
	cfg, st, orgKey, res := adoptSetup(t, identTestOrgURL, false)
	nf := newNodeFeaturesHandle()
	loadPolicyResourceLKG(context.Background(), cfg, identTestClient(st), st, nil, nil, nil, nf, slog.Default())

	if f := nf.Facts(); !f.HasOrgRail || !f.InEffect || f.Version != res.Version {
		t.Fatalf("node.features after start = %+v, want installed and in effect at version %d", f, res.Version)
	}
	row, ok, err := st.LoadPolicyResourceState(context.Background(), orgKey, policyfam.FamilyNodeFeatures)
	if err != nil || !ok || row.FloorVersion != res.Version {
		t.Fatalf("durable state = %+v ok=%v err=%v, want floor %d", row, ok, err, res.Version)
	}
}

// TestPollerAdoptsUnchangedLayerItNeverInstalled is the same daemon at its
// next poll: it booted with no org layer, and the server now answers the
// version the durable floor already holds ("unchanged"). Before the fix the
// status table kept the empty layer until a restart.
func TestPollerAdoptsUnchangedLayerItNeverInstalled(t *testing.T) {
	var served orgcontract.SignedPolicyResource
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.TrimPrefix(r.URL.Path, "/api/agent/policy/") != policyfam.FamilyNodeFeatures {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"no_policy_resource"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(served)
	}))
	t.Cleanup(srv.Close)

	cfg, st, _, res := adoptSetup(t, srv.URL, true)
	served = res
	oc := orgclient.New(config.OrgClientConfig{OrgServerURL: srv.URL}, st, adoptBearer{}, "test", srv.Client(), slog.Default())
	nf := newNodeFeaturesHandle()
	if f := nf.Facts(); f.HasOrgRail {
		t.Fatalf("precondition: layer installed before the poll: %+v", f)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runPolicyResourcePoller(ctx, cfg, oc, nil, nil, nil, nf, nil, slog.Default())
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	deadline := time.After(10 * time.Second)
	for {
		if f := nf.Facts(); f.HasOrgRail && f.InEffect && f.Version == res.Version {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("the poller never adopted the unchanged layer: %+v", nf.Facts())
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// TestPolicyLayerAdoptedAfterIdentityReadFailsOnce (WINNODE merge follow-up
// F3): the identity gate refuses the first install (one failed enrolment
// read), so nothing is installed; the next "unchanged" poll of the same
// layer must still install it. Recording the layer before publish checked
// the gate left the daemon ungoverned until a restart.
func TestPolicyLayerAdoptedAfterIdentityReadFailsOnce(t *testing.T) {
	const fam = policyfam.FamilyNodeFeatures
	reads := 0
	ident := orgIdentityGate(func(string, int64) bool {
		reads++
		return reads > 1
	})
	res := orgclient.PolicyResourceResult{
		Status: orgclient.PRUnchanged, Family: fam, OrgKey: "k", Generation: 1,
		Version: 3, BodyHash: "h3", EnforceAllowed: true, Spec: nodefeatures.PolicySpec{},
	}
	a := newPolicyLayerAdopter()
	nf := newNodeFeaturesHandle()
	adoptAndPublish(a, ident, nil, nil, nil, nf, fam, res, slog.Default())
	if f := nf.Facts(); f.HasOrgRail {
		t.Fatalf("installed although the identity read failed: %+v", f)
	}
	adoptAndPublish(a, ident, nil, nil, nil, nf, fam, res, slog.Default())
	if f := nf.Facts(); !f.HasOrgRail || !f.InEffect || f.Version != 3 {
		t.Fatalf("after the identity read recovered = %+v, want installed and in effect at version 3", f)
	}
}
