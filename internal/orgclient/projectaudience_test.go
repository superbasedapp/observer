package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

const projTOML = "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n"

// v3TestDelivery signs a v3 delivery for org-1/scim-42 with one envelope for X.
func v3TestDelivery(t *testing.T, priv ed25519.PrivateKey, version, epoch int64, mutate func(*orgcontract.ProjectMapping)) orgcontract.PolicyBundle {
	t.Helper()
	pub := base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	m := orgcontract.ProjectMapping{
		OrgID: "org-1", Subject: "scim-42", Epoch: epoch, MaxAgeSeconds: orgcontract.DefaultProjectMappingMaxAge,
		Projects: []orgcontract.ProjectMappingEntry{{OrgProjectID: "X", Repos: []orgcontract.ProjectRepoHashes{{RemoteHash: "rh-x", RootCommitHash: "rc-x"}}}},
	}
	m = orgcontract.SignProjectMapping(priv, m)
	env := orgcontract.PolicyBundle{
		Version: version, BundleTOML: projTOML, PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org-1", Subject: "scim-42", OrgProjectID: "X", Epoch: epoch},
	}
	env.Signature = orgcontract.SignPolicyBundleEnvelope(priv, env)
	digest := orgcontract.ProjectMappingDigest(m)
	if mutate != nil {
		mutate(&m)
		m = orgcontract.SignProjectMapping(priv, m)
	}
	b := orgcontract.PolicyBundle{
		Version: version, BundleTOML: "[[override]]\nrule = \"R-153\"\ndecision = \"ask\"\n", PublicKey: pub,
		ProjectBinding: &orgcontract.ProjectBinding{OrgID: "org-1", Subject: "scim-42", Epoch: epoch, MappingDigest: digest},
	}
	b.Signature = orgcontract.SignPolicyBundleEnvelope(priv, b)
	b.Projects = &orgcontract.ProjectDelivery{Mapping: m, Envelopes: []orgcontract.PolicyBundle{env}}
	return b
}

// TestFetchPolicyBundle_ProjectAudience is milestone 3 on the node: a v3
// delivery is accepted, its envelopes and mapping cached as files beside the
// bundle (which is cached without them), the index and the state row written;
// then a v2 bundle after it, a lower epoch, and a mapping whose digest or
// epoch differs from the signed one are refused and change nothing.
func TestFetchPolicyBundle_ProjectAudience(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = pub
	var serve *orgcontract.PolicyBundle
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, serve)
	}))
	t.Cleanup(srv.Close)
	c, s, cachePath := enrolledClient(t, srv.URL)
	fetch := func(b orgcontract.PolicyBundle) PolicyResult {
		t.Helper()
		serve = &b
		res, err := c.FetchPolicyBundle(context.Background(), cachePath)
		if err != nil {
			t.Fatalf("FetchPolicyBundle: %v", err)
		}
		return res
	}

	if res := fetch(v3TestDelivery(t, priv, 5, 3, nil)); res.Status != PolicyApplied {
		t.Fatalf("v3 delivery = %+v, want applied", res)
	}
	raw, err := os.ReadFile(cachePath)
	if err != nil || strings.Contains(string(raw), `"projects"`) || !strings.Contains(string(raw), `"project_binding"`) {
		t.Fatalf("the cached bundle must keep its v3 binding and drop the projects field: %s (%v)", raw, err)
	}
	l := projectmatch.LayoutFor(cachePath)
	mraw, err := os.ReadFile(l.MappingPath())
	if err != nil {
		t.Fatalf("mapping not cached: %v", err)
	}
	mf, err := projectmatch.DecodeMappingFile(mraw)
	if err != nil || mf.BundleVersion != 5 || mf.Mapping.Epoch != 3 || mf.AcceptedAt.IsZero() {
		t.Fatalf("mapping file = %+v (%v)", mf, err)
	}
	if _, err := os.Stat(l.EnvelopePath("X")); err != nil {
		t.Fatalf("envelope X not cached: %v", err)
	}
	if got, err := s.LookupOrgProjects(context.Background(), []string{"rh-x"}, ""); err != nil || len(got.OrgProjectIDs) != 1 || got.Epoch != 3 {
		t.Fatalf("index = %+v (%v)", got, err)
	}
	if row := orgStateRow(t, s, srv.URL+ProjectAudienceStateSuffix); row == nil || row.Version != "3" {
		t.Fatalf("state row = %+v", row)
	}

	refused := []struct {
		name string
		b    orgcontract.PolicyBundle
		code PolicyRejectCode
	}{
		{"v2 after v3", boundTestBundle(t, priv, priv.Public().(ed25519.PublicKey), 6, projTOML, &orgcontract.PolicyBinding{OrgID: "org-1", Subject: "scim-42"}), RejectSigInvalid},
		{"v1 after v3", signedTestBundle(t, priv, priv.Public().(ed25519.PublicKey), 6, projTOML), RejectSigInvalid},
		{"a lower epoch", v3TestDelivery(t, priv, 6, 2, nil), RejectVersionDowngrade},
		{"mapping digest differs", v3TestDelivery(t, priv, 6, 3, func(m *orgcontract.ProjectMapping) { m.Projects[0].Repos[0].RemoteHash = "rh-other" }), RejectSigInvalid},
		{"mapping epoch differs", v3TestDelivery(t, priv, 6, 3, func(m *orgcontract.ProjectMapping) { m.Epoch = 4 }), RejectSigInvalid},
	}
	for _, r := range refused {
		res := fetch(r.b)
		if res.Status != PolicyRejected || res.RejectCode != r.code {
			t.Fatalf("%s = %+v, want rejected %s", r.name, res, r.code)
		}
		if after, _ := os.ReadFile(cachePath); string(after) != string(raw) {
			t.Fatalf("%s: a refused bundle replaced the cache", r.name)
		}
	}

	// A newer epoch at a newer version lands, and the stale envelope set is
	// replaced.
	if res := fetch(v3TestDelivery(t, priv, 7, 4, nil)); res.Status != PolicyApplied {
		t.Fatalf("newer epoch = %+v", res)
	}
	if row := orgStateRow(t, s, srv.URL+ProjectAudienceStateSuffix); row == nil || row.Version != "4" {
		t.Fatalf("state row after the newer epoch = %+v", row)
	}
}

// TestProjectFilesPresentNeedsEveryMappedEnvelope is audit finding 4 on the
// conditional fetch: a mapped project whose envelope file is gone makes the
// next poll fetch in full instead of keeping the cache on a 304.
func TestProjectFilesPresentNeedsEveryMappedEnvelope(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	b := v3TestDelivery(t, priv, 5, 3, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, b)
	}))
	t.Cleanup(srv.Close)
	c, _, cachePath := enrolledClient(t, srv.URL)
	if res, err := c.FetchPolicyBundle(context.Background(), cachePath); err != nil || res.Status != PolicyApplied {
		t.Fatalf("v3 delivery = %+v (%v)", res, err)
	}
	if !projectFilesPresent(cachePath) {
		t.Fatal("a complete project cache reads as incomplete")
	}
	if err := os.Remove(projectmatch.LayoutFor(cachePath).EnvelopePath("X")); err != nil {
		t.Fatal(err)
	}
	if projectFilesPresent(cachePath) {
		t.Fatal("a missing mapped envelope must force a full fetch, not a 304")
	}
}
