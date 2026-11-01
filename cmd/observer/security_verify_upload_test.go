//go:build !sbo_omit_security && !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secverify"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// TestSecurityVerifyUploadExampleInSync: the documented upload-on example
// is the generator's output, and the verdict job (every job but the result
// job) is byte-identical to the upload-off example.
func TestSecurityVerifyUploadExampleInSync(t *testing.T) {
	publictree.Skip(t, "docs/examples/security-verify")
	p := secverify.ExampleOrgWorkflowParams(update.VendorPublicKeyV1)
	p.ResultUpload = true
	want, err := secverify.RenderWorkflow(p)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join("..", "..", "docs", "examples", "security-verify")
	got, err := os.ReadFile(filepath.Join(dir, "observer-security-verify-org-upload.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("docs/examples/security-verify/observer-security-verify-org-upload.yml drifted from the generator; regenerate it with:\n  go run ./cmd/observer security verify template --org-url https://observer-org.example.com --org-id your-org-id --org-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= --result-upload > docs/examples/security-verify/observer-security-verify-org-upload.yml")
	}
	off, err := os.ReadFile(filepath.Join(dir, "observer-security-verify-org.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(got), strings.TrimSuffix(string(off), "\n")+"\n\n  result:\n") {
		t.Error("the upload-on example changed a job of the upload-off example")
	}
}

// TestSecurityVerifyUpload posts the verdict job's SARIF to a fake org with
// the CI credential, binds it to the runner's repository and attempt, and
// uploads unknown when the artifact is missing.
func TestSecurityVerifyUpload(t *testing.T) {
	var got []orgcontract.CIResultUpload
	var bearer, oidc, audience string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/runner/idtoken" {
			if r.Header.Get("Authorization") != "bearer runner-request-token" {
				http.Error(w, "no", http.StatusUnauthorized)
				return
			}
			audience = r.URL.Query().Get("audience")
			_ = json.NewEncoder(w).Encode(map[string]string{"value": "hdr.claims.sig"})
			return
		}
		if r.Method != http.MethodPost || r.URL.Path != orgcontract.CIResultPath {
			http.NotFound(w, r)
			return
		}
		bearer = r.Header.Get("Authorization")
		oidc = r.Header.Get(orgcontract.CIResultOIDCHeader)
		b, _ := io.ReadAll(r.Body)
		var u orgcontract.CIResultUpload
		_ = json.Unmarshal(b, &u)
		got = append(got, u)
		_ = json.NewEncoder(w).Encode(orgcontract.CIResultAnswer{Repository: u.Repository, HeadSHA: u.HeadSHA, Attempt: u.Attempt, Verdict: u.Verdict, Stored: true})
	}))
	defer srv.Close()
	t.Setenv("OBSERVER_CI_CREDENTIAL", "ci_test_credential")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_RUN_ATTEMPT", "3")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_RUN_ID", "77")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", srv.URL+"/runner/idtoken?api-version=2.0")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-request-token")
	head, base := strings.Repeat("a", 40), strings.Repeat("b", 40)
	dir := t.TempDir()
	sarif := filepath.Join(dir, "observer-security.sarif")
	var b bytes.Buffer
	if err := secverify.WriteSARIF(&b, secverify.Report{Verdict: secverify.VerdictFail, Rule: "secret.added", Base: base, Head: head}, "/repo", ""); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sarif, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	o := securityVerifyOpts{base: base, head: head, upload: verifyUploadOpts{sarif: sarif, orgURL: srv.URL, credentialEnv: "OBSERVER_CI_CREDENTIAL"}}
	var out, errOut bytes.Buffer
	if err := runSecurityVerifyUpload(context.Background(), &out, &errOut, o); err != nil {
		t.Fatalf("upload: %v %s", err, errOut.String())
	}
	o.upload.sarif = filepath.Join(dir, "missing.sarif")
	if err := runSecurityVerifyUpload(context.Background(), &out, &errOut, o); err != nil {
		t.Fatalf("missing upload: %v %s", err, errOut.String())
	}
	if len(got) != 2 || got[0].Verdict != "fail" || got[0].Repository != "acme/app" || got[0].Attempt != 3 ||
		got[0].RunURL != "https://github.com/acme/app/actions/runs/77/attempts/3" || got[1].Verdict != "unknown" || got[1].VerdictRule != secverify.UploadRuleSARIFMissing {
		t.Fatalf("uploads %+v", got)
	}
	if bearer != "Bearer ci_test_credential" {
		t.Fatalf("bearer %q", bearer)
	}
	if oidc != "hdr.claims.sig" || audience != srv.URL {
		t.Fatalf("the OIDC token %q (audience %q) did not ride the upload", oidc, audience)
	}
	// --upload-pending registers the run (no SARIF read).
	pend := o
	pend.upload.sarif, pend.upload.pending = "", true
	if err := runSecurityVerifyUpload(context.Background(), &out, &errOut, pend); err != nil {
		t.Fatalf("pending: %v %s", err, errOut.String())
	}
	if len(got) != 3 || got[2].Verdict != orgcontract.CIResultPending || got[2].VerdictRule != "" {
		t.Fatalf("pending upload %+v", got)
	}
	got = got[:2]
	if strings.Contains(out.String()+errOut.String(), "ci_test_credential") {
		t.Fatal("the credential reached the output")
	}
	// Refusals: no org URL, a check flag beside --upload, no credential.
	for _, mut := range []func(*securityVerifyOpts){
		func(o *securityVerifyOpts) { o.upload.orgURL = "" },
		func(o *securityVerifyOpts) { o.policyFile = "/p.toml" },
		func(o *securityVerifyOpts) { o.head = "zz" },
		func(o *securityVerifyOpts) { o.upload.credentialEnv = "OBSERVER_NO_SUCH_VAR" },
		func(o *securityVerifyOpts) { o.upload.pending = true },
	} {
		q := o
		mut(&q)
		if err := runSecurityVerifyUpload(context.Background(), io.Discard, io.Discard, q); err == nil {
			t.Errorf("accepted %+v", q)
		}
	}
	if len(got) != 2 {
		t.Fatalf("a refused upload reached the org: %d", len(got))
	}
}

// TestSecurityVerifyUploadNeedsOIDC (audit finding F1): with no runner OIDC
// request in the environment (a job without `id-token: write`) nothing is
// uploaded.
func TestSecurityVerifyUploadNeedsOIDC(t *testing.T) {
	posts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts++ }))
	defer srv.Close()
	t.Setenv("OBSERVER_CI_CREDENTIAL", "ci_test_credential")
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_RUN_ID", "77")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	o := securityVerifyOpts{head: strings.Repeat("a", 40), upload: verifyUploadOpts{pending: true, orgURL: srv.URL, credentialEnv: "OBSERVER_CI_CREDENTIAL"}}
	var errOut bytes.Buffer
	if err := runSecurityVerifyUpload(context.Background(), io.Discard, &errOut, o); err == nil || !strings.Contains(errOut.String(), "id-token: write") {
		t.Fatalf("uploaded without an OIDC token: %v %s", err, errOut.String())
	}
	if posts != 0 {
		t.Fatalf("%d requests reached the org", posts)
	}
}
