package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/attachgrant"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestAttachResponseError is one case per attachRefusals row, plus the
// answers it leaves to enrolResponseError.
func TestAttachResponseError(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   error
		reason string
	}{
		{name: "ok", status: http.StatusOK, body: `{}`},
		{name: "not accepted", status: http.StatusForbidden, body: `{"error":"attach_grant_not_accepted","message":"sign in to it instead"}`, want: ErrAttachGrantNotAccepted, reason: "sign in to it instead"},
		{name: "older server: missing token", status: http.StatusBadRequest, body: `{"error":"bad_request","message":"one_time_token and agent_public_key are required"}`, want: ErrAttachGrantNotAccepted},
		{name: "refused with a reason", status: http.StatusForbidden, body: `{"error":"attach_grant_refused","message":"your account is not a member of this team; ask a team admin to invite you"}`, want: ErrAttachGrantRefused, reason: "not a member of this team"},
		{name: "member not active is the token rail's", status: http.StatusForbidden, body: `{"error":"member_not_active"}`},
		{name: "server error is the token rail's", status: http.StatusInternalServerError, body: `{"error":"internal"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := attachResponseError(tc.status, []byte(tc.body))
			if tc.want == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("err = %v, want the server's reason %q", err, tc.reason)
			}
		})
	}
}

// TestEnrollWithAttachGrant: an attach-grant enrolment sends the grant and a
// device proof over THIS enrolment's node key, and no one-time token; the
// proof verifies against the device key's thumbprint the grant would name.
func TestEnrollWithAttachGrant(t *testing.T) {
	devPub, devPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var got orgcontract.EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
			Tenancy: orgcontract.TenancyManaged,
		})
	}))
	defer srv.Close()

	c := newTestClient(t, newAgentStore(t), &memBearerStore{})
	prove := func(grant, agentPub string) (orgcontract.AttachProof, error) {
		p, err := attachgrant.SignProof(devPriv, grant, agentPub)
		return orgcontract.AttachProof{DevicePublicKey: p.DevicePublicKey, Signature: p.Signature}, err
	}
	_, _, _, err = c.EnrollWithOptions(context.Background(), srv.URL, "", EnrollOptions{Attach: AttachCredential{Grant: "sbag1.G.S", Prove: prove}})
	if err != nil {
		t.Fatalf("EnrollWithOptions: %v", err)
	}
	if got.OneTimeToken != "" || got.AttachGrant != "sbag1.G.S" || got.AttachProof == nil || got.AgentPublicKey == "" {
		t.Fatalf("request = %+v", got)
	}
	claims := attachgrant.Claims{DeviceThumbprint: attachgrant.Thumbprint(devPub)}
	proof := attachgrant.Proof{DevicePublicKey: got.AttachProof.DevicePublicKey, Signature: got.AttachProof.Signature}
	if err := attachgrant.VerifyProof(claims, proof, got.AttachGrant, got.AgentPublicKey); err != nil {
		t.Fatalf("the proof does not bind the grant to the node key sent: %v", err)
	}

	// A grant and a token together, or a grant with no signer, are refused
	// before any network call.
	if _, _, _, err := c.EnrollWithOptions(context.Background(), srv.URL, "tok.secret", EnrollOptions{Attach: AttachCredential{Grant: "g", Prove: prove}}); err == nil {
		t.Fatal("a grant and a token together were accepted")
	}
	if _, _, _, err := c.EnrollWithOptions(context.Background(), srv.URL, "", EnrollOptions{Attach: AttachCredential{Grant: "g"}}); err == nil {
		t.Fatal("a grant with no device proof signer was accepted")
	}
}
