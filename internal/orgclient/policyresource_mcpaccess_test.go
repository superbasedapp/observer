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
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/localpdp"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	famcp "github.com/marmutapp/superbased-observer/internal/policyfam/mcpaccess"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Agent Access P4 W4c: the tools.mcp_access family rides the SAME
// family-generic four-gate accept every other v1 family does
// (FetchAndAcceptPolicyResource) — no family-specific rail exists, by
// design. These tests pin that the generic gates hold for THIS family
// (bad signature / foreign org key / stale generation / unknown family /
// not accepted) and that an accepted resource compiles straight into the
// node relay's local PDP table.

// mcpAccessBody is a valid canonical tools.mcp_access body (DecodeBody
// refuses unknown fields, so it is built from the compiler's own types).
func mcpAccessBody(t *testing.T, mode string) string {
	t.Helper()
	b := famcp.Body{Mode: mode, Registry: mcpaccess.Registry{
		Issuer: "https://auth.acme", Org: "acme", GatewayBaseURI: "https://gw.acme", PolicyGen: 5,
		VServers: []mcpaccess.VServer{{
			ID: "vs-gh", Slug: "gh", SenderConstraint: "bearer",
			Servers: []mcpaccess.Server{{ID: "gh", Target: "gh", CredentialMode: "service"}},
		}},
	}, Grants: []mcpaccess.Grant{{
		ID: "g1", Ord: 1, Subject: mcpaccess.Subject{Kind: mcpaccess.SubjectProduct, Value: "claude-code"},
		Resource: mcpaccess.Resource{VServer: "vs-gh", Name: "create_issue"}, Action: mcpaccess.ActionCall,
		Effect: mcpaccess.EffectAllow, Enabled: true,
	}}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestFetchAndAcceptPolicyResource_MCPAccessAppliedCompilesNodeTable(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ps := newPolicyResourceServer(t)
	body := mcpAccessBody(t, famcp.ModeEnforce)
	r := signedTestResource(t, priv, pub, policyfam.FamilyMCPAccess, 4, body, nil)
	ps.resources[policyfam.FamilyMCPAccess] = &r

	c, _, cacheDir := enrolledPRClient(t, ps.srv.URL)
	// Enforce requested, NOT preauthorized: applied_inert, cached, never
	// enforced — the node table compiles to observe.
	opts := PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfam.FamilyMCPAccess}}
	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfam.FamilyMCPAccess, opts)
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRAppliedInert || res.EnforceAllowed || res.InertReason != "not_preauthorized" || res.Family != policyfam.FamilyMCPAccess {
		t.Fatalf("result = %+v, want applied_inert not_preauthorized", res)
	}
	spec, ok := res.Spec.(famcp.PolicySpec)
	if !ok {
		t.Fatalf("Spec is %T, want policyfam/mcpaccess.PolicySpec", res.Spec)
	}
	tbl, err := localpdp.Compile(spec, localpdp.Meta{Version: res.Version, BodyHash: res.BodyHash, OrgKey: res.OrgKey, Generation: res.Generation, EnforceAllowed: res.EnforceAllowed}, time.Now().Unix())
	if err != nil {
		t.Fatalf("localpdp.Compile: %v", err)
	}
	if tbl.Mode != localpdp.ModeObserve || len(tbl.Node.Rows) != 1 || tbl.PolicyGen() != 5 || tbl.Meta.Version != 4 {
		t.Fatalf("table %+v", tbl)
	}

	// Preauthorized on a new version: applied + enforce.
	r2 := signedTestResource(t, priv, pub, policyfam.FamilyMCPAccess, 5, body, nil)
	ps.resources[policyfam.FamilyMCPAccess] = &r2
	opts.PreauthorizeEnforce = []string{policyfam.FamilyMCPAccess}
	res, err = c.FetchAndAcceptPolicyResource(context.Background(), policyfam.FamilyMCPAccess, opts)
	if err != nil || res.Status != PRApplied || !res.EnforceAllowed {
		t.Fatalf("preauthorized: %+v err=%v", res, err)
	}
	tbl, _ = localpdp.Compile(res.Spec.(famcp.PolicySpec), localpdp.Meta{EnforceAllowed: true}, 0)
	if tbl.Mode != localpdp.ModeEnforce {
		t.Fatalf("mode %s, want enforce", tbl.Mode)
	}
	h := &localpdp.Holder{}
	h.Swap(tbl)
	p, _ := tbl.NodePrincipal(localpdp.NodeIdentity{Subject: "dev", Product: "claude-code"}, "vs-gh", localpdp.TransportStdioWrapper)
	d := (&localpdp.Engine{Tables: h}).CheckRequest(context.Background(), localpdp.Request{VServerID: "vs-gh", Method: "tools/call", Tool: "create_issue", Principal: p})
	if !d.Forwardable() || d.MatchedGrant != "g1" {
		t.Fatalf("accepted policy must decide on the node: %+v", d)
	}
}

func TestFetchAndAcceptPolicyResource_MCPAccessFourGatesRefuse(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	foreignPub, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)
	body := mcpAccessBody(t, famcp.ModeObserve)

	cases := []struct {
		name     string
		resource func(t *testing.T) orgcontract.SignedPolicyResource
		prePin   ed25519.PublicKey
		accept   []string
		want     PolicyResourceStatus
		wantCode PolicyResourceRejectCode
	}{
		{
			name: "gate 1: tampered body breaks the signature",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				r := signedTestResource(t, priv, pub, policyfam.FamilyMCPAccess, 1, body, nil)
				r.Body = mcpAccessBody(t, famcp.ModeEnforce)
				return r
			},
			accept: []string{policyfam.FamilyMCPAccess}, want: PRRejected, wantCode: PRRejectSigInvalid,
		},
		{
			name: "gate 2: signed by a FOREIGN org's key (pin mismatch)",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				return signedTestResource(t, foreignPriv, foreignPub, policyfam.FamilyMCPAccess, 1, body, nil)
			},
			prePin: pub, accept: []string{policyfam.FamilyMCPAccess}, want: PRRejected, wantCode: PRRejectKeyPinMismatch,
		},
		{
			name: "gate 3: envelope tagged with another family is a closed-envelope violation",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				return signedTestResource(t, priv, pub, policyfam.FamilyNodeFeatures, 1, body, nil)
			},
			accept: []string{policyfam.FamilyMCPAccess}, want: PRRejected, wantCode: PRRejectClosedEnvelope,
		},
		{
			name: "gate 4: body that does not compile (unknown action)",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				bad := strings.Replace(body, `"action":"call"`, `"action":"*"`, 1)
				return signedTestResource(t, priv, pub, policyfam.FamilyMCPAccess, 1, bad, nil)
			},
			accept: []string{policyfam.FamilyMCPAccess}, want: PRRejected, wantCode: PRRejectDecodeFailed,
		},
		{
			name: "family verified but not in accept_families",
			resource: func(t *testing.T) orgcontract.SignedPolicyResource {
				return signedTestResource(t, priv, pub, policyfam.FamilyMCPAccess, 1, body, nil)
			},
			accept: []string{policyfam.FamilyAdmissionInput}, want: PRDeliveredUnaccepted, wantCode: PRRejectFamilyNotAccepted,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := newPolicyResourceServer(t)
			r := tc.resource(t)
			ps.resources[policyfam.FamilyMCPAccess] = &r
			c, s, cacheDir := enrolledPRClient(t, ps.srv.URL)
			if tc.prePin != nil {
				enr, _ := s.LoadEnrolment(context.Background())
				if _, err := s.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
					Layer: "org", Path: PolicyKeyPinPath(enr.OrgServerURL),
					ContentHash: orgcontract.PublicKeyPinHash(tc.prePin), LoadedAt: time.Now().UTC(),
				}); err != nil {
					t.Fatalf("pre-pin: %v", err)
				}
			}
			res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfam.FamilyMCPAccess, PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: tc.accept})
			if err != nil {
				t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
			}
			if res.Status != tc.want || res.RejectCode != tc.wantCode {
				t.Fatalf("result = %+v, want %s/%s", res, tc.want, tc.wantCode)
			}
			if res.Spec != nil {
				t.Fatal("a refused resource must not hand back a compiled spec")
			}
		})
	}
}

// TestFetchAndAcceptPolicyResource_MCPAccessStaleGenerationRefused: the
// enrolment generation advances between the captured read and the durable
// CAS fence (a concurrent re-enrol) — the verified envelope is refused
// identity_changed and nothing is installed.
func TestFetchAndAcceptPolicyResource_MCPAccessStaleGenerationRefused(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	r := signedTestResource(t, priv, pub, policyfam.FamilyMCPAccess, 1, mcpAccessBody(t, famcp.ModeObserve), nil)

	var (
		s      *store.Store
		orgKey string
		bumped bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !bumped {
			bumped = true
			if _, err := s.BumpEnrolmentGeneration(context.Background(), orgKey, false); err != nil {
				t.Errorf("bump: %v", err)
			}
		}
		writeTestJSON(w, http.StatusOK, r)
	}))
	t.Cleanup(srv.Close)
	var c *Client
	var cacheDir string
	c, s, cacheDir = enrolledPRClient(t, srv.URL)
	orgKey = OrgKey(srv.URL, "org-1")

	res, err := c.FetchAndAcceptPolicyResource(context.Background(), policyfam.FamilyMCPAccess, PolicyResourceOptions{CacheDir: cacheDir, AcceptFamilies: []string{policyfam.FamilyMCPAccess}})
	if err != nil {
		t.Fatalf("FetchAndAcceptPolicyResource: %v", err)
	}
	if res.Status != PRRejected || res.RejectCode != PRRejectIdentityChanged {
		t.Fatalf("result = %+v, want rejected/identity_changed", res)
	}
	if _, ok, _ := s.LoadPolicyResourceState(context.Background(), orgKey, policyfam.FamilyMCPAccess); ok {
		t.Fatal("stale-generation envelope must not install state")
	}
	// Unknown family never reaches the wire.
	if _, err := c.FetchAndAcceptPolicyResource(context.Background(), "tools.nope", PolicyResourceOptions{CacheDir: cacheDir}); err == nil || !strings.Contains(err.Error(), "unsupported family") {
		t.Fatalf("unknown family: %v", err)
	}
	if errors.Is(err, ErrNotEnrolled) {
		t.Fatal("unexpected")
	}
}
