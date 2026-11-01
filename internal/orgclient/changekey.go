package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// changekey.go is a managed node's change-record key enrolment (security
// plan 7.10 "Key enrolment", lane SEC-F2B): the node registers the public
// half of its change-record signing key with the org over the enrolled
// channel (its enrolment bearer and the org key pinned at enrolment), with a
// proof of possession, and gets back the org's key certificate (key id,
// machine identity, org, 90-day validity). This package checks only that the
// answer's org root is the org key pinned at enrolment; the caller (the
// security module, which owns the certificate format) verifies the
// certificate under that root and that it names this key, org and machine.
// An individual node self-certifies and never calls this.

// maxChangeKeyReply caps the enrolment answer.
const maxChangeKeyReply = 64 << 10

// The enrolment refusals a caller tells apart.
var (
	// ErrChangeKeyIndividual: an individual enrolment self-certifies.
	ErrChangeKeyIndividual = errors.New("orgclient: key certificates are for managed enrolments")
	// ErrChangeKeyNotSupported: the org server has no org.security.ci (404).
	ErrChangeKeyNotSupported = errors.New("orgclient: the org server certifies no change-record keys")
	// ErrChangeKeyRevoked: the org has revoked this key (409).
	ErrChangeKeyRevoked = errors.New("orgclient: the org has revoked this change-record key")
	// ErrChangeKeyMachineNotOnRecord: the org has no machine on record for
	// this member yet (409 machine_not_on_record, lane SEC-P4 decision 8):
	// the node enrols after its first push names its machine.
	ErrChangeKeyMachineNotOnRecord = errors.New("orgclient: the org has no machine on record for this member yet")
	// ErrChangeKeyMachineBound: this member's change-record keys are bound
	// to another machine (the member's first certified enrolment); an org
	// admin resets the binding (lane LEFT-SHARED, SECP-31).
	ErrChangeKeyMachineBound = errors.New("orgclient: this member's change-record keys are bound to another machine; an org admin can reset the binding")
	// ErrChangeKeyCertificate: the answer is not issued by the pinned org
	// key.
	ErrChangeKeyCertificate = errors.New("orgclient: the key certificate is not issued by the pinned org key")
)

// ChangeKeyCertificate is the org's answer whose root is the pinned org
// key: the certificate as JSON (internal/secchange.Certificate, for the
// caller to verify) and the org root.
type ChangeKeyCertificate struct {
	Certificate json.RawMessage              `json:"certificate"`
	OrgRoot     orgcontract.ChangeKeyOrgRoot `json:"org_root"`
}

// EnrolChangeKey registers priv's public key for this machine and returns
// the org's verified certificate.
func (c *Client) EnrolChangeKey(ctx context.Context, priv ed25519.PrivateKey, machine string, now time.Time) (ChangeKeyCertificate, error) {
	var zero ChangeKeyCertificate
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return zero, errors.New("orgclient.EnrolChangeKey: not an Ed25519 key")
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: load enrolment: %w", err)
	}
	if enr == nil || c.bearers == nil {
		return zero, ErrNotEnrolled
	}
	// A managed enrolment, or one whose org switched it to enterprise
	// (P-205): the org server certifies both.
	if managed, merr := NodeManagedFor(ctx, c.store, enr); merr != nil {
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: %w", merr)
	} else if !managed {
		return zero, ErrChangeKeyIndividual
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: load bearer: %w", err)
	}
	pinned, err := c.loadKeyPin(ctx, enr.OrgServerURL)
	if err != nil {
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: read key pin: %w", err)
	}
	if pinned == "" {
		return zero, ErrChangeKeyCertificate
	}
	req := orgcontract.ChangeKeyEnrolRequest{
		KeyID: orgcontract.CIKeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: machine,
		At: now.UTC().Format(time.RFC3339),
	}
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, orgcontract.ChangeKeyEnrolMessage(enr.OrgID, req.KeyID, req.PublicKey, req.MachineIdentity, req.At)))
	raw, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(enr.OrgServerURL, "/")+orgcontract.AgentChangeKeyPath, bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	hreq.Header.Set("Authorization", "Bearer "+bearer)
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(hreq)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return zero, ErrChangeKeyNotSupported
	case http.StatusConflict:
		var e struct {
			Error string `json:"error"`
		}
		if b, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096)); rerr == nil && json.Unmarshal(b, &e) == nil && e.Error == orgcontract.ChangeKeyMachineNotOnRecord {
			return zero, ErrChangeKeyMachineNotOnRecord
		}
		return zero, ErrChangeKeyRevoked
	case http.StatusForbidden:
		// A machine binding refusal (lane LEFT-SHARED): this member's keys
		// are bound to another machine until an admin resets it.
		var e struct {
			Error string `json:"error"`
		}
		if b, rerr := io.ReadAll(io.LimitReader(resp.Body, 4096)); rerr == nil && json.Unmarshal(b, &e) == nil {
			switch e.Error {
			case orgcontract.ChangeKeyMachineBound:
				return zero, ErrChangeKeyMachineBound
			case managedOnlyCode:
				// The server does not serve this node as managed: an
				// older org server asked by a node its org switched to
				// enterprise. The key stays self-certified.
				return zero, ErrChangeKeyIndividual
			}
		}
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: %w", ErrAuthFailed)
	case http.StatusUnauthorized:
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: %w", ErrAuthFailed)
	default:
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxChangeKeyReply))
	if err != nil {
		return zero, fmt.Errorf("orgclient.EnrolChangeKey: read: %w", err)
	}
	return acceptChangeKeyCertificate(body, pinned)
}

// acceptChangeKeyCertificate reads an enrolment answer and checks that its
// org root is the pinned org key (the certificate itself is the caller's to
// verify under that root).
func acceptChangeKeyCertificate(body []byte, pinned string) (ChangeKeyCertificate, error) {
	var zero ChangeKeyCertificate
	var ans orgcontract.ChangeKeyEnrolResponse
	if err := json.Unmarshal(body, &ans); err != nil || len(ans.Certificate) == 0 {
		return zero, ErrChangeKeyCertificate
	}
	rootRaw, err := base64.StdEncoding.Strict().DecodeString(ans.OrgRoot.PublicKey)
	if err != nil || len(rootRaw) != ed25519.PublicKeySize || orgcontract.PublicKeyPinHash(ed25519.PublicKey(rootRaw)) != pinned ||
		ans.OrgRoot.KeyID != orgcontract.CIKeyID(ed25519.PublicKey(rootRaw)) {
		return zero, ErrChangeKeyCertificate
	}
	return ChangeKeyCertificate{Certificate: ans.Certificate, OrgRoot: ans.OrgRoot}, nil
}
