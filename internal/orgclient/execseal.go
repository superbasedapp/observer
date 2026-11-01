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

	"github.com/marmutapp/superbased-observer/internal/execevidence"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// execseal.go is a managed node's execution evidence seal key registration
// (component isolation.seal, ledger SHR-6, lane GATES-SEC; the change-key
// enrolment precedent, changekey.go): the node registers the public half of
// its seal key with the org over the enrolled channel, with a proof of
// possession, so the org can verify the seals on its run rows and
// countersign them. An individual node's seals stay self-attested and it
// never calls this.

// The registration refusals a caller tells apart.
var (
	// ErrExecSealIndividual: an individual enrolment's seals are
	// self-attested.
	ErrExecSealIndividual = errors.New("orgclient: seal keys are registered by managed enrolments only")
	// ErrExecSealNotSupported: the org server registers no seal keys (404).
	ErrExecSealNotSupported = errors.New("orgclient: the org server registers no execution evidence seal keys")
	// ErrExecSealNotManagedHere: the org server answered 403 managed_only
	// to a node managed by its org's switch to enterprise (an older org
	// server, or the window before it recorded the switch); the caller
	// backs off as for ErrExecSealNotSupported.
	ErrExecSealNotManagedHere = errors.New("orgclient: the org server does not register seal keys for this node as a managed one")
	// ErrExecSealMachineNotOnRecord: the org has no machine on record for
	// this member yet; the node retries after its first push.
	ErrExecSealMachineNotOnRecord = errors.New("orgclient: the org has no machine on record for this member yet")
	// ErrExecSealKeyRevoked: an org admin revoked this seal key (409
	// seal_key_revoked); its seals read key_revoked and asking again
	// changes nothing.
	ErrExecSealKeyRevoked = errors.New("orgclient: the org revoked this execution evidence seal key")
)

// RegisterExecSealKey registers priv's public key for this machine.
func (c *Client) RegisterExecSealKey(ctx context.Context, priv ed25519.PrivateKey, machine string, now time.Time) (orgcontract.ExecSealKeyAnswer, error) {
	var zero orgcontract.ExecSealKeyAnswer
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(priv) != ed25519.PrivateKeySize {
		return zero, errors.New("orgclient.RegisterExecSealKey: not an Ed25519 key")
	}
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return zero, fmt.Errorf("orgclient.RegisterExecSealKey: load enrolment: %w", err)
	}
	if enr == nil || c.bearers == nil {
		return zero, ErrNotEnrolled
	}
	// A managed enrolment, or one whose org switched it to enterprise
	// (P-205).
	managed, err := NodeManagedFor(ctx, c.store, enr)
	if err != nil {
		return zero, fmt.Errorf("orgclient.RegisterExecSealKey: %w", err)
	}
	if !managed {
		return zero, ErrExecSealIndividual
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return zero, fmt.Errorf("orgclient.RegisterExecSealKey: load bearer: %w", err)
	}
	req := orgcontract.ExecSealKeyRequest{
		KeyID: execevidence.SealKeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub), MachineIdentity: machine,
		At: now.UTC().Format(time.RFC3339),
	}
	req.Proof = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, execevidence.RegisterMessage(enr.OrgID, req.KeyID, req.PublicKey, req.MachineIdentity, req.At)))
	raw, err := json.Marshal(req)
	if err != nil {
		return zero, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(enr.OrgServerURL, "/")+orgcontract.AgentExecSealKeyPath, bytes.NewReader(raw))
	if err != nil {
		return zero, err
	}
	hreq.Header.Set("Authorization", "Bearer "+bearer)
	hreq.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(hreq)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return zero, fmt.Errorf("orgclient.RegisterExecSealKey: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if err := execSealStatusErr(resp.StatusCode, resp.Body); err != nil {
		return zero, err
	}
	var ans orgcontract.ExecSealKeyAnswer
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&ans); err != nil || ans.KeyID != req.KeyID {
		return zero, errors.New("orgclient.RegisterExecSealKey: the answer does not name this key")
	}
	return ans, nil
}

// execSealStatusErr maps a registration answer's status (and, for a 409,
// its error code) to the refusal a caller tells apart; nil for 200.
func execSealStatusErr(status int, body io.Reader) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound, http.StatusMethodNotAllowed:
		return ErrExecSealNotSupported
	case http.StatusConflict:
		var e struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&e) == nil && e.Error == orgcontract.ExecSealKeyRevoked {
			return ErrExecSealKeyRevoked
		}
		return ErrExecSealMachineNotOnRecord
	case http.StatusForbidden:
		var e struct {
			Error string `json:"error"`
		}
		if json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&e) == nil && e.Error == managedOnlyCode {
			return ErrExecSealNotManagedHere
		}
		return fmt.Errorf("orgclient.RegisterExecSealKey: %w", ErrAuthFailed)
	case http.StatusUnauthorized:
		return fmt.Errorf("orgclient.RegisterExecSealKey: %w", ErrAuthFailed)
	}
	return fmt.Errorf("orgclient.RegisterExecSealKey: status %d", status)
}
