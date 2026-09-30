package orgclient

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// Agent Access per-device registration, node side (docs/plans/
// agent-access-implementation-plan-2026-09-23.md §4.1 / §11.3 W1b, R6/R8.13).
//
// The node holds a DEDICATED agent-access keypair - its DPoP key (cnf.jkt) and
// actor-assertion signer - that is never the push-signing key (domain
// separation, R2/D-2). It lives in the OS keychain slot "agent-access-key"
// FIRST and, when the keychain cannot round-trip a record, in a hardened 0600
// file beside the BearerStore's own file fallback (operator ruling 2026-09-27;
// agentaccess_keystore.go owns the backend selection). Only when NEITHER is
// usable does the operation fail closed with ErrAgentAccessKeychainUnavailable.
// The short-lived access tokens minted against this key are memory-only and
// never persisted here.
//
// RegisterAgentAccessKey registers the key's PUBLIC half with the org server
// (POST /api/agent/agent-access/register), signed with the node's existing
// enrolment key and carrying a proof of possession of the new key.

// recAgentAccessKey is the keychain record (and file-fallback record name) of
// the agent-access private key, under the same service (KeychainID) as the
// BearerStore's records.
const recAgentAccessKey = "agent-access-key"

// agentAccessKeyEnvelope versions the stored value, identical in the keychain
// and the file fallback ("sbo-aak-v1:<alg>:<base64 PKCS#8>").
const agentAccessKeyEnvelope = "sbo-aak-v1"

// AgentAccessKeyProofTyp is the JOSE typ of the registration key proof; it
// must equal the org server's (api.AgentAccessKeyProofTyp).
const AgentAccessKeyProofTyp = "sbo-aa-register+jwt"

// DefaultAgentAccessKeyAlg is the algorithm a new agent-access key is
// generated for (EdDSA is the Agent Access default, R8.23.m).
const DefaultAgentAccessKeyAlg = jose.AlgEdDSA

// Agent Access registration errors.
var (
	// ErrAgentAccessKeychainUnavailable: NEITHER the OS keychain NOR the
	// hardened 0600 file fallback can hold the agent-access key (the
	// keychain cannot round-trip a record AND the file fallback is
	// unsupported on this platform or its directory fails the owner/mode
	// checks). The name predates the 2026-09-27 file fallback.
	ErrAgentAccessKeychainUnavailable = errors.New("orgclient: no usable agent-access key store (the OS keychain is unavailable and the 0600 file fallback cannot be used)")
	// ErrAgentAccessUnsupported: the org server does not serve the rail
	// (404/405 - an older server - or Agent Access not enabled there).
	ErrAgentAccessUnsupported = errors.New("orgclient: the org server does not serve agent-access registration")
	// ErrAgentAccessDeviceRevoked: an admin revoked this device; it cannot
	// register again until an admin re-enables it.
	ErrAgentAccessDeviceRevoked = errors.New("orgclient: this device's agent-access credential was revoked by an admin")
	// ErrAgentAccessDeviceLimit: the member is at the active-device cap.
	ErrAgentAccessDeviceLimit = errors.New("orgclient: the member has reached the agent-access device limit")
	// ErrAgentAccessRejected: the server refused the registration's shape
	// (400/413) - a client/server contract mismatch, not a retryable fault.
	ErrAgentAccessRejected = errors.New("orgclient: the org server rejected the agent-access registration")
)

// AgentAccessKey is the node's agent-access private key and its JWS
// algorithm.
type AgentAccessKey struct {
	Alg    string
	Signer crypto.Signer
}

// AgentAccessKeyStore persists the agent-access private key. Load returns
// ErrNoSecret when no key has been stored yet.
type AgentAccessKeyStore interface {
	LoadAgentAccessKey() (AgentAccessKey, error)
	SaveAgentAccessKey(k AgentAccessKey) error
	// ClearAgentAccessKey removes the key (unenrol); absence is not an error.
	ClearAgentAccessKey() error
}

// encodeAgentAccessKey renders the keychain envelope.
func encodeAgentAccessKey(k AgentAccessKey) (string, error) {
	if k.Signer == nil {
		return "", errors.New("orgclient: agent-access key has no signer")
	}
	if err := jose.CheckKeyAlg(k.Signer.Public(), k.Alg); err != nil {
		return "", fmt.Errorf("orgclient: agent-access key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k.Signer)
	if err != nil {
		return "", fmt.Errorf("orgclient: encode agent-access key: %w", err)
	}
	return agentAccessKeyEnvelope + ":" + k.Alg + ":" + base64.StdEncoding.EncodeToString(der), nil
}

// decodeAgentAccessKey parses and validates the keychain envelope.
func decodeAgentAccessKey(v string) (AgentAccessKey, error) {
	parts := strings.SplitN(v, ":", 3)
	if len(parts) != 3 || parts[0] != agentAccessKeyEnvelope {
		return AgentAccessKey{}, errors.New("orgclient: agent-access key record has an unknown envelope")
	}
	der, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return AgentAccessKey{}, errors.New("orgclient: agent-access key record is not base64")
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return AgentAccessKey{}, errors.New("orgclient: agent-access key record is not a PKCS#8 key")
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return AgentAccessKey{}, errors.New("orgclient: agent-access key record is not a signing key")
	}
	if err := jose.CheckKeyAlg(signer.Public(), parts[1]); err != nil {
		return AgentAccessKey{}, fmt.Errorf("orgclient: agent-access key record: %w", err)
	}
	return AgentAccessKey{Alg: parts[1], Signer: signer}, nil
}

// EnsureAgentAccessKey returns the stored agent-access key, generating and
// saving a new DefaultAgentAccessKeyAlg key on first use (created=true).
func EnsureAgentAccessKey(keys AgentAccessKeyStore) (k AgentAccessKey, created bool, err error) {
	if keys == nil {
		return AgentAccessKey{}, false, ErrAgentAccessKeychainUnavailable
	}
	k, err = keys.LoadAgentAccessKey()
	if err == nil {
		return k, false, nil
	}
	if !errors.Is(err, ErrNoSecret) {
		return AgentAccessKey{}, false, err
	}
	k, err = newAgentAccessKey(keys)
	return k, err == nil, err
}

// newAgentAccessKey generates, saves and returns a fresh key (replacing any
// stored one).
func newAgentAccessKey(keys AgentAccessKeyStore) (AgentAccessKey, error) {
	signer, err := jose.GenerateKey(rand.Reader, DefaultAgentAccessKeyAlg)
	if err != nil {
		return AgentAccessKey{}, fmt.Errorf("orgclient: generate agent-access key: %w", err)
	}
	k := AgentAccessKey{Alg: DefaultAgentAccessKeyAlg, Signer: signer}
	if err := keys.SaveAgentAccessKey(k); err != nil {
		return AgentAccessKey{}, err
	}
	return k, nil
}

// AgentAccessRegistration is the org server's record of this device's
// agent-access credential.
type AgentAccessRegistration struct {
	CredentialID        string `json:"credential_id"`
	MachineFP           string `json:"machine_fp"`
	KeyThumbprint       string `json:"key_thumbprint"`
	Alg                 string `json:"alg"`
	CredentialAssurance string `json:"credential_assurance"`
	CredGen             int64  `json:"cred_gen"`
	Status              string `json:"status"`
	CreatedAt           string `json:"created_at"`
	// Created is true when this call registered a new credential, false on
	// an idempotent re-registration of the same device key.
	Created bool `json:"created"`
}

// agentAccessRegisterBody is the POST body (the org server's
// agentAccessRegisterRequest).
type agentAccessRegisterBody struct {
	MachineFP string          `json:"machine_fp"`
	Alg       string          `json:"alg"`
	PublicJWK json.RawMessage `json:"public_jwk"`
	KeyProof  string          `json:"key_proof"`
}

// agentAccessKeyProofClaims are the key_proof claims (the org server's
// agentAccessKeyProofClaims).
type agentAccessKeyProofClaims struct {
	Aud       string `json:"aud"`
	Sub       string `json:"sub"`
	MachineFP string `json:"sbo_machine_fp"`
	JKT       string `json:"jkt"`
	Iat       int64  `json:"iat"`
}

// BuildAgentAccessRegistration renders the registration body for one device:
// the new key's public JWK and a key_proof JWS, signed by that key, binding
// its RFC 7638 thumbprint to (orgID, memberID, machineFP) at now. It is pure
// (no I/O); the caller signs the returned bytes with the enrolment key.
func BuildAgentAccessRegistration(orgID, memberID, machineFP string, k AgentAccessKey, now time.Time) ([]byte, error) {
	if k.Signer == nil {
		return nil, errors.New("orgclient.BuildAgentAccessRegistration: no agent-access key")
	}
	jwk, err := jose.PublicJWK(k.Signer.Public(), k.Alg, "")
	if err != nil {
		return nil, fmt.Errorf("orgclient.BuildAgentAccessRegistration: %w", err)
	}
	jkt, err := jwk.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("orgclient.BuildAgentAccessRegistration: %w", err)
	}
	claims, err := json.Marshal(agentAccessKeyProofClaims{
		Aud: orgID, Sub: memberID, MachineFP: machineFP, JKT: jkt, Iat: now.Unix(),
	})
	if err != nil {
		return nil, fmt.Errorf("orgclient.BuildAgentAccessRegistration: %w", err)
	}
	proof, err := jose.Sign(k.Signer, jose.Header{Typ: AgentAccessKeyProofTyp, Alg: k.Alg}, claims)
	if err != nil {
		return nil, fmt.Errorf("orgclient.BuildAgentAccessRegistration: sign key proof: %w", err)
	}
	pub, err := json.Marshal(jwk.PublicOnly())
	if err != nil {
		return nil, fmt.Errorf("orgclient.BuildAgentAccessRegistration: %w", err)
	}
	return json.Marshal(agentAccessRegisterBody{MachineFP: machineFP, Alg: k.Alg, PublicJWK: pub, KeyProof: proof})
}

// agentAccessMachineFP is this machine's identity for orgID - the same
// org-scoped hash (internal/machineid.ForOrg) the push rails report.
var agentAccessMachineFP = machineid.ForOrg

// RegisterAgentAccessKey registers this device's agent-access key with the
// org server, generating the key on first use. It is idempotent: a device
// key the server already holds comes back with Created=false. When the
// server reports the key's credential EXPIRED, the node generates a fresh key
// and registers that, once.
//
// Errors: ErrNotEnrolled; ErrAgentAccessKeychainUnavailable (fail closed:
// neither the keychain nor the file fallback is usable); ErrAgentAccessUnsupported (the server does not serve the
// rail); ErrAgentAccessDeviceRevoked; ErrAgentAccessDeviceLimit;
// ErrAgentAccessRejected; ErrAuthFailed (401/403); any other error is
// retryable.
func (c *Client) RegisterAgentAccessKey(ctx context.Context, keys AgentAccessKeyStore) (AgentAccessRegistration, error) {
	key, _, err := EnsureAgentAccessKey(keys)
	if err != nil {
		return AgentAccessRegistration{}, err
	}
	reg, err := c.registerAgentAccessKey(ctx, key)
	if !errors.Is(err, errAgentAccessKeyExpired) {
		return reg, err
	}
	fresh, err := newAgentAccessKey(keys)
	if err != nil {
		return AgentAccessRegistration{}, err
	}
	reg, err = c.registerAgentAccessKey(ctx, fresh)
	if errors.Is(err, errAgentAccessKeyExpired) {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: a freshly generated key was reported expired: %w", ErrAgentAccessRejected)
	}
	return reg, err
}

// errAgentAccessKeyExpired is the internal 409 credential_expired signal.
var errAgentAccessKeyExpired = errors.New("orgclient: agent-access key credential expired")

// agentAccessRegisterStatus maps (status, error code) to a client error,
// walked top-down; code "" matches any code.
var agentAccessRegisterStatus = []struct {
	status int
	code   string
	err    error
}{
	{http.StatusNotFound, "", ErrAgentAccessUnsupported},
	{http.StatusMethodNotAllowed, "", ErrAgentAccessUnsupported},
	{http.StatusForbidden, "device_revoked", ErrAgentAccessDeviceRevoked},
	{http.StatusUnauthorized, "", ErrAuthFailed},
	{http.StatusForbidden, "", ErrAuthFailed},
	{http.StatusConflict, "credential_expired", errAgentAccessKeyExpired},
	{http.StatusConflict, "device_limit", ErrAgentAccessDeviceLimit},
	{http.StatusBadRequest, "", ErrAgentAccessRejected},
	{http.StatusRequestEntityTooLarge, "", ErrAgentAccessRejected},
	{http.StatusConflict, "", ErrAgentAccessRejected},
}

func (c *Client) registerAgentAccessKey(ctx context.Context, key AgentAccessKey) (AgentAccessRegistration, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: %w", err)
	}
	if enr == nil {
		return AgentAccessRegistration{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		return AgentAccessRegistration{}, ErrNotEnrolled
	}
	if err != nil {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: load bearer: %w", err)
	}
	signKey, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		return AgentAccessRegistration{}, ErrNotEnrolled
	}
	if err != nil {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: load signing key: %w", err)
	}
	machine, err := agentAccessMachineFP(enr.OrgID)
	if err != nil {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: this machine has no usable identity: %w", err)
	}
	if orgcontract.SanitizeMachineHeader(machine) != machine || machine == "" {
		// machineid.ForOrg returns ("", nil) when no stable identity exists.
		return AgentAccessRegistration{}, errors.New("orgclient.RegisterAgentAccessKey: this machine has no usable identity")
	}
	now := time.Now()
	body, err := BuildAgentAccessRegistration(enr.OrgID, enr.UserID, machine, key, now)
	if err != nil {
		return AgentAccessRegistration{}, err
	}
	ts := now.Unix()
	sig := ed25519.Sign(signKey, orgcontract.PushSigningMessage(ts, body))

	url := strings.TrimRight(enr.OrgServerURL, "/") + "/api/agent/agent-access/register"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(orgcontract.HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(orgcontract.HeaderAgentSignature, base64.RawURLEncoding.EncodeToString(sig))

	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		var reg AgentAccessRegistration
		if err := json.Unmarshal(raw, &reg); err != nil {
			return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: decode: %w", err)
		}
		return reg, nil
	}
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	for _, row := range agentAccessRegisterStatus {
		if row.status == resp.StatusCode && (row.code == "" || row.code == e.Error) {
			return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: %w (%d %s)", row.err, resp.StatusCode, e.Error)
		}
	}
	return AgentAccessRegistration{}, fmt.Errorf("orgclient.RegisterAgentAccessKey: server returned %d %s", resp.StatusCode, e.Error)
}
