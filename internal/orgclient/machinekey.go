package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Machine-bound credential, node half (T-656, GRANT-15; the wire contract is
// orgcontract/machineproof.go). A managed node generates one Ed25519 key per
// org, keeps it beside its enrolment secret (the hardened 0600 file fallback
// the agent-access key uses, or the OS keychain where no such file exists),
// registers the public half with the org server on the grant rail's cadence,
// and signs every request that names its machine. No new timer, host or
// connection: registration rides the access-grant fetch, which already runs
// on the push cycle.

// machineKeyRecord is the stored slot: one base64 (std) Ed25519 seed PER ORG
// (Keys, REVIEW-4 P4-15), so enrolling into another org adds a key instead of
// overwriting the one an earlier org's server registered. OrgID / Seed are the
// single-key shape an earlier build wrote; it is read as one entry of Keys
// and never written again.
type machineKeyRecord struct {
	Keys  map[string]string `json:"keys,omitempty"`
	OrgID string            `json:"org_id,omitempty"`
	Seed  string            `json:"seed,omitempty"`
}

// machineKeyRingCap bounds the per-org keys one slot keeps. A node enrols
// into a handful of orgs over its life; past the cap the slot refuses to add
// another rather than silently dropping a key a server still holds.
const machineKeyRingCap = 32

// MachineKeyStore holds this node's machine key.
type MachineKeyStore interface {
	LoadMachineKey() ([]byte, error)
	SaveMachineKey(raw []byte) error
}

// recMachineKey names the key's slot (file suffix and keychain account).
const recMachineKey = "org-machine-key"

type machineKeyStore struct {
	service string
	path    string // "" = keychain
}

// OpenMachineKeyStore returns the machine key slot for service: the hardened
// file under fallbackDir where this build supports it, else the OS keychain.
func OpenMachineKeyStore(service, fallbackDir string) MachineKeyStore {
	s := &machineKeyStore{service: service}
	if agentAccessKeyFileSupported && fallbackDir != "" {
		s.path = filepath.Join(fallbackDir, "org-bearer", service+"."+recMachineKey)
	}
	return s
}

func (s *machineKeyStore) LoadMachineKey() ([]byte, error) {
	if s.path != "" {
		return readAgentAccessKeyFile(s.path)
	}
	v, err := keystore.KeyringGet(s.service, recMachineKey)
	if errors.Is(err, keystore.ErrKeyringNotFound) {
		return nil, ErrNoSecret
	}
	return []byte(v), err
}

func (s *machineKeyStore) SaveMachineKey(raw []byte) error {
	if s.path != "" {
		return writeAgentAccessKeyFile(s.path, raw)
	}
	return keystore.KeyringSet(s.service, recMachineKey, string(raw))
}

// SetMachineKeyStore injects the machine key slot. Unset (every build that
// does not wire it, and tests), the node sends no machine proof and never
// registers, which is exactly a released node's behaviour.
func (c *Client) SetMachineKeyStore(keys MachineKeyStore) { c.machineKeys = keys }

// machineKeyState remembers, for the process lifetime, the outcome of the
// last registration attempt so the grant rail does not re-register every
// cycle: a confirmed registration (server URL + fingerprint), or a time
// before which not to ask again (an older server, a conflict, an unattributed
// machine, a transport error).
type machineKeyState struct {
	mu         sync.Mutex
	registered string // serverURL|machine|fingerprint
	retryAfter time.Time
	warned     string
	// proof is this process's last machine-proof outcome (machineproof_status.go).
	proof MachineProofState
}

// machineKeyRetry is how long a refused or unsupported registration waits
// before the next attempt.
const machineKeyRetry = time.Hour

// loadOrCreateMachineKey returns the machine key for orgID, generating and
// storing a fresh one beside the others when the slot holds none for that org.
// A key held for another org is KEPT (REVIEW-4 P4-15): before, the slot held
// one key and a re-enrolment elsewhere overwrote it, so returning to the
// first org met a server still holding the destroyed key, a permanent 409.
func (c *Client) loadOrCreateMachineKey(orgID string) (ed25519.PrivateKey, error) {
	if c.machineKeys == nil {
		return nil, ErrNoSecret
	}
	ring, err := c.machineKeyRing()
	if err != nil {
		return nil, err
	}
	if s, ok := ring[orgID]; ok {
		if seed, derr := base64.StdEncoding.DecodeString(s); derr == nil && len(seed) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(seed), nil
		}
	} else if len(ring) >= machineKeyRingCap {
		return nil, fmt.Errorf("orgclient: machine key slot already holds %d org keys", len(ring))
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ring[orgID] = base64.StdEncoding.EncodeToString(priv.Seed())
	raw, err := json.Marshal(machineKeyRecord{Keys: ring})
	if err != nil {
		return nil, err
	}
	if err := c.machineKeys.SaveMachineKey(raw); err != nil {
		return nil, fmt.Errorf("orgclient: store machine key: %w", err)
	}
	return priv, nil
}

// machineKeyRing reads the slot's per-org seeds (base64 std), the earlier
// single-key record folded in as one entry. An empty slot is an empty ring.
func (c *Client) machineKeyRing() (map[string]string, error) {
	ring := map[string]string{}
	raw, err := c.machineKeys.LoadMachineKey()
	if errors.Is(err, ErrNoSecret) {
		return ring, nil
	}
	if err != nil {
		return nil, err
	}
	var rec machineKeyRecord
	if json.Unmarshal(raw, &rec) == nil {
		for org, seed := range rec.Keys {
			ring[org] = seed
		}
		if rec.OrgID != "" && rec.Seed != "" {
			if _, ok := ring[rec.OrgID]; !ok {
				ring[rec.OrgID] = rec.Seed
			}
		}
	}
	return ring, nil
}

// existingMachineKey returns the machine key the slot already holds for orgID
// and never creates one (a leave must not mint a key it then abandons).
func (c *Client) existingMachineKey(orgID string) (ed25519.PrivateKey, bool) {
	if c.machineKeys == nil {
		return nil, false
	}
	ring, err := c.machineKeyRing()
	if err != nil {
		return nil, false
	}
	s, ok := ring[orgID]
	if !ok {
		return nil, false
	}
	seed, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(seed), true
}

// attachLeaveProof names machine on the leave notice and signs it with the
// machine key this node already holds for the org (T-747, ruling D-559), so
// the server can retire that key. It registers nothing and creates no key:
// with no key (an unwired build, a machine that never registered) or no
// machine identity (an individual enrolment), the notice goes as before.
func (c *Client) attachLeaveProof(req *http.Request, enr *store.Enrolment, machine string) {
	machine = orgcontract.SanitizeMachineHeader(machine)
	if enr == nil || machine == "" {
		return
	}
	priv, ok := c.existingMachineKey(enr.OrgID)
	if !ok {
		return
	}
	req.Header.Set(orgcontract.HeaderMachineIdentity, machine)
	for k, v := range orgcontract.MachineProofHeaders(priv, enr.OrgID, enr.UserID, machine, http.MethodPost, orgcontract.AgentLeavePath, time.Now()) {
		req.Header.Set(k, v)
	}
}

// attachMachineProof registers this machine's key when it is not yet
// registered (best-effort, never failing the caller's request) and adds the
// per-request machine proof for (method, path) to req. path is the rail's
// route constant, never the request URL, so a reverse-proxy prefix in front
// of the org server cannot break the signed message.
func (c *Client) attachMachineProof(ctx context.Context, req *http.Request, enr *store.Enrolment, machine, method, path string) {
	if c.machineKeys == nil || enr == nil || machine == "" {
		return
	}
	priv, err := c.loadOrCreateMachineKey(enr.OrgID)
	if err != nil {
		c.noteMachineProof(MachineProofState{Known: true, Reason: MachineProofUnavailableReason(err)})
		return
	}
	c.noteMachineProof(MachineProofState{Known: true, Available: true})
	c.ensureMachineKeyRegistered(ctx, enr, machine, priv)
	for k, v := range orgcontract.MachineProofHeaders(priv, enr.OrgID, enr.UserID, machine, method, path, time.Now()) {
		req.Header.Set(k, v)
	}
}

// ensureMachineKeyRegistered posts the key once per (server, machine, key) per
// process, honouring the retry window after a refusal.
func (c *Client) ensureMachineKeyRegistered(ctx context.Context, enr *store.Enrolment, machine string, priv ed25519.PrivateKey) {
	pubB64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	fp := orgcontract.MachineKeyFingerprint(priv.Public().(ed25519.PublicKey))
	key := strings.TrimRight(enr.OrgServerURL, "/") + "|" + machine + "|" + fp
	st := &c.machineKeyState
	st.mu.Lock()
	if st.registered == key || time.Now().Before(st.retryAfter) {
		st.mu.Unlock()
		return
	}
	st.mu.Unlock()
	status, outcome := c.registerMachineKey(ctx, enr, machine, pubB64, priv)
	st.mu.Lock()
	defer st.mu.Unlock()
	switch {
	case status == http.StatusOK:
		st.registered, st.retryAfter = key, time.Time{}
	default:
		st.retryAfter = time.Now().Add(machineKeyRetry)
		if st.warned != key+outcome {
			st.warned = key + outcome
			c.logger.Warn("org machine key not registered; machine-scoped grants may be withheld from this machine",
				"status", status, "outcome", outcome, "fingerprint", fp[:12])
		}
	}
}

// registerMachineKey performs POST /api/agent/machine-key and returns the
// HTTP status (0 on a transport error) and a short outcome label.
func (c *Client) registerMachineKey(ctx context.Context, enr *store.Enrolment, machine, pubB64 string, priv ed25519.PrivateKey) (int, string) {
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return 0, "no_bearer"
	}
	ts := time.Now().Unix()
	body, err := json.Marshal(orgcontract.MachineKeyRegistration{
		MachineIdentity: machine, PublicKey: pubB64, Timestamp: ts,
		Signature: orgcontract.SignMachineMessage(priv, orgcontract.MachineKeyRegistrationMessage(enr.OrgID, enr.UserID, machine, pubB64, ts)),
	})
	if err != nil {
		return 0, "marshal"
	}
	url := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.MachineKeyPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, "request"
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return 0, "unreachable"
	}
	defer func() { _ = resp.Body.Close() }()
	if c.classifyRail(machineKeyRail, resp) == railReplyNotSupported {
		return http.StatusNotFound, "not_supported"
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return resp.StatusCode, "registered"
	case http.StatusConflict:
		return resp.StatusCode, "conflict"
	case http.StatusForbidden:
		return resp.StatusCode, "not_attributed"
	default:
		return resp.StatusCode, "refused"
	}
}

// machineKeyRail names this rail in rail-reply classification.
const machineKeyRail = "machine-key"
