package orgcontract

// execseal.go is the execution evidence seal's wire contract (component
// isolation.seal, ledger SHR-6, lane GATES-SEC): the seal a node attaches to
// a TerminalRunRow, and a managed node's registration of its seal key over
// the enrolled channel. The org verifies a seal at ingest (internal/
// execevidence.VerifySeal) and, for a key a managed node registered,
// countersigns it with its own key and the receipt time; an individual
// node's seal stays self-attested. A seal is tamper evidence against a
// later database edit, never proof the machine told the truth (TAMPER-3).

// AgentExecSealKeyPath is the managed node's seal key registration route.
const AgentExecSealKeyPath = "/api/agent/exec-evidence/seal-key"

// ExecSealKeyRevoked is the error code of a registration refused because an
// org admin revoked the key (409).
const ExecSealKeyRevoked = "seal_key_revoked"

// ExecEvidenceSeal is one run's seal: key id, base64 public key and base64
// signature over the run's evidence digest and the key id.
type ExecEvidenceSeal struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
	Sig       string `json:"sig"`
}

// ExecSealKeyRequest registers a managed node's seal key: the key, the
// machine identity, the time and a proof of possession over
// execevidence.RegisterMessage.
type ExecSealKeyRequest struct {
	KeyID           string `json:"key_id"`
	PublicKey       string `json:"public_key"`
	MachineIdentity string `json:"machine_identity"`
	At              string `json:"at"`
	Proof           string `json:"proof"`
}

// ExecSealKeyAnswer is the registration's answer.
type ExecSealKeyAnswer struct {
	KeyID        string `json:"key_id"`
	RegisteredAt string `json:"registered_at"`
}
