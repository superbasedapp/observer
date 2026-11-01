package guardposture

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// The org lock (T-839 / D-672, T-844, T-845).
//
// guard-org-lock.json is the daemon's MAC'd record of what the organization
// holds on this node, written beside guard-posture.json under the SAME key by
// the SAME writer (the daemon's posture loop) and repaired + reported the same
// way. It carries three things a short-lived reader cannot establish on its
// own:
//
//   - the TENANCY (managed or individual) the daemon resolved, so a hook
//     process applies the managed-node floor only on a managed node and an
//     individual node keeps full local control;
//   - the GUARD FLOOR the organization holds on a managed node: the local
//     [guard] / [guard.prompt] switches that may not be set below it
//     (config.Load applies it as its last step, so every reader, hook and
//     daemon alike, sees the floored config);
//   - the LAST VERIFIED org inputs: the signed org policy bundle envelope the
//     daemon accepted under the enrolment key pin, the pin itself, and the
//     exact governance sidecar (+ exceptions) bytes the daemon wrote. A reader
//     whose on-disk copies no longer verify falls back to these instead of
//     running without the org layer.
//
// The honesty framing is the posture's (auth.go): the key sits beside the
// file, so a same-user process that reads the key can forge a lock. What the
// MAC buys is that a plain edit, a strip loop or a deletion no longer works:
// readers refuse the edit and fall back, and the daemon repairs the file and
// records a high guard_error event within one posture interval.

// OrgLockFilename is the lock file's basename, beside the global config.
const OrgLockFilename = "guard-org-lock.json"

// OrgLockSchema is the lock file's schema version.
const OrgLockSchema = 1

// orgLockMACDomain separates the lock MAC from the posture MAC under the
// shared key.
const orgLockMACDomain = "sbo-guard-org-lock-v1"

// maxOrgLockBytes bounds a lock read. The lock embeds the org bundle
// envelope and the governance sidecar (64 KiB each at most), so it is larger
// than the posture.
const maxOrgLockBytes = 512 << 10

// Guard modes in strictness order, the vocabulary GuardFloor.Mode uses (the
// [guard].mode values).
const (
	ModeOff     = "off"
	ModeObserve = "observe"
	ModeEnforce = "enforce"
)

// GuardFloor is the minimum local guard configuration a managed node's
// organization holds. The zero value floors nothing.
type GuardFloor struct {
	// Enabled floors [guard].enabled at true.
	Enabled bool `json:"enabled,omitempty"`
	// Mode floors [guard].mode ("" = no floor; "observe" = never off;
	// "enforce" = the org pinned enforce).
	Mode string `json:"mode,omitempty"`
	// PromptEnabled floors [guard.prompt].enabled and hook_lane at true: the
	// organization pinned a prompt rule, so the prompt-submit lane must run.
	PromptEnabled bool `json:"prompt_enabled,omitempty"`
	// PromptEnforceIndependent floors [guard.prompt].enforce_independent at
	// true: an org prompt pin can stop a prompt, so the lane must enforce on
	// its own even when the global mode is observe.
	PromptEnforceIndependent bool `json:"prompt_enforce_independent,omitempty"`
	// PromptMode floors the global [guard.prompt].mode ("" = no floor) and,
	// with it, every per-detector override that switches a detector the
	// shipped default set does not ship off back to that default (T-864 gap
	// 2: a local "off"/"warn" no longer switches the prompt guard off on a
	// managed node). It is PromptModeFloor whenever set,
	// the exact value the org's local_weakening check accepts.
	PromptMode string `json:"prompt_mode,omitempty"`
}

// IsZero reports whether the floor holds nothing.
func (f GuardFloor) IsZero() bool { return f == GuardFloor{} }

// PromptModeFloor is the global prompt mode a managed node's floor raises a
// weaker local mode to. It must equal orgcontract.LocalGuardPromptFloor, the
// value the org's local_weakening check accepts; guardposture stays stdlib
// only, so internal/config's tests pin the two together.
const PromptModeFloor = "redact"

// ConservativeFloor is the floor a reader applies when the lock exists but
// cannot be verified while an org layer is plausible: the guard stays on and
// never off, and the prompt lane stays on. It never raises the mode to
// enforce (an unknown org floor is not known to enforce).
var ConservativeFloor = GuardFloor{Enabled: true, Mode: ModeObserve, PromptEnabled: true, PromptMode: PromptModeFloor}

// OrgLock is guard-org-lock.json.
type OrgLock struct {
	Schema int `json:"schema"`
	// Managed is the tenancy the daemon resolved (Enterprise-Managed
	// Tenancy on the org's signed enrolment grant).
	Managed bool `json:"managed"`
	// Floor is the organization's guard floor (zero on an individual node).
	Floor GuardFloor `json:"floor"`
	// KeyPinHash is the enrolment key pin the bundle was verified under.
	KeyPinHash string `json:"key_pin_hash,omitempty"`
	// Bundle is the last verified signed org policy bundle envelope, the
	// exact JSON the daemon accepted ("" = none). It stays Ed25519-verifiable
	// on its own; the MAC adds that THIS daemon accepted it.
	Bundle string `json:"bundle,omitempty"`
	// BundleExpected says this node has accepted a verified org bundle
	// (T-864 gap 1): the daemon holds one, or its store recorded one. A
	// MISSING bundle file is then a deletion, not "nothing published": a
	// managed node keeps the last verified layer (Bundle) and, with none,
	// refuses local approvals for every rule until a verified bundle
	// arrives.
	BundleExpected bool `json:"bundle_expected,omitempty"`
	// GovernanceKnown says Governance / GovernanceExceptions are the daemon's
	// own last write. False (a daemon that has not written yet) leaves the
	// on-disk governance files in charge, as before this file existed.
	GovernanceKnown bool `json:"governance_known,omitempty"`
	// Governance is the exact governance-effective.json bytes the daemon last
	// wrote ("" with GovernanceKnown = no sidecar).
	Governance string `json:"governance,omitempty"`
	// GovernanceExceptions is the exact governance-exceptions.json bytes the
	// daemon last wrote ("" = none in force).
	GovernanceExceptions string `json:"governance_exceptions,omitempty"`
	// WrittenAt is when the daemon wrote the file (informational: the lock
	// has no freshness window, it is the LAST verified state and must
	// outlive a stopped daemon).
	WrittenAt time.Time `json:"written_at"`
	// MAC is the daemon's HMAC-SHA256 over every other field.
	MAC string `json:"mac,omitempty"`
}

// OrgLockPath returns the lock file beside the resolved global config path
// ("" when configPath is empty).
func OrgLockPath(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), OrgLockFilename)
}

// orgLockCanonical is the MAC input: the domain, then the JSON of the lock
// with no MAC (encoding/json renders struct fields in declaration order, so
// the encoding is deterministic).
func orgLockCanonical(l OrgLock) []byte {
	l.MAC = ""
	l.Schema = OrgLockSchema
	l.WrittenAt = l.WrittenAt.UTC()
	body, _ := json.Marshal(l)
	var b bytes.Buffer
	b.WriteString(orgLockMACDomain)
	b.WriteByte('\n')
	b.Write(body)
	return b.Bytes()
}

func orgLockMAC(l OrgLock, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(orgLockCanonical(l))
	return hex.EncodeToString(h.Sum(nil))
}

// SignOrgLock returns l normalized and carrying its MAC under key.
func SignOrgLock(l OrgLock, key []byte) OrgLock {
	l.Schema = OrgLockSchema
	l.WrittenAt = l.WrittenAt.UTC()
	l.MAC = orgLockMAC(l, key)
	return l
}

// VerifyOrgLock reports whether l carries a valid MAC under key.
func VerifyOrgLock(l *OrgLock, key []byte) bool {
	if l == nil || len(key) == 0 || l.MAC == "" {
		return false
	}
	want, err := hex.DecodeString(l.MAC)
	if err != nil {
		return false
	}
	got, _ := hex.DecodeString(orgLockMAC(*l, key))
	return hmac.Equal(want, got)
}

// EncodeOrgLock renders a signed lock as the bytes WriteOrgLock stores.
func EncodeOrgLock(l OrgLock) ([]byte, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("guardposture.EncodeOrgLock: %w", err)
	}
	return data, nil
}

// WriteOrgLock signs l under key and replaces the lock file atomically
// (temp + rename, 0600), returning the exact bytes written.
func WriteOrgLock(path string, l OrgLock, key []byte) ([]byte, error) {
	if path == "" {
		return nil, errors.New("guardposture.WriteOrgLock: empty path")
	}
	if len(key) == 0 {
		return nil, errors.New("guardposture.WriteOrgLock: no key")
	}
	data, err := EncodeOrgLock(SignOrgLock(l, key))
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(path, data, ".guard-org-lock-*.tmp"); err != nil {
		return nil, fmt.Errorf("guardposture.WriteOrgLock: %w", err)
	}
	return data, nil
}

// ReadOrgLock loads a lock file. A missing file is (nil, nil).
func ReadOrgLock(path string) (*OrgLock, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) //nolint:gosec // the path is resolved from the node's own config location
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("guardposture.ReadOrgLock: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxOrgLockBytes+1))
	if err != nil {
		return nil, fmt.Errorf("guardposture.ReadOrgLock: %w", err)
	}
	if len(data) > maxOrgLockBytes {
		return nil, errors.New("guardposture.ReadOrgLock: lock file too large")
	}
	var out OrgLock
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("guardposture.ReadOrgLock: %w", err)
	}
	if out.Schema != OrgLockSchema {
		return nil, errors.New("guardposture.ReadOrgLock: unsupported schema")
	}
	return &out, nil
}

// OrgLockState is the outcome of loading the lock for a decision.
type OrgLockState int

const (
	// OrgLockAbsent: no daemon on this node writes a lock (no key, or a
	// verified posture from a daemon that predates the lock). Readers behave
	// exactly as before the lock existed.
	OrgLockAbsent OrgLockState = iota
	// OrgLockValid: the lock verifies under the key.
	OrgLockValid
	// OrgLockTampered: a lock is expected (or present) but does not verify:
	// edited, replaced, deleted. Readers fail closed (ConservativeFloor where
	// an org layer is plausible, the conservative tenancy reading) and the
	// daemon repairs it and reports the tamper.
	OrgLockTampered
)

// String names the state for logs and status lines.
func (s OrgLockState) String() string {
	switch s {
	case OrgLockValid:
		return "valid"
	case OrgLockTampered:
		return "tampered"
	default:
		return "absent"
	}
}

// OrgLockLoaded is a lock load result.
type OrgLockLoaded struct {
	State OrgLockState
	Lock  *OrgLock
	// Detail says why a lock is tampered ("" otherwise).
	Detail string
}

// orgLockExpectation rows decide, for a MISSING lock, whether one was
// expected (CLAUDE.md rule 5: an ordered table, first match wins). The
// posture is the anchor: a daemon that writes the lock says so in its MAC'd
// posture, so an older daemon (no flag) never makes a new hook read "tampered".
var orgLockExpectation = []struct {
	name     string
	match    func(key []byte, posture Loaded) bool
	expected bool
}{
	{"no key: no daemon has published here", func(key []byte, _ Loaded) bool { return key == nil }, false},
	{"verified posture from a daemon that writes no lock", func(_ []byte, p Loaded) bool {
		return p.State == StateValid && p.Posture != nil && !p.Posture.OrgLock
	}, false},
	{"verified posture that says a lock is written", func(_ []byte, p Loaded) bool {
		return p.State == StateValid && p.Posture != nil && p.Posture.OrgLock
	}, true},
	{"key made by an accept before any posture was published", func(_ []byte, p Loaded) bool {
		return p.State == StateAbsent && p.Unpublished
	}, false},
	{"key present, posture missing or unverifiable", func(_ []byte, _ Loaded) bool { return true }, true},
}

// LoadOrgLock reads and authenticates the lock beside the resolved global
// config path. It never errors: every failure is a state.
func LoadOrgLock(configPath string) OrgLockLoaded {
	if configPath == "" {
		return OrgLockLoaded{State: OrgLockAbsent}
	}
	keyPath := KeyPath(configPath)
	key, kerr := ReadKey(keyPath)
	l, lerr := ReadOrgLock(OrgLockPath(configPath))
	switch {
	case lerr != nil:
		return OrgLockLoaded{State: OrgLockTampered, Detail: "org lock unreadable: " + lerr.Error()}
	case kerr != nil:
		if l == nil {
			return OrgLockLoaded{State: OrgLockAbsent}
		}
		return OrgLockLoaded{State: OrgLockTampered, Detail: "key unreadable: " + kerr.Error()}
	case l == nil:
		posture := Load(PosturePath(configPath), keyPath)
		for _, row := range orgLockExpectation {
			if row.match(key, posture) {
				if row.expected {
					return OrgLockLoaded{State: OrgLockTampered, Detail: "org lock missing (" + row.name + ")"}
				}
				return OrgLockLoaded{State: OrgLockAbsent}
			}
		}
		return OrgLockLoaded{State: OrgLockAbsent}
	case key == nil:
		return OrgLockLoaded{State: OrgLockTampered, Detail: "org lock present without its key"}
	case !VerifyOrgLock(l, key):
		return OrgLockLoaded{State: OrgLockTampered, Detail: "org lock does not verify under its key"}
	default:
		return OrgLockLoaded{State: OrgLockValid, Lock: l}
	}
}

// guardModeRank orders the [guard].mode vocabulary by strictness.
var guardModeRank = map[string]int{ModeOff: 0, ModeObserve: 1, ModeEnforce: 2}

// GuardModeBelow reports whether local is a weaker [guard].mode than floor
// ("" floor holds nothing; an unknown local value counts as off).
func GuardModeBelow(local, floor string) bool {
	f, ok := guardModeRank[floor]
	if !ok || floor == "" {
		return false
	}
	return guardModeRank[local] < f
}

// FloorInputs is what the daemon knows about the organization's hold on its
// guard when it derives the floor.
type FloorInputs struct {
	// Managed is the resolved tenancy.
	Managed bool
	// OrgLayer reports a verified org policy bundle in force.
	OrgLayer bool
	// PromptFloor reports an org-pinned prompt-rule decision.
	PromptFloor bool
	// PromptFloorStops reports that pin can stop a prompt (block or ask).
	PromptFloorStops bool
	// Pinned is the governance pins in force (guard.enabled / guard.mode are
	// the keys read here).
	Pinned map[string]any
}

// floorRules derive the floor from the inputs, walked in order (CLAUDE.md
// rule 5). Each row reads the inputs and may raise one part of the floor.
var floorRules = []struct {
	name  string
	apply func(in FloorInputs, f *GuardFloor)
}{
	{"an org guard layer or a guard pin keeps the guard and the prompt guard on", func(in FloorInputs, f *GuardFloor) {
		if in.OrgLayer || pinnedBool(in.Pinned, "guard.enabled") || pinnedMode(in.Pinned) != "" {
			f.Enabled = true
			f.Mode = ModeObserve
			// The prompt guard is held the same way (T-864 gap 2): the
			// org's local_weakening check treats a managed node's prompt
			// guard off or loosened as a weakening, so the floor keeps it
			// at that check's own floor instead of only reporting it.
			f.PromptEnabled = true
			f.PromptMode = PromptModeFloor
		}
	}},
	{"a pinned guard.mode is the mode floor", func(in FloorInputs, f *GuardFloor) {
		if m := pinnedMode(in.Pinned); m != "" && guardModeRank[m] > guardModeRank[f.Mode] {
			f.Mode = m
		}
	}},
	{"an org prompt pin keeps the prompt lane on", func(in FloorInputs, f *GuardFloor) {
		if in.PromptFloor {
			f.Enabled, f.PromptEnabled = true, true
			f.PromptMode = PromptModeFloor
			if f.Mode == "" {
				f.Mode = ModeObserve
			}
		}
	}},
	{"a stopping org prompt pin keeps prompt enforcement on", func(in FloorInputs, f *GuardFloor) {
		if in.PromptFloorStops {
			f.PromptEnforceIndependent = true
		}
	}},
}

// DeriveFloor is the ONE derivation of a managed node's guard floor. An
// individual node (Managed=false) and an organization that pinned the guard
// OFF (guard.enabled=false, or guard.mode="off") get the zero floor: the
// floor only ever keeps the organization's own posture, it never raises a
// node above what the organization asked for.
func DeriveFloor(in FloorInputs) GuardFloor {
	if !in.Managed {
		return GuardFloor{}
	}
	if v, ok := in.Pinned["guard.enabled"].(bool); ok && !v {
		return GuardFloor{}
	}
	if m, ok := in.Pinned["guard.mode"].(string); ok && m == ModeOff {
		return GuardFloor{}
	}
	var f GuardFloor
	for _, r := range floorRules {
		r.apply(in, &f)
	}
	return f
}

func pinnedBool(pinned map[string]any, key string) bool {
	v, ok := pinned[key].(bool)
	return ok && v
}

func pinnedMode(pinned map[string]any) string {
	m, ok := pinned["guard.mode"].(string)
	if !ok || (m != ModeObserve && m != ModeEnforce) {
		return ""
	}
	return m
}
