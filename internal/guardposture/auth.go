package guardposture

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Posture authentication (Sol A2-02).
//
// The posture file is read by the hook process, which runs as the same OS
// user as the coding agent it guards, so file permissions cannot stop that
// agent from rewriting the file. What this layer buys, honestly:
//
//   - A posture that was hand-edited, replaced by a generic JSON writer,
//     truncated or deleted no longer verifies. The hook treats an
//     unverifiable posture as TAMPERED and IGNORES it (D-188 / D-193): it
//     computes enforcement itself from the config and the signed org bundle,
//     exactly as when no daemon ever published. So a forged "not enforced"
//     posture cannot open a gate the config or the org enforces, and a
//     forged "enforced" posture cannot close one on a node that does not
//     enforce. (An earlier design closed every wired gate on a tamper; that
//     was reversed because it blocked non-enforcing nodes.)
//   - The daemon, the one writer, re-checks the file and the key on every
//     publish interval, repairs a mismatch and records it as a guard event
//     that reaches the org.
//
// What it does NOT buy: the HMAC key sits beside the posture, readable by
// the same user, because the hook must verify without a daemon round trip.
// A same-user process that reads the key can sign any posture; the daemon
// repairs that on its next interval (docs/security.md HOOKFAIL-2 names the
// window). Under tool-gate enforcement the integrity rule R-160 also
// denies agent writes under ~/.observer, where both files live.

// KeyFilename is the posture HMAC key's basename, beside the posture.
const KeyFilename = "guard-posture.key"

// macDomain separates this MAC from any other use of the key.
const macDomain = "sbo-guard-posture-v1"

// keyBytes is the key length.
const keyBytes = 32

// KeyPath returns the key file beside the resolved global config path.
func KeyPath(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), KeyFilename)
}

// ReadKey loads the key file. A missing file is (nil, nil); a malformed one
// is an error.
func ReadKey(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("guardposture.ReadKey: %w", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != keyBytes {
		return nil, errors.New("guardposture.ReadKey: malformed key file")
	}
	return key, nil
}

// LoadOrCreateKey returns the key at path, creating a fresh random one when
// the file is missing or malformed. Daemon only (the one writer).
func LoadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("guardposture.LoadOrCreateKey: empty path")
	}
	if key, err := ReadKey(path); err == nil && key != nil {
		return key, nil
	}
	return WriteNewKey(path)
}

// UnpublishedFilename marks a posture key that was created before any
// posture was published: an accept path (the developer's database or
// disclosure accept, which signs its consent record with this key) ran on a
// fresh node before the first `observer start`. While the marker verifies
// under the key, a key with no posture reads as not yet initialised
// (StateAbsent, Loaded.Unpublished), not as tampered (live check macOS
// 2026-10-22, D4: the next start logged "guard posture: tamper detected"
// and "org lock tamper detected"). The daemon's first posture write removes
// the marker, so a posture removed after one existed still reads as
// tampered. Forging the marker gains nothing a deleted key does not
// already give (no key and no posture also reads absent).
const UnpublishedFilename = "guard-posture.unpublished"

// unpublishedDomain separates the marker's MAC from the posture's.
const unpublishedDomain = "sbo-guard-posture-unpublished-v1"

func unpublishedPath(dir string) string { return filepath.Join(dir, UnpublishedFilename) }

func unpublishedMAC(key []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(unpublishedDomain))
	return hex.EncodeToString(m.Sum(nil))
}

// unpublishedMarked reports whether the marker beside keyPath verifies
// under key.
func unpublishedMarked(keyPath string, key []byte) bool {
	if keyPath == "" || len(key) == 0 {
		return false
	}
	raw, err := os.ReadFile(unpublishedPath(filepath.Dir(keyPath))) //nolint:gosec // G304: the marker beside the resolved key path
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return false
	}
	got, _ := hex.DecodeString(unpublishedMAC(key))
	return hmac.Equal(want, got)
}

// LoadOrCreateKeyBeforePosture is LoadOrCreateKey for an accept path that
// is not the daemon: when it creates the key and no posture exists beside
// it yet, it marks the key unpublished (UnpublishedFilename).
func LoadOrCreateKeyBeforePosture(keyPath string) ([]byte, error) {
	if keyPath == "" {
		return nil, errors.New("guardposture.LoadOrCreateKeyBeforePosture: empty path")
	}
	if key, err := ReadKey(keyPath); err == nil && key != nil {
		return key, nil
	}
	dir := filepath.Dir(keyPath)
	_, postErr := os.Lstat(filepath.Join(dir, PostureFilename))
	key, err := WriteNewKey(keyPath)
	if err != nil {
		return nil, err
	}
	if errors.Is(postErr, os.ErrNotExist) {
		if err := writeAtomic(unpublishedPath(dir), []byte(unpublishedMAC(key)+"\n"), ".guard-posture-unpublished-*.tmp"); err != nil {
			return nil, fmt.Errorf("guardposture.LoadOrCreateKeyBeforePosture: %w", err)
		}
	}
	return key, nil
}

// WriteNewKey writes a fresh random key to path (atomic, 0600) and returns
// it.
func WriteNewKey(path string) ([]byte, error) {
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("guardposture.WriteNewKey: %w", err)
	}
	if err := WriteKey(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// WriteKey writes key to path (atomic, 0600).
func WriteKey(path string, key []byte) error {
	if len(key) != keyBytes {
		return errors.New("guardposture.WriteKey: bad key length")
	}
	if err := writeAtomic(path, []byte(hex.EncodeToString(key)+"\n"), ".guard-posture-key-*.tmp"); err != nil {
		return fmt.Errorf("guardposture.WriteKey: %w", err)
	}
	return nil
}

// canonical is the MAC input: every field of the normalized posture except
// the MAC itself, in a fixed order and spelling.
func canonical(p Posture) []byte {
	return canonicalForm(p, true)
}

// canonicalForm is canonical with or without the tenancy fields. A binary
// before task PT-01 signed without them (legacy), so Managed and
// TenancyRecorded were outside the MAC; withTenancy=false rebuilds that
// form for the compatibility read in Load.
func canonicalForm(p Posture, withTenancy bool) []byte {
	p = normalize(p)
	var b bytes.Buffer
	b.WriteString(macDomain)
	b.WriteByte('\n')
	b.WriteString(strconv.Itoa(p.Schema))
	b.WriteByte('\n')
	b.WriteString(strconv.FormatBool(p.Enforced))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(p.Source))
	b.WriteByte('\n')
	b.WriteString(strconv.Quote(p.Generation))
	b.WriteByte('\n')
	for _, c := range p.GateCaps {
		b.WriteString(strconv.Quote(c))
		b.WriteByte(',')
	}
	b.WriteByte('\n')
	b.WriteString(p.WrittenAt.UTC().Format(time.RFC3339Nano))
	// Fields added after schema 1 are appended ONLY when set, so a posture
	// that does not use them keeps the exact MAC an older binary computes
	// (a mixed-version hook and daemon still verify each other's files).
	if p.UserPolicyFailClosed {
		b.WriteString("\nuser_policy_fail_closed")
	}
	if p.OrgLock {
		b.WriteString("\norg_lock")
	}
	if p.SecurityRecorded {
		b.WriteString("\nsecurity_recorded")
	}
	if p.SecurityActive {
		b.WriteString("\nsecurity_active")
	}
	// The tenancy fields (task PT-01), last and only when set, like every
	// field after schema 1: a posture with neither keeps the legacy MAC.
	if withTenancy && p.Managed {
		b.WriteString("\nmanaged")
	}
	if withTenancy && p.TenancyRecorded {
		b.WriteString("\ntenancy_recorded")
	}
	// The security pack set (lane SEC-GATEFIX), only when set: a posture
	// without it keeps the MAC every earlier binary computes. It is part of
	// both forms: no binary before PT-01 wrote it, so the legacy read gains
	// nothing from it.
	if len(p.SecurityPacks) > 0 {
		b.WriteString("\nsecurity_packs=")
		for _, id := range p.SecurityPacks {
			b.WriteString(strconv.Quote(id))
			b.WriteByte(',')
		}
	}
	// The commit gate floor bit (audit SEC-P4 F2), only when set, in both
	// forms like the pack set: no earlier binary wrote it.
	if p.CommitGateFloorHeld {
		b.WriteString("\ncommit_gate_floor_held")
	}
	// The organization's prompt judge (lane adm-2), only when set, in both
	// forms: no earlier binary wrote them, so a posture without them keeps
	// the MAC every earlier binary computes.
	if p.PromptJudgeActive {
		b.WriteString("\nprompt_judge_active")
	}
	if p.PromptJudgeFailClosed {
		b.WriteString("\nprompt_judge_fail_closed")
	}
	return b.Bytes()
}

func mac(p Posture, key []byte) string {
	return macForm(p, key, true)
}

func macForm(p Posture, key []byte, withTenancy bool) string {
	h := hmac.New(sha256.New, key)
	h.Write(canonicalForm(p, withTenancy))
	return hex.EncodeToString(h.Sum(nil))
}

// Sign returns p normalized and carrying its MAC under key.
func Sign(p Posture, key []byte) Posture {
	p = normalize(p)
	p.MAC = mac(p, key)
	return p
}

// Verify reports whether p carries a valid MAC under key.
func Verify(p *Posture, key []byte) bool {
	return verifyForm(p, key, true)
}

func verifyForm(p *Posture, key []byte, withTenancy bool) bool {
	if p == nil || len(key) == 0 || p.MAC == "" {
		return false
	}
	want, err := hex.DecodeString(p.MAC)
	if err != nil {
		return false
	}
	got, _ := hex.DecodeString(macForm(*p, key, withTenancy))
	return hmac.Equal(want, got)
}

// verifyLegacy is the compatibility read for a posture a binary before
// task PT-01 signed, whose MAC did not cover Managed and TenancyRecorded.
// When only that form verifies, the two fields are unauthenticated, so
// they are cleared: the posture reads as an older daemon's that never
// recorded its tenancy, and a flipped Managed bit gains nothing. A posture
// signed in the current form with either field set never verifies here
// (its MAC covers them), so a current file cannot be downgraded.
func verifyLegacy(p *Posture, key []byte) bool {
	if p == nil || (!p.Managed && !p.TenancyRecorded) || !verifyForm(p, key, false) {
		return false
	}
	p.Managed, p.TenancyRecorded = false, false
	return true
}

// State is the outcome of loading the posture for a decision.
type State int

const (
	// StateAbsent: no posture and no key. No daemon has published on this
	// node; the reader falls back to its own configuration.
	StateAbsent State = iota
	// StateValid: the posture verifies under the key.
	StateValid
	// StateTampered: a posture or key exists but the pair does not verify
	// (edited, replaced, truncated, deleted, or written by a binary that
	// predates authentication). Readers ignore it and fall back to the
	// config, as for StateAbsent; the daemon repairs it and reports the
	// tamper.
	StateTampered
)

// String names the state for logs.
func (s State) String() string {
	switch s {
	case StateValid:
		return "valid"
	case StateTampered:
		return "tampered"
	default:
		return "absent"
	}
}

// Loaded is a posture load result.
type Loaded struct {
	State   State
	Posture *Posture
	// Detail says why a posture is tampered ("" otherwise).
	Detail string
	// Legacy reports a valid posture signed before the tenancy fields
	// joined the MAC (task PT-01); its Managed and TenancyRecorded were
	// cleared as unauthenticated. The daemon's next publish replaces it.
	Legacy bool
	// Unpublished reports StateAbsent for a key that an accept path made
	// before any posture was published (UnpublishedFilename): not yet
	// initialised, not tampered.
	Unpublished bool
}

// Load reads and authenticates the posture at posturePath with the key at
// keyPath.
func Load(posturePath, keyPath string) Loaded {
	key, kerr := ReadKey(keyPath)
	p, perr := Read(posturePath)
	switch {
	case perr != nil:
		return Loaded{State: StateTampered, Detail: "posture unreadable: " + perr.Error()}
	case kerr != nil:
		return Loaded{State: StateTampered, Detail: "key unreadable: " + kerr.Error()}
	case p == nil && key == nil:
		return Loaded{State: StateAbsent}
	case p == nil && unpublishedMarked(keyPath, key):
		return Loaded{State: StateAbsent, Unpublished: true}
	case p == nil:
		return Loaded{State: StateTampered, Detail: "posture missing while its key exists"}
	case key == nil:
		return Loaded{State: StateTampered, Detail: "posture present without its key"}
	case !Verify(p, key):
		if verifyLegacy(p, key) {
			return Loaded{State: StateValid, Posture: p, Legacy: true}
		}
		return Loaded{State: StateTampered, Detail: "posture does not verify under its key"}
	default:
		return Loaded{State: StateValid, Posture: p}
	}
}
