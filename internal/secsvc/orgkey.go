//go:build !sbo_omit_security

package secsvc

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// orgkey.go is the node's half of the org finding dedupe key (security plan
// 4.5.1, lane LEFT-SHARED): the owner-only key file the security managed
// pull's follower keeps, the detection-time org_key memo, and the secret
// finding that carries it. It moved here from cmd/observer at the merge so
// the daemon's scans, both history scans (the CLI and the dashboard) and the
// end-to-end test share one owner (merge audit findings 5 and 8).
//
//   - A secret's value exists only at detection, so its org_key
//     (secfinding.OrgSecretKey under the held key) is computed there: the
//     detector's Identify (SecretIdentify) notes the version-tagged digest
//     beside the node-keyed identity, and OrgKeyMemo.SecretFinding stamps
//     it on the finding.
//   - The key file is the only place the key lives on the node: the managed
//     pull cache stores the signed body with the key stripped
//     (orgcontract.StripSecurityOrgDedupeKey).

// OrgDedupeKeyName is the key file in the security directory.
const OrgDedupeKeyName = "org_dedupe.key"

// orgDedupeFile is the key file's content.
type orgDedupeFile struct {
	Version int64  `json:"version"`
	Key     string `json:"key"`
}

// OrgDedupeFor is the key an applied security pull carries: nil when the
// pull is not in force, carries no policy or no key (the follower then
// removes the file).
func OrgDedupeFor(inForce bool, p *orgcontract.SecurityManagedPolicyV1) *orgcontract.SecurityOrgDedupe {
	if !inForce || p == nil {
		return nil
	}
	return p.OrgDedupe
}

// WriteOrgDedupeKey writes the key file in dir (0600, atomically), or with
// nil removes it. A malformed key is refused and writes nothing; the same
// key and version already on disk is a no-op.
func WriteOrgDedupeKey(dir string, d *orgcontract.SecurityOrgDedupe) error {
	if dir == "" {
		return errors.New("secsvc.WriteOrgDedupeKey: no security directory")
	}
	path := filepath.Join(dir, OrgDedupeKeyName)
	if d == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	want, err := d.KeyBytes()
	if err != nil || d.Version <= 0 {
		return errors.New("secsvc.WriteOrgDedupeKey: refusing a malformed org dedupe key")
	}
	if cur, ver, ok := ReadOrgDedupeKey(dir); ok && ver == d.Version && string(cur) == string(want) {
		return nil
	}
	b, err := json.Marshal(orgDedupeFile{Version: d.Version, Key: d.Key})
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(path, append(b, '\n'), fsatomic.Options{TempPattern: ".sec-org-dedupe-*.tmp"})
}

// ReadOrgDedupeKey reads the key file in dir: the key bytes and the
// version, ok false when there is none or it does not read.
func ReadOrgDedupeKey(dir string) ([]byte, int64, bool) {
	d, ok := ReadOrgDedupe(dir)
	if !ok {
		return nil, 0, false
	}
	key, err := d.KeyBytes()
	if err != nil {
		return nil, 0, false
	}
	return key, d.Version, true
}

// ReadOrgDedupe reads the key file in dir as the served shape (version and
// base64 key), ok false when there is none or it does not read. The managed
// pull cache restores a stripped body from it.
func ReadOrgDedupe(dir string) (orgcontract.SecurityOrgDedupe, bool) {
	if dir == "" {
		return orgcontract.SecurityOrgDedupe{}, false
	}
	raw, err := os.ReadFile(filepath.Join(dir, OrgDedupeKeyName))
	if err != nil || len(raw) > 4096 {
		return orgcontract.SecurityOrgDedupe{}, false
	}
	var f orgDedupeFile
	if json.Unmarshal(raw, &f) != nil || f.Version <= 0 {
		return orgcontract.SecurityOrgDedupe{}, false
	}
	d := orgcontract.SecurityOrgDedupe{Version: f.Version, Key: f.Key}
	if _, err := d.KeyBytes(); err != nil {
		return orgcontract.SecurityOrgDedupe{}, false
	}
	return d, true
}

// orgIdentityCap bounds an OrgKeyMemo.
const orgIdentityCap = 8192

// OrgKeyMemo maps a secret's node-keyed identity to its stored org_key,
// filled by SecretIdentify and read by SecretFinding in the same pass (a
// scan runs both in one process). The zero value is ready to use.
type OrgKeyMemo struct {
	mu sync.Mutex
	m  map[string]string
}

// Note records the org_key of one secret under the key held in dir now
// (nothing without a key file).
func (m *OrgKeyMemo) Note(dir, nodeIdentity, secretType, value string) {
	if m == nil || nodeIdentity == "" {
		return
	}
	key, version, ok := ReadOrgDedupeKey(dir)
	if !ok {
		return
	}
	stored := secfinding.StoredOrgKey(version, secfinding.OrgSecretKey(key, secretType, value))
	if stored == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil || len(m.m) >= orgIdentityCap {
		m.m = map[string]string{}
	}
	m.m[nodeIdentity] = stored
}

// For is the stored org_key noted for a node identity ("" when none).
func (m *OrgKeyMemo) For(nodeIdentity string) string {
	if m == nil {
		return ""
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.m[nodeIdentity]
}

// SecretFinding is secdetect.SecretFinding carrying the version-tagged
// org_key noted for the hit's identity. Every native secret finding path
// (the daemon's scans and the history scans) goes through it.
func (m *OrgKeyMemo) SecretFinding(in secdetect.FindingInput) (secfinding.Finding, bool) {
	f, ok := secdetect.SecretFinding(in)
	if ok {
		f.OrgKey = m.For(in.Hit.Identity)
	}
	return f, ok
}

// SecretIdentify returns the detector's Identify under the node finding key
// in dir (FindingKeyName, made on first use), noting each secret's org_key
// in m while the value is in hand. nil when the key cannot be read or made
// (then no secret finding is stored).
func SecretIdentify(dir string, m *OrgKeyMemo) (func(typ, value string) string, error) {
	if dir == "" {
		return nil, errors.New("secsvc.SecretIdentify: no security directory")
	}
	key, err := secposture.LoadOrCreateKey(filepath.Join(dir, FindingKeyName))
	if err != nil {
		return nil, err
	}
	return func(typ, value string) string {
		id, err := secfinding.SecretIdentity(key, typ, value)
		if err != nil {
			return ""
		}
		m.Note(dir, id.Value, typ, value)
		return id.Value
	}, nil
}
