package sandboxopenshell

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
)

// gateway_custody.go is the managed gateway's key custody (risk RK-20):
// the private gateway's PKI (its CA, server and client certificates and
// keys, and the sandbox JWT signing key) and its credential-store
// key-encryption key are held in internal/keystore, in one of two
// custodies, recorded at the first save and never changed silently
// (GatewayLayout.CustodyPath, lifecycle row G7):
//
//   - CustodyKeychain: the OS keychain (OS-backed encryption at rest); no
//     key material is ever a file under the row's state dir.
//   - CustodyOwnerFile: where no keychain is usable (a headless Linux host
//     with no Secret Service, the only host class measured), the
//     keystore's hardened owner-only file store under <state dir>/
//     gateway/keys. Those files are 0600 in a 0700 dir and NOT encrypted:
//     the PKI (the CA key included) and the key-encryption key sit on disk
//     beside the database that key protects, so against the local user
//     they are no stronger than the user's own OpenShell install. The
//     probe hint, the run's posture note and the operator doc say so
//     (audit finding O2-A1, decision OB-050).
//
// While the gateway runs, the driver also restores the PKI into the
// private runtime dir (a RAM filesystem owned by the user, mode 0700;
// GatewayRuntimeFS) for the gateway and its CLI to read, and writes the
// key-encryption key into that dir's owner-only EnvironmentFile for the
// user manager (GatewayEnvFile); both are removed when the gateway stops.
// The key never reaches a command line, the transient unit file or
// `systemctl --user show`. Nothing here logs a value.
//
// The record set is closed: exactly the nine files `openshell-gateway
// generate-certs --output-dir` writes at v0.1.6
// (crates/openshell-server/src/certgen.rs LocalPaths), plus a manifest
// that names each file's digest. The manifest is written last and read
// first, so a partial save reads as no custody, and a record that does not
// match its digest refuses the restore.

// PKIFiles are the gateway PKI's files, relative to its TLS dir
// (OPENSHELL_LOCAL_TLS_DIR), as v0.1.6 lays them out.
var PKIFiles = []string{
	"ca.crt", "ca.key",
	"server/tls.crt", "server/tls.key",
	"client/tls.crt", "client/tls.key",
	"jwt/signing.pem", "jwt/public.pem", "jwt/kid",
}

// PKISecretFiles are the files of PKIFiles a restore writes 0600 (every
// other one is written 0644 inside the 0700 dir).
var PKISecretFiles = map[string]bool{"ca.key": true, "server/tls.key": true, "client/tls.key": true, "jwt/signing.pem": true}

// KEKBytes is the key-encryption key's length (the gateway's credential
// store takes exactly 32 bytes, base64-encoded, from the variable).
const KEKBytes = 32

// GatewayKEKEnv is the variable the private gateway reads its
// key-encryption key from (key_encryption_key_env): letters, digits and
// underscores only, as the gateway requires.
const GatewayKEKEnv = "OBSERVER_OPENSHELL_GATEWAY_KEK"

// maxPKIFile caps one PKI file (a PEM certificate or key is a few KiB).
const maxPKIFile = 16 << 10

// CustodyStore is the keystore as the custody code sees it. The driver
// adapts internal/keystore to it (Load reports ok false for a missing
// record, never an error).
type CustodyStore interface {
	Load(name string) (value string, ok bool, err error)
	Save(name, value string) error
	Remove(name string) error
}

// ErrNoCustody means no complete PKI is held yet (a first start generates
// one).
var ErrNoCustody = errors.New("sandboxopenshell: no managed gateway PKI is held in the keystore yet")

// ErrCustodyCorrupt refuses a held PKI whose records do not match their
// manifest.
var ErrCustodyCorrupt = errors.New("sandboxopenshell: the managed gateway PKI in the keystore does not match its manifest")

// custodyManifest is the manifest record.
type custodyManifest struct {
	Version int               `json:"version"`
	Files   map[string]string `json:"files"`
}

// custodyPrefix is the record name prefix of one install's gateway.
func custodyPrefix(id GatewayIdentity) string { return "gateway." + id.Name + "." }

// pkiRecordName is the record of one PKI file ("/" is not a record name
// character; ":" is).
func pkiRecordName(id GatewayIdentity, rel string) string {
	b := []byte(rel)
	for i := range b {
		if b[i] == '/' {
			b[i] = ':'
		}
	}
	return custodyPrefix(id) + "pki." + string(b)
}

// manifestRecordName is the manifest's record.
func manifestRecordName(id GatewayIdentity) string { return custodyPrefix(id) + "pki-manifest" }

// kekRecordName is the key-encryption key's record.
func kekRecordName(id GatewayIdentity) string { return custodyPrefix(id) + "kek" }

// CustodyRecordNames lists every record name of one install's gateway (for
// a reset and for tests).
func CustodyRecordNames(id GatewayIdentity) []string {
	out := []string{manifestRecordName(id), kekRecordName(id)}
	for _, f := range PKIFiles {
		out = append(out, pkiRecordName(id, f))
	}
	return out
}

// SavePKI stores a complete PKI set: every file of PKIFiles, nothing else,
// each at most 16 KiB. Files go first and the manifest last.
func SavePKI(s CustodyStore, id GatewayIdentity, files map[string][]byte) error {
	if len(files) != len(PKIFiles) {
		return fmt.Errorf("sandboxopenshell.SavePKI: %d files, want exactly the %d of the gateway PKI", len(files), len(PKIFiles))
	}
	man := custodyManifest{Version: 1, Files: map[string]string{}}
	for _, rel := range PKIFiles {
		b, ok := files[rel]
		if !ok {
			return fmt.Errorf("sandboxopenshell.SavePKI: the PKI lacks %s", rel)
		}
		if len(b) == 0 || len(b) > maxPKIFile {
			return fmt.Errorf("sandboxopenshell.SavePKI: %s is empty or larger than 16 KiB", rel)
		}
		sum := sha256.Sum256(b)
		man.Files[rel] = hex.EncodeToString(sum[:])
		if err := s.Save(pkiRecordName(id, rel), base64.StdEncoding.EncodeToString(b)); err != nil {
			return fmt.Errorf("sandboxopenshell.SavePKI: store %s: %w", rel, err)
		}
	}
	mb, err := json.Marshal(man)
	if err != nil {
		return fmt.Errorf("sandboxopenshell.SavePKI: %w", err)
	}
	if err := s.Save(manifestRecordName(id), string(mb)); err != nil {
		return fmt.Errorf("sandboxopenshell.SavePKI: store the manifest: %w", err)
	}
	return nil
}

// LoadPKI returns the held PKI set, ErrNoCustody when no manifest is held,
// or ErrCustodyCorrupt when a record is missing or does not match.
func LoadPKI(s CustodyStore, id GatewayIdentity) (map[string][]byte, error) {
	raw, ok, err := s.Load(manifestRecordName(id))
	if err != nil {
		return nil, fmt.Errorf("sandboxopenshell.LoadPKI: %w", err)
	}
	if !ok {
		return nil, ErrNoCustody
	}
	var man custodyManifest
	if err := json.Unmarshal([]byte(raw), &man); err != nil || man.Version != 1 || len(man.Files) != len(PKIFiles) {
		return nil, ErrCustodyCorrupt
	}
	out := make(map[string][]byte, len(PKIFiles))
	for _, rel := range PKIFiles {
		want, ok := man.Files[rel]
		if !ok {
			return nil, ErrCustodyCorrupt
		}
		v, ok, err := s.Load(pkiRecordName(id, rel))
		if err != nil {
			return nil, fmt.Errorf("sandboxopenshell.LoadPKI: %w", err)
		}
		if !ok {
			return nil, ErrCustodyCorrupt
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return nil, ErrCustodyCorrupt
		}
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return nil, ErrCustodyCorrupt
		}
		out[rel] = b
	}
	return out, nil
}

// LoadOrCreateKEK returns the held key-encryption key (base64), creating
// one from rnd on the first call. The value is exactly what the gateway
// reads from GatewayKEKEnv.
func LoadOrCreateKEK(s CustodyStore, id GatewayIdentity, rnd io.Reader) (string, error) {
	v, ok, err := s.Load(kekRecordName(id))
	if err != nil {
		return "", fmt.Errorf("sandboxopenshell.LoadOrCreateKEK: %w", err)
	}
	if ok {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(b) != KEKBytes {
			return "", fmt.Errorf("sandboxopenshell.LoadOrCreateKEK: the held key-encryption key is not %d bytes of base64", KEKBytes)
		}
		return v, nil
	}
	b := make([]byte, KEKBytes)
	if _, err := io.ReadFull(rnd, b); err != nil {
		return "", fmt.Errorf("sandboxopenshell.LoadOrCreateKEK: %w", err)
	}
	v = base64.StdEncoding.EncodeToString(b)
	if err := s.Save(kekRecordName(id), v); err != nil {
		return "", fmt.Errorf("sandboxopenshell.LoadOrCreateKEK: %w", err)
	}
	return v, nil
}

// ForgetCustody removes every record of one install's gateway, the
// manifest first (so a half-done removal reads as no custody). It is the
// reset path: the next start generates a new PKI, so every run on the old
// gateway must have ended (the driver checks).
func ForgetCustody(s CustodyStore, id GatewayIdentity) error {
	var errs []error
	for _, n := range CustodyRecordNames(id) {
		if err := s.Remove(n); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// PKIDigest is a digest over the held PKI's file digests (the gateway
// record notes which PKI a gateway was started with, without a secret).
func PKIDigest(files map[string][]byte) string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, n := range names {
		sum := sha256.Sum256(files[n])
		_, _ = io.WriteString(h, n+"\x00"+hex.EncodeToString(sum[:])+"\n")
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
