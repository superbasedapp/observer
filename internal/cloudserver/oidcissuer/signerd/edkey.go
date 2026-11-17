package signerd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// Systemd credential names the document signer reads its Ed25519 keys from
// (LoadCredentialEncrypted=<name>:<path>), one per purpose.
const (
	EntitlementsKeyCredential = "entitlements-signing-key" //nolint:gosec // G101: a systemd credential NAME, not a credential
	AvailabilityKeyCredential = "availability-signing-key" //nolint:gosec // G101: a systemd credential NAME, not a credential
	HostAPIKeyCredential      = "host-api-signing-key"     //nolint:gosec // G101: a systemd credential NAME, not a credential
)

// readKeyFile reads a key-sized regular file that, off Windows, is readable
// by its owner only. Both signers' key loaders use it.
func readKeyFile(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxKeyFile {
		return nil, fmt.Errorf("%s is not a key-sized regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others (mode %o); make it 0600", path, fi.Mode().Perm())
	}
	return os.ReadFile(path) //nolint:gosec // G304: the operator-configured key path
}

// LoadEd25519Key reads an Ed25519 private key (PKCS#8 "PRIVATE KEY" PEM)
// from a file only its owner may read. Encrypted PEM is not supported: as for
// the OIDC key, decryption is the systemd credential's job.
func LoadEd25519Key(path string) (ed25519.PrivateKey, error) {
	raw, err := readKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("signerd.LoadEd25519Key: %w", err)
	}
	k, err := ParseEd25519KeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("signerd.LoadEd25519Key: %s: %w", path, err)
	}
	return k, nil
}

// ParseEd25519KeyPEM parses exactly one PKCS#8 Ed25519 private key PEM block.
func ParseEd25519KeyPEM(raw []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("signerd.ParseEd25519KeyPEM: no PEM block")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("signerd.ParseEd25519KeyPEM: more than one PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("signerd.ParseEd25519KeyPEM: unsupported PEM type %q", block.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signerd.ParseEd25519KeyPEM: %w", err)
	}
	ek, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signerd.ParseEd25519KeyPEM: not an Ed25519 key")
	}
	return ek, nil
}

// GenerateEd25519KeyFile writes a new Ed25519 key as PKCS#8 PEM to path (mode
// 0600, never overwriting) and returns its document key id
// (platformcontract.DocumentKeyID), which hosts pin.
func GenerateEd25519KeyFile(path string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("signerd.GenerateEd25519KeyFile: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("signerd.GenerateEd25519KeyFile: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator-named output path
	if err != nil {
		return "", fmt.Errorf("signerd.GenerateEd25519KeyFile: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("signerd.GenerateEd25519KeyFile: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("signerd.GenerateEd25519KeyFile: %w", err)
	}
	return platformcontract.DocumentKeyID(pub), nil
}
