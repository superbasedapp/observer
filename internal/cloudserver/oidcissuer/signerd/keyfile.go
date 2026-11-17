package signerd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// CredentialKeyName is the systemd credential name the signer reads its key
// from (LoadCredentialEncrypted=oidc-signing-key:<path>).
const CredentialKeyName = "oidc-signing-key" //nolint:gosec // G101: a systemd credential NAME, not a credential

// maxKeyFile bounds a key file read.
const maxKeyFile = 64 << 10

// CredentialKeyPath returns <credentialsDir>/<name> (credentialsDir is the
// $CREDENTIALS_DIRECTORY systemd sets for a unit with credentials), or ""
// when there is no directory or the name is not a plain file name.
func CredentialKeyPath(credentialsDir, name string) string {
	dir := strings.TrimSpace(credentialsDir)
	if dir == "" || name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return ""
	}
	return filepath.Join(dir, name)
}

// LoadPrivateKey reads an RSA private key (PKCS#8 "PRIVATE KEY" or PKCS#1
// "RSA PRIVATE KEY" PEM) of at least oidcissuer.MinRSABits bits. Off Windows
// the file must not be readable by group or others. Encrypted PEM is not
// supported: decryption is the systemd credential's job (see the package
// doc).
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("signerd.LoadPrivateKey: %w", err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxKeyFile {
		return nil, fmt.Errorf("signerd.LoadPrivateKey: %s is not a key-sized regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("signerd.LoadPrivateKey: %s is readable by group or others (mode %o); make it 0600", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304: the operator-configured key path
	if err != nil {
		return nil, fmt.Errorf("signerd.LoadPrivateKey: %w", err)
	}
	return ParsePrivateKeyPEM(raw)
}

// ParsePrivateKeyPEM parses one RSA private key PEM block.
func ParsePrivateKeyPEM(raw []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("signerd.ParsePrivateKeyPEM: no PEM block")
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("signerd.ParsePrivateKeyPEM: more than one PEM block")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signerd.ParsePrivateKeyPEM: %w", err)
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("signerd.ParsePrivateKeyPEM: not an RSA key")
		}
		key = rk
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signerd.ParsePrivateKeyPEM: %w", err)
		}
		key = k
	default:
		return nil, fmt.Errorf("signerd.ParsePrivateKeyPEM: unsupported PEM type %q (encrypted keys are decrypted by the systemd credential, not here)", block.Type)
	}
	if key.N.BitLen() < oidcissuer.MinRSABits {
		return nil, fmt.Errorf("signerd.ParsePrivateKeyPEM: %d-bit key, want at least %d", key.N.BitLen(), oidcissuer.MinRSABits)
	}
	if err := key.Validate(); err != nil {
		return nil, fmt.Errorf("signerd.ParsePrivateKeyPEM: %w", err)
	}
	return key, nil
}

// GenerateKeyFile writes a new RSA key of oidcissuer.MinRSABits bits as
// PKCS#8 PEM to path (mode 0600, never overwriting) and returns its public
// JWK.
func GenerateKeyFile(path string) (oidcissuer.JWK, error) {
	key, err := rsa.GenerateKey(rand.Reader, oidcissuer.MinRSABits)
	if err != nil {
		return oidcissuer.JWK{}, fmt.Errorf("signerd.GenerateKeyFile: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return oidcissuer.JWK{}, fmt.Errorf("signerd.GenerateKeyFile: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator-named output path
	if err != nil {
		return oidcissuer.JWK{}, fmt.Errorf("signerd.GenerateKeyFile: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return oidcissuer.JWK{}, fmt.Errorf("signerd.GenerateKeyFile: %w", err)
	}
	if err := f.Close(); err != nil {
		return oidcissuer.JWK{}, fmt.Errorf("signerd.GenerateKeyFile: %w", err)
	}
	return oidcissuer.PublicJWK(&key.PublicKey), nil
}
