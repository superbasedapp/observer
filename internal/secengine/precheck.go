package secengine

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	_ "embed"
)

// precheck.go is the offline pre-check of an Opengrep release asset's
// keyless cosign signature (JSP-8 "What does verify offline"): the ECDSA
// signature over the asset's sha256, the Fulcio chain at signing time and
// the identity and issuer the certificate names. It needs only the
// digest, the base64 .sig and .cert files, and the Sigstore roots below.
// It is not a verification: only Rekor proves the signature was made inside
// the certificate's ten minutes, so scripts/secengine always runs the full
// online cosign verification after it.

// The Sigstore public-good Fulcio root and intermediate (sigstore/root-signing
// targets/fulcio_v1.crt.pem and fulcio_intermediate_v1.crt.pem at commit
// f138b50, the certificate authority valid from 2022-04-13 with no end).
//
//go:embed sigstore/fulcio_v1.crt.pem
var fulcioRootPEM []byte

//go:embed sigstore/fulcio_intermediate_v1.crt.pem
var fulcioIntermediatePEM []byte

// FulcioRoots returns the embedded root and intermediate PEM blocks.
func FulcioRoots() (root, intermediate []byte) {
	return append([]byte(nil), fulcioRootPEM...), append([]byte(nil), fulcioIntermediatePEM...)
}

// Caps on the inputs.
const (
	maxCertBytes = 16 << 10
	maxSigBytes  = 1 << 10
)

// The Fulcio certificate extensions that carry the OIDC issuer: the v2
// extension (a DER UTF8String) and the deprecated v1 one (raw bytes).
var (
	oidIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
	oidIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
)

// PrecheckInput is one pre-check.
type PrecheckInput struct {
	// Digest is the hex sha256 of the asset.
	Digest string
	// SigB64 and CertB64 are the release's .sig and .cert files as
	// published (base64 of a DER signature, base64 of a PEM certificate).
	SigB64, CertB64  []byte
	Identity, Issuer string
	// RootPEM and IntermediatePEM are the trust anchors; empty means the
	// embedded Fulcio pair.
	RootPEM, IntermediatePEM []byte
}

// PrecheckResult is what the certificate says.
type PrecheckResult struct {
	NotBefore, NotAfter time.Time
	Identity, Issuer    string
}

// ErrPrecheck wraps every pre-check refusal.
var ErrPrecheck = errors.New("secengine: offline signature pre-check failed")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPrecheck, fmt.Sprintf(format, a...))
}

// Precheck runs the offline pre-check.
func Precheck(in PrecheckInput) (PrecheckResult, error) {
	digest, err := hex.DecodeString(strings.TrimSpace(in.Digest))
	if err != nil || len(digest) != 32 {
		return PrecheckResult{}, refuse("the digest is not a sha256")
	}
	if len(in.CertB64) > maxCertBytes || len(in.SigB64) > maxSigBytes {
		return PrecheckResult{}, refuse("the signature or certificate is over its cap")
	}
	certPEM, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(in.CertB64)))
	if err != nil {
		// A .cert may also be published as plain PEM.
		certPEM = in.CertB64
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return PrecheckResult{}, refuse("the certificate is not a PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return PrecheckResult{}, refuse("the certificate does not parse: %v", err)
	}
	rootPEM, interPEM := in.RootPEM, in.IntermediatePEM
	if len(rootPEM) == 0 {
		rootPEM, interPEM = fulcioRootPEM, fulcioIntermediatePEM
	}
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return PrecheckResult{}, refuse("no root certificate")
	}
	inters.AppendCertsFromPEM(interPEM)
	// The chain at signing time: the leaf lives ten minutes, so verify one
	// second after it became valid (JSP-8's openssl -attime check).
	at := leaf.NotBefore.Add(time.Second)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}); err != nil {
		return PrecheckResult{}, refuse("the certificate does not chain to the Fulcio root at its signing time: %v", err)
	}
	res := PrecheckResult{NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Issuer: certIssuer(leaf)}
	uris := make([]string, 0, len(leaf.URIs))
	for _, u := range leaf.URIs {
		uris = append(uris, u.String())
	}
	if !slices.Contains(uris, in.Identity) {
		return res, refuse("the certificate's identity %v is not %s", uris, in.Identity)
	}
	res.Identity = in.Identity
	if res.Issuer != in.Issuer {
		return res, refuse("the certificate's issuer %q is not %s", res.Issuer, in.Issuer)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return res, refuse("the certificate's key is not ECDSA")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(in.SigB64)))
	if err != nil {
		return res, refuse("the signature is not base64")
	}
	if !ecdsa.VerifyASN1(pub, digest, sig) {
		return res, refuse("the signature does not match the asset's digest")
	}
	return res, nil
}

// certIssuer reads the OIDC issuer extension, the v2 form first.
func certIssuer(c *x509.Certificate) string {
	for _, e := range c.Extensions {
		if e.Id.Equal(oidIssuerV2) {
			var s string
			if _, err := asn1.Unmarshal(e.Value, &s); err == nil {
				return s
			}
		}
	}
	for _, e := range c.Extensions {
		if e.Id.Equal(oidIssuerV1) {
			return string(bytes.TrimSpace(e.Value))
		}
	}
	return ""
}
