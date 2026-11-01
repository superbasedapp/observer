package seciac

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/secengine"
)

// bundle.go is the offline pre-check of a Trivy release asset's sigstore
// bundle (Trivy's signature-verification page at v0.75.0: since v0.68.1
// each asset has <asset>.sigstore.json and no separate .sig and .pem). The
// bundle carries the Fulcio leaf and the ECDSA signature over the asset's
// sha256; secengine.Precheck, called as a library, checks the chain at
// signing time, the pinned identity and issuer and the signature. Like
// Opengrep's, it is a pre-check, not a full verification: only the Rekor
// entry proves the signature was made inside the leaf's ten minutes, which
// the full online cosign verification checks where a manifest is built.

// MaxBundleBytes caps a bundle file.
const MaxBundleBytes = 64 << 10

type sigstoreBundle struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		Certificate *struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
		X509CertificateChain *struct {
			Certificates []struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificates"`
		} `json:"x509CertificateChain"`
	} `json:"verificationMaterial"`
	MessageSignature *struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    string `json:"digest"`
		} `json:"messageDigest"`
		Signature string `json:"signature"`
	} `json:"messageSignature"`
}

// BundleInput is one bundle pre-check.
type BundleInput struct {
	Engine EngineID
	// Version is the pin's version (the identity names its tag).
	Version string
	// Digest is the asset's hex sha256 as the installer computed it.
	Digest string
	Bundle []byte
	// RootPEM and IntermediatePEM override the embedded Fulcio roots
	// (tests only).
	RootPEM, IntermediatePEM []byte
}

// PrecheckBundle pre-checks a sigstore bundle for the asset digest.
func PrecheckBundle(in BundleInput) (secengine.PrecheckResult, error) {
	e, ok := Lookup(in.Engine)
	if !ok || e.Signature != SigCosignKeylessBundle {
		return secengine.PrecheckResult{}, fmt.Errorf("%w: %s publishes no sigstore bundle", secengine.ErrPrecheck, in.Engine)
	}
	if len(in.Bundle) == 0 || len(in.Bundle) > MaxBundleBytes {
		return secengine.PrecheckResult{}, fmt.Errorf("%w: the bundle is empty or over %d bytes", secengine.ErrPrecheck, MaxBundleBytes)
	}
	var b sigstoreBundle
	if err := json.Unmarshal(in.Bundle, &b); err != nil {
		return secengine.PrecheckResult{}, fmt.Errorf("%w: the bundle does not parse", secengine.ErrPrecheck)
	}
	if !strings.HasPrefix(b.MediaType, "application/vnd.dev.sigstore.bundle") || b.MessageSignature == nil {
		return secengine.PrecheckResult{}, fmt.Errorf("%w: not a message-signature sigstore bundle", secengine.ErrPrecheck)
	}
	raw := ""
	switch {
	case b.VerificationMaterial.Certificate != nil:
		raw = b.VerificationMaterial.Certificate.RawBytes
	case b.VerificationMaterial.X509CertificateChain != nil && len(b.VerificationMaterial.X509CertificateChain.Certificates) > 0:
		raw = b.VerificationMaterial.X509CertificateChain.Certificates[0].RawBytes
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(der) == 0 {
		return secengine.PrecheckResult{}, fmt.Errorf("%w: the bundle carries no certificate", secengine.ErrPrecheck)
	}
	md := b.MessageSignature.MessageDigest
	if md.Algorithm != "" && md.Algorithm != "SHA2_256" {
		return secengine.PrecheckResult{}, fmt.Errorf("%w: digest algorithm %q", secengine.ErrPrecheck, md.Algorithm)
	}
	if md.Digest != "" {
		got, err := base64.StdEncoding.DecodeString(md.Digest)
		if err != nil || hex.EncodeToString(got) != lower(in.Digest) {
			return secengine.PrecheckResult{}, fmt.Errorf("%w: the bundle signs another digest", secengine.ErrPrecheck)
		}
	}
	return secengine.Precheck(secengine.PrecheckInput{
		Digest:   in.Digest,
		SigB64:   []byte(b.MessageSignature.Signature),
		CertB64:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Identity: e.Identity(in.Version), Issuer: e.Issuer,
		RootPEM: in.RootPEM, IntermediatePEM: in.IntermediatePEM,
	})
}
