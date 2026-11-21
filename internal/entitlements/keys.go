package entitlements

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// The compiled-in entitlements verification keys (plan 06 5.3.8: "Vendor
// entitlement verify key: compiled in"; M6.0 3.3: the document signer's
// entitlements key, "two keys valid at once; hosts pin both ids; floor
// documents compiled into the binary carry the trust anchors"). The private
// halves live only with the document signer on the worker VM
// (`observer-cloud signer document`), never in this tree.
//
// STATUS: both slots are EMPTY. The key is generated under the operator's
// key custody plan (operator dependency C12, docs/plans/managed-saas/
// 07-operator-dependencies-2026-11-13.md), which is not settled. An empty
// slot contributes no key, so until a key is compiled in every document is
// refused and every org resolves to its floor; the zero value never means
// "accept anything" (the internal/update/vendorkey.go rule).
//
// Rotation, as for the vendor artifact key: (1) generate the new key on the
// signer; (2) move EntitlementsPublicKeyV1 here to the previous slot and put
// the new one in V1; (3) ship a release carrying both and wait for hosts to
// reach it; (4) only then switch the signer to the new key, and clear the
// previous slot one release later.
const (
	// EntitlementsPublicKeyV1 is the current key: base64 (standard, padded)
	// of the 32 raw Ed25519 public-key bytes. Empty: see STATUS.
	EntitlementsPublicKeyV1 = ""
	// EntitlementsPublicKeyV0Previous is the rotation slot. Empty between
	// rotations.
	EntitlementsPublicKeyV0Previous = ""
)

// CompiledKeys returns the compiled-in key set: one key per non-empty slot,
// each pinned under its derived id. It fails on a slot that does not decode
// to a 32-byte key (a build-time mistake, pinned by a test).
func CompiledKeys() (platformcontract.KeySet, error) {
	return keySetFrom(EntitlementsPublicKeyV1, EntitlementsPublicKeyV0Previous)
}

// ParsePublicKeys decodes public keys written the way the compiled slots
// are: base64 (standard, padded) of the 32 raw Ed25519 public-key bytes, one
// key per argument. Empty arguments contribute nothing. It is data only: the
// caller reads whatever file the text came from (W14-D1(b): a pooled host's
// [platform] key files are read at the org server's config boundary,
// internal/orgserver/platformkeys); this package never reads a file.
func ParsePublicKeys(slots ...string) (platformcontract.KeySet, error) {
	ks, err := keySetFrom(slots...)
	if err != nil {
		return nil, fmt.Errorf("entitlements.ParsePublicKeys: %w", err)
	}
	return ks, nil
}

// HostKeys is the entitlements key set a POOLED host verifies documents
// under (lead decision W14-D1(b), ledger ENTL-8): the compiled keys when at
// least one is compiled in (plan 06 5.3.8: "compiled in"; a compiled key
// always wins), otherwise pinned, the keys the host pinned from its
// root-owned [platform].entitlements_pubkey_file. pinned is data its caller
// loaded and passes only in pooled tenancy; a self-hosted licence never
// reaches this function (internal/orgserver/licence verifies under
// CompiledKeys only, so a self-hosted customer cannot pin their own key and
// sign their own licence; tests/invariant pins both rules).
func HostKeys(pinned platformcontract.KeySet) (platformcontract.KeySet, error) {
	compiled, err := CompiledKeys()
	if err != nil {
		return nil, err
	}
	return PreferCompiled(compiled, pinned), nil
}

// PreferCompiled is HostKeys' rule over explicit sets: compiled when it holds
// a key, otherwise a copy of pinned. Never a union: a compiled key is the
// vendor's anchor and a pinned one only stands in while none is compiled.
func PreferCompiled(compiled, pinned platformcontract.KeySet) platformcontract.KeySet {
	if len(compiled) > 0 {
		return append(platformcontract.KeySet(nil), compiled...)
	}
	return append(platformcontract.KeySet(nil), pinned...)
}

func keySetFrom(slots ...string) (platformcontract.KeySet, error) {
	var ks platformcontract.KeySet
	for i, s := range slots {
		if s == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("entitlements.CompiledKeys: slot %d is not a base64 Ed25519 public key", i)
		}
		ks = append(ks, platformcontract.NewDocumentKey(ed25519.PublicKey(raw)))
	}
	return ks, nil
}
