package oidcissuer

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ClientIDForOrg returns the client id of org orgID ("org:" + the id).
func ClientIDForOrg(orgID string) string { return ClientIDPrefix + orgID }

// OrgFromClientID returns the org id a client id names, or false when the id
// is not "org:" followed by a canonical UUID.
func OrgFromClientID(clientID string) (string, bool) {
	org, ok := strings.CutPrefix(clientID, ClientIDPrefix)
	if !ok || !isCanonicalUUID(org) {
		return "", false
	}
	return org, true
}

// TenantRedirectURI returns the one redirect URI an org's client registers:
// https://<slug>.<tenantDomain>/auth/oidc/callback.
func TenantRedirectURI(slug, tenantDomain string) (string, error) {
	slug = strings.TrimSpace(slug)
	tenantDomain = strings.Trim(strings.ToLower(strings.TrimSpace(tenantDomain)), ".")
	if slug == "" || tenantDomain == "" || strings.ContainsAny(slug+tenantDomain, "/:@?#\\ ") {
		return "", fmt.Errorf("oidcissuer.TenantRedirectURI: slug %q / domain %q unusable", slug, tenantDomain)
	}
	return "https://" + slug + "." + tenantDomain + TenantCallbackPath, nil
}

// ClientForOrg builds the client row for org orgID served at slug.
func ClientForOrg(orgID, slug, tenantDomain string) (Client, error) {
	if !isCanonicalUUID(orgID) {
		return Client{}, fmt.Errorf("oidcissuer.ClientForOrg: org id %q is not a canonical UUID", orgID)
	}
	uri, err := TenantRedirectURI(slug, tenantDomain)
	if err != nil {
		return Client{}, err
	}
	return Client{ClientID: ClientIDForOrg(orgID), OrgID: orgID, RedirectURIs: []string{uri}}, nil
}

// RedirectMatches reports whether got equals one of the registered URIs
// exactly, byte for byte (no normalisation, no prefix, no case folding).
func RedirectMatches(registered []string, got string) bool {
	if got == "" {
		return false
	}
	for _, r := range registered {
		if subtle.ConstantTimeCompare([]byte(r), []byte(got)) == 1 {
			return true
		}
	}
	return false
}

// S256Challenge returns the PKCE S256 challenge of verifier.
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(sum[:])
}

// VerifyPKCE reports whether verifier is a well-formed RFC 7636 verifier
// (43 to 128 unreserved characters) whose S256 challenge equals challenge.
// There is no plain method: a verifier equal to its own challenge fails.
func VerifyPKCE(challenge, verifier string) bool {
	if !validToken(verifier, 43, 128) || !validChallenge(challenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(S256Challenge(verifier)), []byte(challenge)) == 1
}

// validChallenge reports whether c has the shape of an S256 challenge: 43
// base64url characters (a SHA-256 digest, unpadded).
func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	_, err := b64.DecodeString(c)
	return err == nil
}

// HashCode returns the stored form of an authorization code (hex SHA-256).
func HashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// PublishedKeys returns the keys the JWKS lists at now: active (including one
// whose not_before is still ahead, which is the point of publishing first)
// and retiring keys whose not_after has not passed. Ordered by kid.
func PublishedKeys(keys []SigningKey, now time.Time) []JWK {
	out := make([]JWK, 0, len(keys))
	for _, k := range keys {
		if k.Status != KeyActive && k.Status != KeyRetiring {
			continue
		}
		if !k.NotAfter.IsZero() && !now.Before(k.NotAfter) {
			continue
		}
		out = append(out, k.JWK)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Kid < out[j].Kid })
	return out
}

// SelectSigningKey picks the key to sign with at now among the keys the
// signer holds: active, its not_before reached (so it has been in the JWKS
// since promotion), its not_after not passed. The latest not_before wins; a
// tie goes to the smaller kid. false when there is none.
func SelectSigningKey(keys []SigningKey, held map[string]bool, now time.Time) (SigningKey, bool) {
	var best SigningKey
	found := false
	for _, k := range keys {
		if k.Status != KeyActive || !held[k.KID] || k.NotBefore.IsZero() || now.Before(k.NotBefore) {
			continue
		}
		if !k.NotAfter.IsZero() && !now.Before(k.NotAfter) {
			continue
		}
		if !found || k.NotBefore.After(best.NotBefore) || (k.NotBefore.Equal(best.NotBefore) && k.KID < best.KID) {
			best, found = k, true
		}
	}
	return best, found
}
