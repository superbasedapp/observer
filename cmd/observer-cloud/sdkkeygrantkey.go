package main

import (
	"crypto/ed25519"
	"errors"
)

// sdkkeygrantkey.go loads the SDK key grant's signing key for `observer-cloud
// serve` (the AI Apps SDK quickstart, plan
// docs/plans/sdk-quickstart-one-command-plan-2026-11-25.md section 3.6,
// ruling R13 and amendment 2; internal/sdkkeygrant; docs/security.md
// SDKQS-2). It is a SECOND platform key, never the attach grant's: the cloud
// kit generates it once on the cloud host (deploy/saas-ovh/cloud-app
// cloud-app.sh, state/sdk_key_grant_key, mounted read-only into cloud-api
// only), and the tenant hosts pin its public half
// (`cloud-app.sh sdk-key-public` piped to the org kit). The format and the
// rules are the attach grant key's (attachgrantkey.go): a hex Ed25519 seed,
// the _FILE form only, never an environment value.

// envSDKKeyGrantKeyFile names the key file. Unset: the cloud takes no SDK
// key requests (the create answers invalid_purpose, so nobody approves a key
// that could never be delivered).
const envSDKKeyGrantKeyFile = "SBCI_SDK_KEY_GRANT_KEY_FILE"

// errSameGrantKey refuses one seed for both grants: the two keys exist so a
// compromise of one cannot sign the other's documents (ruling R13).
var errSameGrantKey = errors.New("observer-cloud: " + envSDKKeyGrantKeyFile + " holds the same key as " + envAttachGrantKeyFile + "; the SDK key grant needs its own key")

// loadSDKKeyGrantKey reads the seed at path (empty: no key), and refuses the
// attach grant's own key (attach may be nil).
func loadSDKKeyGrantKey(path string, attach ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	k, err := loadGrantSeedFile(envSDKKeyGrantKeyFile, path)
	if err != nil || k == nil {
		return k, err
	}
	if attach != nil && k.Equal(attach) {
		return nil, errSameGrantKey
	}
	return k, nil
}

// sdkKeyGrantKeyID is the key id the tenant hosts pin (the grant's kid).
func sdkKeyGrantKeyID(priv ed25519.PrivateKey) string {
	return attachGrantKeyID(priv)
}
