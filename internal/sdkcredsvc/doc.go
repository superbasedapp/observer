// Package sdkcredsvc is the machine side of the SDK credential and the SDK
// destination discovery (Plane A build-out W2-7, ruling D18; contract
// docs/plans/plane-a-sdk-buildout/contracts/destination.md).
//
// Sign-in asks the org (through an injected Minter, the orgclient lane) for
// the member's own scoped SDK key and stores it twice:
//
//   - in the machine keystore (service sbo-sdk-credential-v1, record
//     sdk-credential): the OS keychain where there is one, else the
//     keystore's hardened 0600 file;
//   - as the SDK's delivery copy, written through the keystore's hardened
//     file writer (directory 0700, file 0600, owner-checked, symlinks
//     refused, atomic). The superbased SDKs read this file directly; no
//     route on the machine ever returns the key (contract section 4.1).
//     Its first line is the key; a "gateway_url=<base>" line names the only
//     address the SDKs send it to (review E-04), so the loopback discovery
//     answer never decides where the key goes.
//
// A member of an organization that issues no member keys (a hosted one,
// SR-9) installs a key an admin issued instead: InstallKey (`observer sdk
// use-key`, the dashboard's "Use an SDK key from my admin") stores it through
// the same two hardened writes, marked admin-issued, with the gateway address
// the member names. Sign-out removes an admin-issued key's local copies and
// never asks the organization to revoke it (it is the admin's).
//
// The non-secret facts about the key (ids, scopes, gateway address) live in
// a second 0600 record beside it, so the discovery route can describe the key
// without reading it. Sign-out revokes the key this machine holds on the
// org (every key of the member only with an explicit all) and removes every
// local copy. An expired key keeps the machine signed in, with a warning,
// and is not offered to the SDKs.
//
// No network of its own: the org call is the Minter's. No database.
package sdkcredsvc
