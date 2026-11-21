// Package dastconsent is the developer's one-time accept of the local
// passive DAST checker (component security.dast; OS and CI vulnerability
// scanning plan section 14.9: "its own one-time accept, and every run starts
// from the developer (card or CLI); an agent cannot start it or give the
// accept (R-165)").
//
// It follows the osvdb consent records (internal/secscan/osvdb/consent.go):
// a small JSON file in the security directory, signed under the node's
// posture key (guardposture.RecordMAC) with its own MAC domain and version,
// so a hand-written file, another accept's record copied under this name,
// or a record of an older text reads not accepted. It is given only on the
// dashboard or with `observer security dast accept` (a terminal question or
// --yes), never by an agent: guard rule R-165 denies the verb, the reserved
// dashboard route and a write to the record. It lives in its own package,
// not beside the osvdb records, so the checker needs nothing from the
// dependency scanners (security.deps can be compiled out without it).
//
// The package does file I/O only (no network, database, process or
// fsnotify; imports_test.go).
package dastconsent
