// Package seciac is the pure core of the two infrastructure-as-code scanner
// drivers, security.scan.trivy and security.scan.kics (security pillar plan
// sections 4.2, 4.4, 5.6 P2, 8.1 and 8.5; gap G4; lane GATES-SEC, operator
// ruling P-129). It holds, as data and pure functions:
//
//   - the engine table: each engine's tested and minimum version, its
//     release assets per platform, how its release is signed, the flags every
//     run passes (each turning off a network path), the flags it never passes,
//     the repository-local config files a run ignores unless allowed, and its
//     exit codes;
//   - the pin tables, in the internal/secengine shape (a tested version equal
//     to the minimum, never "latest"), where a platform whose asset and
//     checksum were not fetched and compared is pin_owed;
//   - the reading of the shared security.engine manifest (entries prefixed
//     "trivy" or "kics"; an "opengrep" entry is skipped here as a "trivy"
//     entry is skipped by secengine);
//   - the decision table (pinned, pin owed, revoked, digest mismatch,
//     untested version, a managed node refusing what an individual node
//     labels), walked top-down;
//   - the guided install's plan and the developer's one-time size consent
//     per pin, and the offline signature pre-check of a Trivy sigstore bundle
//     through secengine.Precheck;
//   - the IaC path classes of the post_write trigger, the argument lists and
//     the --help check of the pinned flags;
//   - the result mapping: category iac, flag only, every kept finding at a
//     file and a line (the P-115 location rule).
//
// It does no I/O: the cmd layer (cmd/observer/security_iac*.go) reads
// files, manifests and certificates and hands them in. imports_test.go pins
// it free of database/sql, net/http, os/exec and fsnotify.
package seciac
