// Package update is the pure-logic core of enterprise update management
// (docs/plans/enterprise-update-management-plan-2026-09-07.md, wave W1).
//
// It owns the decisions an update makes and none of the effects:
//
//   - the signed manifest wire shape and its canonical encoding
//     (manifest.go, §3.1),
//   - the nine ordered verification rules, expressed as a TABLE walked
//     top-down so a rule is a row and a test is a row (verify.go, §3.2),
//   - the vendor artifact-signature key material slot (vendorkey.go,
//     review finding H0),
//   - semver comparison mirroring web/src/lib/version.ts so the CLI, the
//     dashboard and the verifier can never disagree (semver.go),
//   - os/arch -> artifact selection and archive-shape handling for BOTH
//     real pipeline shapes, POSIX tar.gz and win32 zip (platform.go, §0
//     row 3 / §3.1),
//   - archive member selection and its safety rules over an ABSTRACT
//     entry list, so the rules are testable without touching a
//     filesystem (archive.go, §3.7 step 4),
//   - the install-method table that decides whether this node may
//     self-apply at all (installmethod.go, §3.7),
//   - the apply plan and the rollback decision, including "does this
//     target advance the schema, and therefore must a DB snapshot be
//     taken" (plan.go, §3.7 steps 5 and 8),
//   - the node update state enum and its legal transitions (state.go,
//     §2.1).
//
// It owns NO transport, NO storage and NO process control. Downloading
// bytes, hashing a file on disk, extracting an archive, swapping a
// binary, forking the successor and writing update_state all live in
// cmd/observer/update_apply.go and internal/store (waves W2/W3); they
// call in here for every decision and get a plain result back.
//
// The discipline mirrors internal/announce, internal/predict and
// internal/routing, and imports_test.go pins it: NO database/sql, NO
// net/http, NO net, NO os/exec, NO fsnotify. The announce rationale
// applies verbatim and then some — an http import in a package whose
// job is "fetch a new binary" would be the first symptom of a node
// reaching a host it is not enrolled with, which ruling R8 forbids
// (the org mirror is the only artifact source a node ever uses).
package update
