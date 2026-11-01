// Package secposture is the on-disk contract between the daemon and the
// short-lived `observer hook` process for the security pillar's commit gate
// (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md
// section 4.8): the signed per-project posture file, the dirty marker, the
// seen mark, and the one pure function that derives a project's state from
// them.
//
// Everything lives under ~/.observer/security/ (inside R-160's
// ~/.observer/** surface):
//
//   - posture/<project_root_hash>.json: one signed file per project
//     (revision 2.4 [JSP-2]), at most MaxFileBytes. ONE writer, the
//     daemon's security.posture loop, by atomic replace. The key sits
//     beside it as posture/posture.key.
//   - dirty/<project_root_hash>: an append-only file whose size is the
//     dirty counter (one byte appended per raise). Two writers of one kind
//     (the hook before a write-capable call proceeds, the daemon when it
//     learns of a write), no lock, no fsync on the hook path. Never
//     decremented.
//   - seen/<project_root_hash>: the highest posture sequence this
//     project's hooks accepted, so an older posture put back is refused.
//
// The package is core residue (section 4.3): it is compiled into every
// build, including sbo_omit_security, because the hook reads it whether or
// not the module is active. It imports the standard library, the atomic
// file writer, internal/guardposture (for the module signal) and
// internal/policy (the pure owner of the posture
// vocabulary) only, because it is read on the hook path; imports_test.go
// pins that.
package secposture
