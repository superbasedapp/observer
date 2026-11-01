// Package secsvc is the security pillar's boundary service (security
// pillar plan docs/plans/security-pillar-plan-2026-10-19.md sections 4.2,
// 4.6 and 4.8). It owns no SQL and no file format of its own: it reads the
// findings store through internal/store's one seam, and writes each
// project's signed posture file through internal/secposture, as the one
// writer the plan names (the security.posture loop).
//
// Later phases add the driver runs, the post-write queue and the quick
// scan here; Phase A ships the posture writer, the daemon's in-memory
// posture for the relay path, and the clean-scan record the quick scan
// will feed.
//
// It belongs to the `security` module root and is compiled out with
// sbo_omit_security.
//
// This file carries no build tag on purpose (the D-535 precedent of
// internal/aggregatesvc): with sbo_omit_security the package still exists,
// empty, so the omit-tag test run of a package that holds a tagged file
// does not fail with every file excluded.
package secsvc
