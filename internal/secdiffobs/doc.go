// Package secdiffobs is the security pillar's diff observations for
// Phase C (security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md section 5.7): deterministic
// facts about an agent's edit or a commit's diff, each labelled an
// observation and flag-only (whether a change is legitimate needs a human;
// R-166 is the blocking variant for tests and CI).
//
//	S-761 disabled verification: TLS verification switched off
//	S-767 test tampering: a test file deleted, or a skip, xfail or only
//	      marker added
//	S-768 test tampering: assertions net-removed from a test file
//	S-769 test tampering: a suppression added (# nosec, eslint-disable,
//	      //nolint, @SuppressWarnings, ...), an always-true fallback added
//	      to a CI step, or a coverage threshold lowered
//
// The inferences of section 5.7 (lane SEC-G5) guess intent and are always
// flag-only; they run only through ObserveWith (Observe keeps them off):
//
//	S-762 a removed or bypassed authentication check (decorator, middleware)
//	S-763 a debug branch returning a privileged identity
//	S-764 a CSRF exemption added
//	S-765 CORS opened to any origin with credentials
//	S-766 a rate limit removed
//	S-770 scope drift: a sensitive path class (auth, CI, IaC, lockfiles,
//	      tests) changed while the session's prompt named none of its terms;
//	      the prompt is read at decision time and never kept
//
// Fix observations (fixobs.go, section 5.11 (a)) decide from session facts
// whether a not_reproduced finding may move to fixed_verified, and which
// commit subjects claim a fix (unverified_fix). Observations carry a rule,
// a path, a line and fixed rule text, never repository text. Pure: no SQL,
// HTTP, process or filesystem.
package secdiffobs
