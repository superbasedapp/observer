// Package secrules is the security pillar's guard rule tables (security
// pillar plan docs/plans/security-pillar-plan-2026-10-19.md section 4.7):
// pure constructors that return immutable []policy.Rule per pillar child,
// and the one composition step that validates them before the cmd layer
// passes them to guard as Options.PackRules (they reach the engine as
// Config.ExtraRules).
//
// There is no init registration and no process-global registry: the
// RegisterLinkedFamily pattern silently replaces a duplicate, which is the
// wrong failure for rules. The pillar's Match closures read only
// Event.Security, filled by the hook context seam (internal/hookctx); the
// guard core imports nothing from here.
//
// Phase C rows: S-721 (a secret in a proposed write, in the hook) and the
// commit gate S-791 to S-794 (section 4.8 decision table).
// PreWriteSecurity is the pre-write scan the hook context seam runs to
// stamp the in-hook hits.
//
// Every row carries a pillar id (policy.SecurityRuleIDPrefix, S-701 to
// S-799), the category policy.CategoryCodeSecurity (secret rules keep
// policy.CategorySecrets) and Source policy.SourcePackSecurity. Phase B
// rows: S-701 to S-705 (repository trust, read from Event.Security.Trust).
//
// The package is pure (it imports internal/policy and the pure detection
// packages only: no SQL, no HTTP, no filesystem) and belongs to the
// `security` module root; it is compiled out with sbo_omit_security.
package secrules
