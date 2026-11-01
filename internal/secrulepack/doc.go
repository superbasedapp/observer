// Package secrulepack is the Opengrep rule pack format of the security
// pillar's code rules (security pillar plan sections 5.5 and 8.5, Phase G
// lane G1; spike JSP-8). The pack is Observer-authored Semgrep-syntax rules
// that the security.scan.opengrep driver hands to a separately installed
// Opengrep; it is never a Semgrep Registry rule or an opengrep-rules file.
//
// The pack id is observer-code. "Rule pack" already names the native guard
// rules of internal/secrules (secrules.PackVersion); this package is the
// Opengrep pack only and never shares that id.
//
// What it owns:
//
//   - the format: a pack.json manifest (id, version, licence, the canary,
//     and per rule its id, languages, category, severity, CWE and an
//     optional precision figure with its Wilson lower bound, denominator,
//     corpus and method) beside one YAML file per rule;
//   - the strict validator (Parse): unique ids, a strict decode of each rule
//     file against the Semgrep syntax subset the pack may use (an unknown
//     key fails), size and count caps, local files only (no remote config,
//     no path outside the pack), and the manifest agreeing with each file;
//   - the canonical digest of a pack, its signed-channel bundle form
//     (security.rule_pack, internal/update/content), and Choose, under which
//     the newer verified pack wins over the embedded floor;
//   - the blocking bar: a rule may count toward the commit gate's S-791 only
//     when the manifest turns blocking on for it, and the validator refuses
//     that unless the rule has a precision figure whose Wilson lower bound,
//     recomputed from its counts, is at least BlockingLowerBound (PR7) AND an
//     independent spot-check of the reviewers' labels (P-047, P-064: an AI
//     reviewer that labelled none of the corpus, or the operator) of exactly
//     those figures (figures_digest) and of at least MinSpotcheckSample
//     answers is recorded with no overturned true positive
//     (operator_spotcheck). The figures and the corpus method live in
//     internal/seccorpus and docs/code-rules-precision.md; a rule under
//     NoisyFloor is listed as noisy and stays flag-only;
//   - RulePrefix, the dotted rules directory Opengrep embeds in a rule id
//     (secscan.AdaptOptions.RulePrefix strips it).
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1): it reads the
// embedded floor through embed and everything else from bytes its caller
// passes; it never opens a file, starts a process or makes a network call
// (imports_test.go). It belongs to security.scan.opengrep.
package secrulepack
