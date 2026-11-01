// Package seccorpus is the precision corpus of the observer-code rule pack
// (security pillar plan PR7, section 5.5 and 6.3, Phase G lane G3; spikes
// JSP-7 and JSP-8). It holds the arithmetic and the records of the method
// that decides whether an Opengrep rule may ever count toward the commit
// gate's S-791, and nothing else:
//
//   - the candidate finding and label records: data only (repository URL,
//     commit, path, line, rule id, a verdict and a fixed reason code), never
//     source text;
//   - the ecosystem exclusions (installed dependencies, vendored copies,
//     minified and generated files), one table walked top-down;
//   - agreement between the two reviewers and Cohen's kappa;
//   - per-rule precision under the operator's ruling (P-047): a finding is a
//     true positive only when both reviewers say so, and any disagreement
//     counts against the rule;
//   - the Wilson 95 percent lower bound (secrulepack's validator and blocking
//     bar call it, so the bar and the corpus share one formula);
//   - the operator's spot-check sample, drawn per rule with a recorded seed
//     so the same seed always draws the same rows, and its tally.
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1, pinned by
// imports_test.go): its callers (scripts/seccorpus) read and write files,
// clone repositories and run the engine; this package only computes.
package seccorpus
