// egressReasonCodes: the closed egress reason-code vocabulary, ONE copy for
// every app (FRONT-02). The org dashboard's egress editor reads it through
// web2/src/pages/policyforms/vocab.ts, a re-export. It is the TypeScript
// MIRROR of the Go owner, internal/policyfam/egress ReasonCodes() (the set
// the egress lint and the engine accept on a rule's reason_code); the Go
// test internal/policyfam/egress/reasoncodes_mirror_test.go fails when the
// two drift, so a code added in Go is added here in the same change.

/** The reason-code picker's options: "" first (let the engine derive the
 *  code from the rule's action and fail posture), then every code in the Go
 *  declaration order. */
export const EGRESS_REASON_CODES: readonly string[] = [
  "",
  "egress_flagged_local",
  "egress_budget_band",
  "egress_cohort_upstream",
  "egress_overload_degrade",
  "egress_sensitive_local_only",
  "egress_deny_unavailable",
  "egress_fail_open",
  "egress_no_route",
  "egress_switch_held",
  "egress_effort_noop",
];
