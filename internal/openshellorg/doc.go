// Package openshellorg is the pure core of the org-hosted OpenShell gateway
// (tracker F-019; design of record docs/plans/openshell/build/g1-design.md,
// lane G2 section 11.2).
//
// It holds the decisions and the vocabularies, and no I/O:
//
//   - the three token profiles (run, member gateway, sync admin) and their
//     claims (claims.go, section 5.2);
//   - the proof-of-possession messages a node signs with its agent key, and
//     the front's service-key message for the internal decision API (pop.go,
//     sections 5.4 and 7.7);
//   - the mint rule table T0 to T8 with T5b, T6, T7, T7x, T7r and T7h, and the
//     end-report rule E1 (mint.go, section 5.4);
//   - the grant and device-code state machines (grant.go, devicecode.go,
//     section 5.3);
//   - quota reserve and settle (quota.go, section 7.3);
//   - the workspace, box-name, provider-instance and git-row-id grammars
//     (workspace.go, boxname.go);
//   - the box ledger states, the hold triggers H1 to H3, the hold and resume
//     state table with collect_failed, and the expiry rule (hold.go,
//     section 3.6);
//   - the closed reasons every surface answers with (reasons.go).
//
// Every decision is a data table walked top-down, one test case per row
// (CLAUDE.md module rule 5). The store seam that persists the ledger is
// internal/orgserver/openshellctl; the signer is
// internal/orgserver/openshellidp. This package imports neither, nor
// database/sql, net/http, os/exec, fsnotify or the OpenShell SDK
// (imports_test.go).
package openshellorg
