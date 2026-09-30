package agentid

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// P11(e) project / team ABAC claims (doc3 §11.12b (e), R10.9).
//
//   - sbo_team_ids is the member's team roster, read SERVER-SIDE at mint
//     (never client-supplied) AFTER the member generation the token carries,
//     so a roster change that bumps the member generation refuses every token
//     minted under the old roster (the front's generation floor). PRESENT
//     (possibly the empty array) means "known"; ABSENT means the minter could
//     not establish the roster (no lookup wired, or a token minted before the
//     claim existed) and a team-scoped grant evaluates FAIL-CLOSED.
//   - sbo_team_overflow marks a roster larger than MaxTeamIDs (P11 fold
//     PF2): rather than fail the whole mint (an outage for a member of a
//     large org) the token is minted WITHOUT sbo_team_ids and with this
//     marker, and every team subject is untrusted for it - a team allow
//     never matches, a team deny / ask always does (per-grant fail closed,
//     the same outcome as an absent roster). The two claims never appear
//     together: the mint refuses it and VerifyProfile refuses a token that
//     carries both.
//   - sbo_project_hash is the canonical resolver-v2 project hash of the
//     coding session's project. It is RELAY-ATTESTED: the node relay signs it
//     inside its sbo-actor+jwt, the STS copies it only on the F1 node
//     exchange, and VerifyProfile refuses it on any token that is not
//     relay-originated (RelayOriginated) - a client can never label its own
//     token with a project.
const (
	// MaxTeamIDs bounds sbo_team_ids (the §4.7 size budget; the same bound
	// sbo_groups has). A roster larger than the bound is never truncated (a
	// deny grant may name the dropped team): the token carries
	// sbo_team_overflow instead and every team subject fails closed.
	MaxTeamIDs = 64
	// MaxTeamIDBytes bounds one team id.
	MaxTeamIDBytes = 128
	// ProjectHashMinLen / ProjectHashMaxLen bound sbo_project_hash: the
	// canonical project id is the 16-hex prefix of the sha256 of the project
	// root (rollup.ProjectIDFromHash over the node's project_root_hash); a
	// full 64-hex digest is also accepted.
	ProjectHashMinLen = 16
	ProjectHashMaxLen = 64
)

// ValidProjectHash reports whether s is a well-formed project hash:
// ProjectHashMinLen..ProjectHashMaxLen LOWERCASE hex characters.
func ValidProjectHash(s string) bool {
	if len(s) < ProjectHashMinLen || len(s) > ProjectHashMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ProjectHashOfRoot returns the canonical project hash of a project root
// path: the first 16 hex characters of sha256(root) - the same derivation
// the node's projects.root_path_hash and the org's rollup.ProjectIDFromHash
// compose to, so an attested hash joins the org Projects page and the
// resolver-v2 membership table directly. "" for an empty root.
func ProjectHashOfRoot(root string) string {
	if root == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(root))
	return hex.EncodeToString(sum[:])[:ProjectHashMinLen]
}

// RelayOriginated reports whether c is a relay-originated NODE token: minted
// by the F1 node exchange, which is the only flow that nests the node actor
// (`act.act.sub = "node:<id>"`) and it always DPoP-binds (cnf.jkt). A
// relay-attested claim (sbo_project_hash) is trusted ONLY on such a token.
func RelayOriginated(c Claims) bool {
	return c.Act != nil && c.Act.Act != nil && strings.HasPrefix(c.Act.Act.Sub, "node:") &&
		len(c.Act.Act.Sub) > len("node:") && c.Cnf != nil && c.Cnf.JKT != ""
}

// checkABAC is VerifyProfile's P11(e) row set: a bounded, well-formed team
// roster, and a well-formed project hash that appears ONLY on a
// relay-originated node token (a spoofed project label is refused, never
// ignored).
func checkABAC(c Claims) error {
	if c.SboTeamOverflow && c.SboTeamIDs != nil {
		return tokErr(TokErrClaims, "sbo_team_overflow with sbo_team_ids")
	}
	if len(c.SboTeamIDs) > MaxTeamIDs {
		return tokErr(TokErrClaims, "too many sbo_team_ids")
	}
	for _, t := range c.SboTeamIDs {
		if t == "" || len(t) > MaxTeamIDBytes {
			return tokErr(TokErrClaims, "sbo_team_ids entry must be 1..%d bytes", MaxTeamIDBytes)
		}
	}
	if c.SboProjectHash == "" {
		return nil
	}
	if !ValidProjectHash(c.SboProjectHash) {
		return tokErr(TokErrClaims, "malformed sbo_project_hash")
	}
	if !RelayOriginated(c) {
		return tokErr(TokErrClaims, "sbo_project_hash on a token that is not relay-originated")
	}
	return nil
}

// copyTeams copies a roster preserving the present-vs-absent distinction
// (nil stays nil, an empty roster stays a non-nil empty slice).
func copyTeams(ts []string) []string {
	if ts == nil {
		return nil
	}
	out := make([]string, len(ts))
	copy(out, ts)
	return out
}
