package orgcontract

// Machine DISAMBIGUATION on the agent rails.
//
// A per-caller agent rail (today GET /api/agent/budget) identifies its caller
// by the VERIFIED bearer's `sub` claim and nothing else. That claim names a
// MEMBER, and a member may run several machines — a laptop, a devbox, a CI
// runner — all enrolled under the same user id. Some server-side work is
// per-MACHINE rather than per-member (the cross-machine spend baseline
// subtracts the calling machine's own rows so the node can add its local spend
// without double-counting), and the server cannot name that machine from the
// bearer: it can only look at the machines the member has reported and, when
// there is exactly one, assume it.
//
// [HeaderMachineIdentity] lets the node SAY which of its own machines is
// asking, so a multi-machine developer stops silently losing that per-machine
// work. It is NON-AUTHORITATIVE by construction and this is the load-bearing
// property:
//
//   - It never widens identity. The server uses it only to SELECT among the
//     machines already attributed to the bearer's own user id. A value naming
//     any other machine — another member's, or one this member has never
//     reported — selects nothing and is discarded, so setting it can disclose
//     nothing the bearer could not already read.
//   - It never authenticates anything. The Ed25519 signed-request proof and
//     the bearer remain the only authenticators, exactly as with
//     [HeaderAgentKeyFingerprint], whose optional-in-both-directions shape
//     this header copies.
//   - It is OPTIONAL in both directions. An old node omits it and gets
//     today's single-machine inference; an old server ignores it entirely.
//     Neither end may require it.
const HeaderMachineIdentity = "X-SBO-Machine"

// machineHeaderMaxLen caps the header's accepted length. A machine identity is
// a 64-char hex SHA-256 (internal/machineid.ForOrg), so 256 is four times the
// only shape that can ever match a stored row while staying far below any
// header-size limit a proxy enforces. Anything longer cannot be a machine
// identity and is treated as absent rather than compared.
const machineHeaderMaxLen = 256

// SanitizeMachineHeader normalizes a raw [HeaderMachineIdentity] value into
// either a usable candidate or "" (meaning "treat as absent").
//
// It is deliberately a SHAPE check, never a lookup: whether the candidate names
// a machine the caller owns is the server's question, answered against the
// caller's own inventory. This only refuses values that cannot be a machine
// identity at all — empty or blank, longer than [machineHeaderMaxLen], or
// carrying anything outside printable non-space ASCII (control characters,
// spaces, or any byte a log line or a header re-emission would mangle).
//
// Both ends call it — the node before setting the header, the server before
// using it — so one vocabulary has one owner and a node can never send a value
// its server would silently drop.
func SanitizeMachineHeader(raw string) string {
	if raw == "" || len(raw) > machineHeaderMaxLen {
		return ""
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] > '~' {
			return ""
		}
	}
	return raw
}
