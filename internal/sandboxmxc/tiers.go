package sandboxmxc

import "fmt"

// tiers.go is the per-row accepted-tier set (lane GATES-SBX decision 5,
// additive): mxc-process accepts exactly the PSEC base-container tier, as
// probe.go's ladder already enforces (unchanged); mxc-appcontainer accepts
// exactly MXC's appcontainer-bfs tier. appcontainer-dacl is accepted by no
// row: it rewrites host ACLs, and allowDaclMutation is always false.
//
// What @microsoft/mxc-sdk 1.0.1 says about the AppContainer tier (read from
// the published package, sha1 f1a4859f..., 2026-10-24): dist/v1/types.d.ts
// names it "AppContainer + BFS filesystem isolation" beside the full
// BaseContainer "process security environment"; dist/v1/policy/filesystem.js
// says AppContainer processes see every directory whose ACL grants
// ALL_APPLICATION_PACKAGES without brokering; and the loopback facts the
// probe reports (ingressHostLoopbackAllow, identitylessLoopbackProxy) are
// named for BaseContainer only. So the row offers tier none alone, and the
// relay over the shared loopback port is claimed until register WIN-4.

// The AppContainer tiers MXC's probe may report.
const (
	TierAppContainerBFS  = "appcontainer-bfs"
	TierAppContainerDACL = "appcontainer-dacl"
)

// The rows that drive MXC.
const (
	RowMXCProcess      = "mxc-process"
	RowMXCAppContainer = "mxc-appcontainer"
)

// rowTiers is the accepted-tier set per row.
var rowTiers = map[string][]string{
	RowMXCProcess:      {TierBaseContainer},
	RowMXCAppContainer: {TierAppContainerBFS},
}

// AcceptedTiers returns the tiers row accepts (nil for an unknown row).
func AcceptedTiers(row string) []string { return append([]string(nil), rowTiers[row]...) }

// TierAccepted reports whether row accepts tier.
func TierAccepted(row, tier string) bool {
	for _, t := range rowTiers[row] {
		if t == tier {
			return true
		}
	}
	return false
}

// TierVerdict judges MXC's request-probe answer for row: the tier must be
// one the row accepts and need no host ACL change (the HostMutation rule).
// For mxc-process it agrees with the probe ladder's tier rows exactly.
func TierVerdict(row string, po ProbeOutput) Verdict {
	switch {
	case po.Tier == "":
		return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC found no ProcessContainer tier on this host: " + po.Error}
	case po.Tier == TierAppContainerDACL:
		return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC offers only its appcontainer-dacl tier here, which rewrites host ACLs; allowDaclMutation is false, so it is never used"}
	case !TierAccepted(row, po.Tier):
		return Verdict{Code: VerdictPSECUnavailable, Reason: fmt.Sprintf("MXC offers its %s tier here; the %s row accepts only %v", po.Tier, row, rowTiers[row])}
	case po.NeedsDaclAugmentation != nil && *po.NeedsDaclAugmentation:
		return Verdict{Code: VerdictPSECUnavailable, Reason: "MXC needs to change host ACLs for this policy, and allowDaclMutation is false"}
	}
	return Verdict{Code: VerdictAvailable}
}

// TierPin is the windows.mxc_tier value: the weakest MXC tier a node may
// use. Restrictive-only: an organization may pin process_container (the
// safe value) and nothing else, so it can never move a node onto the
// weaker AppContainer tier.
type TierPin string

// The closed TierPin vocabulary, strongest first.
const (
	PinProcessContainer TierPin = "process_container"
	PinAppContainer     TierPin = "appcontainer"
)

// TierPinValues is the enum, with the label each value shows.
var TierPinValues = []struct {
	Value TierPin
	Label string
	// Rank orders strength: higher is stronger.
	Rank int
}{
	{PinProcessContainer, "ProcessContainer only (the PSEC tier)", 2},
	{PinAppContainer, "AppContainer allowed (weaker than ProcessContainer: sees every folder granted to ALL APPLICATION PACKAGES)", 1},
}

// PinSafe is the value an organization may pin.
const PinSafe = PinProcessContainer

// OrgPinAccepted reports whether an organization's pin of v is accepted
// (restrictive-only: only the safe value).
func OrgPinAccepted(v TierPin) bool { return v == PinSafe }

// PinAllowsRow reports whether a node under pin may use row ("" is no pin).
func PinAllowsRow(pin TierPin, row string) bool {
	if row == RowMXCAppContainer {
		return pin == "" || pin == PinAppContainer
	}
	return true
}
