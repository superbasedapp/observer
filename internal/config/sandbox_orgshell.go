package config

// TerminalSandboxHostedOrgShellConfig is the
// [terminal.sandbox.hosted.openshell-org] block (tracker F-019,
// g1-design.md sections 2.5 and 3.7, lane G4): the org-hosted OpenShell
// row's two node-local keys. Both default to false and are written only by
// the dashboard's Settings card or the `observer sandbox org-shell` verbs.
// Everything else about the row comes from the organization's verified
// managed sandbox body (Provider, never read from a file).
type TerminalSandboxHostedOrgShellConfig struct {
	// LaptopRelay is the member's opt-in to the laptop-relay mode: model
	// requests and hook events from the member's org sandbox runs travel
	// through this laptop, which must stay online for the run (design 3.7).
	// Without it the row is not offered (probe row R2b).
	LaptopRelay bool `toml:"laptop_relay"`
	// HoldOnEnd is the member's own H1 preference: when the run ends
	// normally and the org's hold_policy is on_disconnect_and_end, the box is
	// held for a later resume instead of returned and deleted (design 3.6).
	HoldOnEnd bool `toml:"hold_on_end"`
	// Provider is the row's provider table, composed from the verified
	// managed body (the front URL as Endpoint with OrgPublished, its pin and
	// the org's region label); never read from or written to a file.
	Provider TerminalSandboxHostedProviderConfig `toml:"-" json:"-"`
	// Published is the rest of the organization's published gateway, from
	// the same verified body (never read from or written to a file). Its
	// zero value (Offered false) means the row is not offered here.
	Published TerminalSandboxOrgShellPublished `toml:"-" json:"-"`
}

// TerminalSandboxOrgShellPublished is the org-published gateway as the node
// composes it from the verified managed body's org_openshell field (data
// only: it never enables the row).
type TerminalSandboxOrgShellPublished struct {
	// Offered: the verified, in-force body carries org_openshell.
	Offered bool
	// SandboxAuthorityMissing: no body applies because this node is a
	// managed enrolment whose grant does not hold enforce.sandbox (FX1
	// item 7, live finding F-B2), so the row's not-offered verdict can say
	// so. It explains Offered false; it never offers anything.
	SandboxAuthorityMissing bool
	// FrontURL and FrontSPKISHA256 are where the node connects and the pin.
	FrontURL, FrontSPKISHA256 string
	// GatewayID, Issuer, Version, Image, IsoClass and Region say what the
	// gateway is (shown; the node never dials the gateway).
	GatewayID, Issuer, Version, Image, IsoClass, Region string
	// Tiers, EgressAllowHosts, AllowCIDRs and BlockedCIDRs are the org's
	// network inputs (the node previews with them; the org compiles).
	Tiers, EgressAllowHosts, AllowCIDRs, BlockedCIDRs []string
	// CloneRepositories are the repositories this member may clone.
	CloneRepositories []string
	// BoxBinary is upload or image.
	BoxBinary string
	// LaptopRelay is the org's allowed or forbidden.
	LaptopRelay string
	// HoldPolicy, MaxHoldHours and ReturnToNode are shown; the org enforces.
	HoldPolicy   string
	MaxHoldHours int
	ReturnToNode bool
	// MaxRunMinutes lowers the row's static lifetime.
	MaxRunMinutes int
	// DailyBoxMinutesPerMember is the org's per-member daily quota from the
	// body's quota_summary (shown on the consent screen; the org enforces
	// it; 0 when the body names none).
	DailyBoxMinutesPerMember int
}
