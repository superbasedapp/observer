package agentconfig

// Shared grounding for the rows the macOS run of the surface-gap arc
// (MAC-4, docs/handovers/surface-gap-mac4-report.md) settled. Every probe
// there ran on a macOS 26.2 VM with HOME pointed at a scratch directory; a
// "live" fact is one the tool's behaviour or its first launch showed, a
// "source" fact one read from the shipped binary or package.

const (
	mac4Date   = "2026-10-27"
	mac4Report = "docs/handovers/surface-gap-mac4-report.md"
)

// mac4Live grounds a row in what the MAC-4 macOS run observed.
func mac4Live(what string) Grounding {
	return Grounding{Kind: GroundLive, Source: "macOS VM (MAC-4, " + mac4Report + "): " + what, Date: mac4Date}
}

// mac4Source grounds a row in the shipped binary or package source the
// MAC-4 macOS run read.
func mac4Source(what string) Grounding {
	return Grounding{Kind: GroundSource, Source: "macOS VM (MAC-4, " + mac4Report + "): " + what, Date: mac4Date}
}
