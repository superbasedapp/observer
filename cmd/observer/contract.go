//go:build !sbo_omit_integration_mcp_server

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp"
)

// contractVersion is the schema version of the `observer contract --json`
// artifact. It is bumped ONLY when the artifact's own shape changes
// incompatibly (a field renamed or removed) — adding a field is additive and
// does not bump it. It is deliberately independent of the observer release
// version: an integrator pins the contract version, not the binary version.
const contractVersion = 1

// contractDoc is the machine-readable stability contract: the published MCP
// tool tiers (docs/mcp-contract.md) plus the adapter capability registry,
// in one artifact an integrator can diff across releases.
type contractDoc struct {
	ContractVersion int               `json:"contract_version"`
	MCP             contractMCP       `json:"mcp"`
	Adapters        []contractAdapter `json:"adapters"`
}

// contractMCP is the MCP half of the artifact: the pinned server-registration
// name plus every published tool with its stability tier.
type contractMCP struct {
	// ServerName is the MCP registration entry name observer writes into each
	// AI tool's config — the reason every tool a client sees is namespaced
	// `mcp__observer__*`. Pinned by the contract.
	ServerName string `json:"server_name"`
	// Tools is the published tool-stability table, alphabetical.
	Tools []mcp.ContractTool `json:"tools"`
}

// contractAdapter is one adapter's PUBLIC capability row — the subset of
// internal/integration.Capability that is meaningful to an outside
// integrator, flattened to plain strings/bools so consumers never have to
// model observer's internal Go types. Fields carry the registry's honesty
// convention verbatim: an empty string or false means "no grounded
// capability", never a fabricated one.
type contractAdapter struct {
	// Tool is the adapter's canonical name (matches `observer adapters`).
	Tool string `json:"tool"`
	// ProxyRoute names the mechanism observer drives TODAY to point this
	// tool at the proxy ("env_settings", "config_file", "launcher", …), or
	// "" when observer applies no route.
	ProxyRoute string `json:"proxy_route"`
	// Routability is the surface-specific bucket — whether the tool is
	// routable AT ALL, independent of what observer drives today
	// ("routable_now", "after_upstream", "after_bridge", "probe_required",
	// "native_exempt", or "" when unclassified).
	Routability string `json:"routability"`
	// HookMechanism names the hook-registration format ("", when the tool is
	// captured by the watcher / SQLite backfill only).
	HookMechanism string `json:"hook_mechanism"`
	// HookAutoWired is true when `observer init` registers that hook today;
	// false with a non-empty HookMechanism means "receiver exists, not yet
	// auto-wired".
	HookAutoWired bool `json:"hook_auto_wired"`
	// MCPAvailable is true when observer can write its MCP server entry into
	// this client today.
	MCPAvailable bool `json:"mcp_available"`
	// MCPFormat names the client's MCP config shape when one is grounded
	// ("mcp_servers_json", "codex_config_toml", …), else "".
	MCPFormat string `json:"mcp_format"`
	// TokenTier names the strongest token/cost capture source for this tool
	// ("proxy", "sqlite", "transcript", …). "none" means audited and no
	// local source exists; "" means the audit has not happened.
	TokenTier string `json:"token_tier"`
	// TokenGap is a short honest description of a known capture hole, or ""
	// when there is none.
	TokenGap string `json:"token_gap,omitempty"`
	// NativeRails lists which vendor-native console rails exist for this
	// tool: "A" node telemetry, "B" managed config, "C" org analytics API.
	// Empty for the majority of adapters (enrollment-only), which is data,
	// not a hole.
	NativeRails []string `json:"native_rails"`
}

// newContractCmd builds `observer contract` — the machine-readable half of
// the published stability contract (docs/mcp-contract.md). The human form
// summarises the tiers; `--json` emits the artifact an integrator pins.
//
// It is a sibling of `observer adapters`, not a replacement: `adapters`
// renders the FULL internal registry for an operator, while `contract`
// publishes the narrower, promise-bearing subset plus the MCP tool tiers.
func newContractCmd() *cobra.Command {
	var jsonOut bool
	cmd := &cobra.Command{
		Use:   "contract",
		Short: "Show the published stability contract (MCP tool tiers + adapter capabilities)",
		Long: "Prints the stability contract integrators build against: every MCP\n" +
			"tool with its published tier (stable / conditional / experimental)\n" +
			"and every adapter's public capability row. Pass --json for the\n" +
			"machine-readable artifact, which carries a contract_version an\n" +
			"integrator can pin. The prose contract - what each tier actually\n" +
			"promises - lives in docs/mcp-contract.md; this command and that doc\n" +
			"read the same Go table, so they cannot drift.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc := buildContractDoc()
			if jsonOut {
				body, err := json.MarshalIndent(doc, "", "  ")
				if err != nil {
					return fmt.Errorf("contract: marshal: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			renderContract(cmd.OutOrStdout(), doc)
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the contract as JSON instead of a table")
	return cmd
}

// buildContractDoc assembles the artifact from its two single-owner
// sources: internal/mcp's contract table and internal/integration's
// capability registry. It reads them, it never re-derives them.
func buildContractDoc() contractDoc {
	caps := integration.Capabilities()
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	adapters := make([]contractAdapter, 0, len(caps))
	for _, c := range caps {
		adapters = append(adapters, publicAdapterRow(c))
	}
	return contractDoc{
		ContractVersion: contractVersion,
		MCP: contractMCP{
			ServerName: mcp.ServerName,
			Tools:      mcp.ContractTools(),
		},
		Adapters: adapters,
	}
}

// publicAdapterRow projects one registry Capability onto the public row,
// dispatching on the SHAPE of each field (nil pointer, zero value) rather
// than on tool name — the registry's own rule (CLAUDE.md #3).
func publicAdapterRow(c integration.Capability) contractAdapter {
	row := contractAdapter{
		Tool:          c.Tool,
		Routability:   string(c.Routability),
		HookMechanism: string(c.Hook.Mechanism),
		HookAutoWired: c.Hook.AutoWiredNow(),
		TokenTier:     c.TokenTier.Best,
		TokenGap:      c.TokenTier.Gap,
		NativeRails:   nativeRailLetters(c.Native),
	}
	if c.Proxy != nil {
		row.ProxyRoute = string(c.Proxy.Kind)
	}
	if c.MCP != nil {
		row.MCPFormat = string(c.MCP.Format)
		row.MCPAvailable = c.MCP.Implemented
	}
	return row
}

// nativeRailLetters renders the native-console rail bitset as the letters
// the template names them by. Returns an empty (non-nil) slice when no rail
// exists, so the JSON field is always an array.
func nativeRailLetters(n integration.NativeRails) []string {
	out := []string{}
	if n.A {
		out = append(out, "A")
	}
	if n.B {
		out = append(out, "B")
	}
	if n.C {
		out = append(out, "C")
	}
	return out
}

// renderContract writes the human summary: the MCP tier table followed by a
// per-tier count and a pointer to the prose contract.
func renderContract(w io.Writer, doc contractDoc) {
	fmt.Fprintf(w, "SuperBased stability contract v%d\n", doc.ContractVersion)
	fmt.Fprintf(w, "MCP server name: %s   (tools are namespaced mcp__%s__*)\n\n", doc.MCP.ServerName, doc.MCP.ServerName)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "MCP TOOL\tTIER\tPRESENCE")
	counts := map[mcp.ContractTier]int{}
	for _, t := range doc.MCP.Tools {
		counts[t.Tier]++
		presence := "always registered"
		if t.ConfigGated {
			presence = "config-gated"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", t.Name, t.Tier, presence)
	}
	_ = tw.Flush()

	fmt.Fprintf(w, "\n%d tools: %d stable, %d conditional, %d experimental.\n",
		len(doc.MCP.Tools), counts[mcp.TierStable], counts[mcp.TierConditional], counts[mcp.TierExperimental])
	fmt.Fprintf(w, "%d adapter capability rows (see `observer adapters` for the full matrix).\n", len(doc.Adapters))
	fmt.Fprintln(w, "\nWhat each tier promises: docs/mcp-contract.md")
	fmt.Fprintln(w, "Machine-readable artifact: `observer contract --json`")
	fmt.Fprintln(w, "The dashboard HTTP API is NOT part of this contract - integrate over MCP.")
}
