package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/settingsgate"
)

// `observer config get|list` (Plane A build-out W2-8, principle 10): the read
// half of settings parity over the config schema, the same read model the
// MCP get_settings tool serves (settingView). A credential is never printed,
// and a value that looks like one is hidden too; a section the organization
// hid on a managed machine is left out.

// settingView is one key as every read surface shows it.
type settingView struct {
	Key        string `json:"key"`
	Value      any    `json:"value,omitempty"`
	Kind       string `json:"kind"`
	Tier       string `json:"tier"`
	Section    string `json:"section"`
	Restart    string `json:"restart"`
	Prominence string `json:"prominence"`
	// Hidden is set when Value is withheld; HiddenReason says why.
	Hidden       bool   `json:"hidden,omitempty"`
	HiddenReason string `json:"hidden_reason,omitempty"`
	// Writable reports whether `observer config set` can write the key.
	Writable bool `json:"writable"`
	// AgentWrite is what an AI agent's MCP set_setting of this key does for
	// its current value class: apply, propose (needs your approval) or refuse.
	AgentWrite string `json:"agent_write"`
	// Enum lists the allowed values, when the schema closes the set.
	Enum []string `json:"enum,omitempty"`
}

// settingsFilter narrows a list.
type settingsFilter struct {
	// Prefix keeps keys equal to it or under it ("observability.sdk").
	Prefix string
	// Section keeps one Settings section.
	Section string
	// Primary keeps only primary-prominence keys.
	Primary bool
}

func (f settingsFilter) keep(l configschema.Leaf) bool {
	if f.Prefix != "" && l.Path != f.Prefix && !strings.HasPrefix(l.Path, strings.TrimSuffix(f.Prefix, ".")+".") {
		return false
	}
	if f.Section != "" && l.Section != f.Section {
		return false
	}
	return !f.Primary || l.Prominence == configschema.ProminencePrimary
}

// viewSetting renders one leaf of cfg under gov. ok is false when the leaf
// must not be listed at all (its section is hidden by the organization).
func viewSetting(cfg *config.Config, l configschema.Leaf, gov configschema.KeyGovernance) (settingView, bool) {
	if gov != nil && gov.IsSettingsSectionHidden(l.Section) {
		return settingView{}, false
	}
	v := settingView{
		Key: l.Path, Kind: string(l.Kind), Tier: string(l.Tier), Section: l.Section,
		Restart: string(l.Restart), Prominence: string(l.Prominence), Enum: l.Enum,
	}
	c := configschema.CheckKey(l.Path, gov)
	v.Writable = c.Verdict == configschema.KeyOK && l.Kind.Writable()
	val := configschema.Get(cfg, l)
	v.AgentWrite = string(settingsgate.Decide(l.Path, scalarString(l, val), gov).Verdict)
	switch {
	case l.Tier == configschema.TierSecret || l.Secret:
		v.Hidden, v.HiddenReason = true, "a credential; never shown"
	case configschema.SecretShapedLeaf(l, val, agentconfigsvc.DefaultDetect):
		v.Hidden, v.HiddenReason = true, "the value looks like a credential"
	default:
		v.Value = val
	}
	return v, true
}

// scalarString is a value in the `config set` spelling, for the gate's value
// rows (only the destination row reads it).
func scalarString(l configschema.Leaf, v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if rhs, ok := configschema.TOMLScalar(l, v); ok {
		return strings.Trim(rhs, `"`)
	}
	return fmt.Sprint(v)
}

// listSettings returns every leaf that passes f, in schema order.
func listSettings(cfg *config.Config, f settingsFilter, gov configschema.KeyGovernance) []settingView {
	out := []settingView{}
	for _, l := range configschema.Leaves() {
		if !f.keep(l) {
			continue
		}
		if v, ok := viewSetting(cfg, l, gov); ok {
			out = append(out, v)
		}
	}
	return out
}

// getSetting returns one key. A map-entry key resolves to its map leaf.
func getSetting(cfg *config.Config, key string, gov configschema.KeyGovernance) (settingView, error) {
	l, ok := configschema.ResolveKey(strings.TrimSpace(key))
	if !ok {
		return settingView{}, fmt.Errorf("unknown config key %q (try `observer config list --prefix %s`)", key, firstSegment(key))
	}
	v, ok := viewSetting(cfg, l, gov)
	if !ok {
		return settingView{}, fmt.Errorf("%s is managed by your organization and is not available on this machine", key)
	}
	return v, nil
}

func firstSegment(key string) string {
	seg, _, _ := strings.Cut(strings.TrimSpace(key), ".")
	return seg
}

// loadConfigForSettingsRead loads the config and its governance posture.
func loadConfigForSettingsRead(cmd *cobra.Command, configPath string) (config.Config, configschema.KeyGovernance, string, error) {
	resolvedPath, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return config.Config{}, nil, "", fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
	if err != nil {
		return config.Config{}, nil, "", fmt.Errorf("load config: %w", err)
	}
	gov, err := configSetGovernance(cmd.Context(), cfg)
	if err != nil {
		return config.Config{}, nil, "", err
	}
	return cfg, gov, resolvedPath, nil
}

func newConfigGetCmd() *cobra.Command {
	var (
		configPath string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "get <key>",
		Short: "Print one config key's current value (dotted TOML path)",
		Long: "Prints the value in force for one dotted key, e.g.\n" +
			"  observer config get observability.sdk.destination\n\n" +
			"A credential is never printed, and a value that looks like one is hidden.\n" +
			"--json adds the key's tier, section, restart class and what an AI agent's\n" +
			"MCP set_setting would do with it (apply, propose for your approval, or refuse).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, gov, _, err := loadConfigForSettingsRead(cmd, configPath)
			if err != nil {
				return err
			}
			v, err := getSetting(&cfg, args[0], gov)
			if err != nil {
				return err
			}
			if asJSON {
				return writeJSONOut(cmd.OutOrStdout(), v)
			}
			fmt.Fprintln(cmd.OutOrStdout(), settingDisplayValue(v))
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the key's full description as JSON")
	return cmd
}

func newConfigListCmd() *cobra.Command {
	var (
		configPath string
		asJSON     bool
		f          settingsFilter
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List config keys and their current values",
		Long: "Lists every key of the config schema with its value in force, e.g.\n" +
			"  observer config list --prefix observability\n" +
			"  observer config list --section observability --primary\n\n" +
			"Credentials are never printed. A section your organization hid on a\n" +
			"managed machine is left out.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, gov, _, err := loadConfigForSettingsRead(cmd, configPath)
			if err != nil {
				return err
			}
			views := listSettings(&cfg, f, gov)
			if asJSON {
				return writeJSONOut(cmd.OutOrStdout(), views)
			}
			printSettingsTable(cmd.OutOrStdout(), views)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	cmd.Flags().StringVar(&f.Prefix, "prefix", "", "Only keys equal to or under this dotted prefix")
	cmd.Flags().StringVar(&f.Section, "section", "", "Only keys of this Settings section")
	cmd.Flags().BoolVar(&f.Primary, "primary", false, "Only the primary keys (hide advanced and expert ones)")
	return cmd
}

// displayValue is the one-line text form of a view's value.
func settingDisplayValue(v settingView) string {
	if v.Hidden {
		return "(hidden: " + v.HiddenReason + ")"
	}
	switch x := v.Value.(type) {
	case string:
		if x == "" {
			return `""`
		}
		return x
	case []string:
		return strings.Join(x, ",")
	case map[string]string:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+x[k])
		}
		return strings.Join(parts, ",")
	}
	b, err := json.Marshal(v.Value)
	if err != nil {
		return fmt.Sprint(v.Value)
	}
	return string(b)
}

func printSettingsTable(out io.Writer, views []settingView) {
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tVALUE\tTIER\tAGENT WRITE")
	for _, v := range views {
		val := settingDisplayValue(v)
		if len(val) > 60 {
			val = val[:57] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", v.Key, val, v.Tier, v.AgentWrite)
	}
	_ = tw.Flush()
}

func writeJSONOut(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
