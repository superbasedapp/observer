package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// newProfileCmd is the `observer profile` group (Track R, P2.6):
// inspect and assign the compression profiles the proxy resolves per
// traffic class. Writes go through config.WriteToml — the same owner
// the dashboard settings seam uses — and a running daemon is poked
// via POST /api/config/reload so assignments apply to new sessions
// without a restart.
func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Inspect and assign compression profiles (per-provider tuned parameters)",
		Long: "Compression profiles are named parameter sets (the embedded recipes\n" +
			"plus \"default\" = your master config) resolved per traffic class at\n" +
			"the proxy: Anthropic-path requests get the [profiles].by_provider\n" +
			"\"anthropic\" assignment, OpenAI-path requests the \"openai\" one.\n" +
			"The master [compression.conversation] enabled switch stays the one\n" +
			"on/off gate — profiles only supply parameters once it is on.",
	}
	cmd.AddCommand(newProfileListCmd(), newProfileShowCmd(), newProfileAssignCmd(),
		newProfileCreateCmd(), newProfileDeleteCmd(), newProfileSetCmd())
	return cmd
}

func newProfileListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List profiles and their traffic-class assignments",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			// Reverse the assignment table: profile → traffic classes.
			// Tool assignments (R2, more specific than provider ones)
			// render with the same tool: prefix `assign` accepts.
			assigned := map[string][]string{}
			for provider, name := range cfg.Profiles.ByProvider {
				if name != "" {
					assigned[name] = append(assigned[name], provider)
				}
			}
			for tool, name := range cfg.Profiles.ByTool {
				if name != "" && tool != "" {
					assigned[name] = append(assigned[name], "tool:"+tool)
				}
			}
			for _, v := range assigned {
				sort.Strings(v)
			}
			tableDefault := cfg.Profiles.Default
			if tableDefault == "" {
				tableDefault = config.DefaultProfileName
			}

			resolvedPath, _ := config.ResolveGlobalPath(configPath)
			store := config.ProfileStore{Dir: config.DefaultProfilesDir(resolvedPath)}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "PROFILE\tSOURCE\tASSIGNED TO")
			for _, name := range store.Names() {
				source := "built-in"
				switch {
				case name == config.DefaultProfileName:
					source = "master config"
				case !config.IsBuiltin(name):
					source = "user"
				}
				classes := assigned[name]
				if name == tableDefault {
					classes = append(classes, "(everything else)")
				}
				col := strings.Join(classes, ", ")
				if col == "" {
					col = "—"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", name, source, col)
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			resolved := resolvedPath
			fmt.Fprintf(cmd.OutOrStdout(),
				"\nassignments live in [profiles] of %s\n"+
					"compression on/off stays [compression.conversation] enabled (master config)\n"+
					"edits apply to new sessions without a daemon restart\n", resolved)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newProfileShowCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "show <profile>",
		Short: "Print a profile's parameters as resolved against your master config",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			resolvedPath, _ := config.ResolveGlobalPath(configPath)
			store := config.ProfileStore{Dir: config.DefaultProfilesDir(resolvedPath)}
			resolvedCompression, _, err := store.ResolveCompression(cfg.Compression, name)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(),
				"# profile %q resolved against master config (%s)\n"+
					"# profile keys overlay master parameters; conversation `enabled`\n"+
					"# is always master-owned\n",
				name, resolvedPath)
			enc := toml.NewEncoder(cmd.OutOrStdout())
			return enc.Encode(struct {
				Compression config.CompressionConfig `toml:"compression"`
			}{resolvedCompression})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newProfileAssignCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "assign <anthropic|openai|default|tool:NAME> <profile>",
		Short: "Assign a profile to a traffic class (writes [profiles] in config.toml)",
		Long: "Assigns the named profile to a traffic class:\n" +
			"  anthropic   requests on the Anthropic Messages API path (Claude Code, …)\n" +
			"  openai      requests on the OpenAI paths (codex, …)\n" +
			"  default     everything without a more specific assignment\n" +
			"  tool:NAME   one specific tool (R2; e.g. tool:cline, tool:kilo-code-cli) —\n" +
			"              wins over the provider assignment when the proxy can resolve\n" +
			"              the connection's owning tool via the session hook bridge\n\n" +
			"Writes [profiles] in config.toml through the same atomic write+backup\n" +
			"path as dashboard saves, then pokes a running daemon so NEW sessions\n" +
			"pick the assignment up immediately (in-flight sessions keep the\n" +
			"parameters they started with).",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, name := args[0], args[1]
			resolvedPath, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return fmt.Errorf("resolve config path: %w", err)
			}
			store := config.ProfileStore{Dir: config.DefaultProfilesDir(resolvedPath)}
			if err := store.Validate(name); err != nil {
				return err
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: resolvedPath})
			if err != nil {
				return fmt.Errorf("load config: %w", err)
			}
			switch {
			case target == "default":
				cfg.Profiles.Default = name
			case target == models.ProviderAnthropic || target == models.ProviderOpenAI:
				if cfg.Profiles.ByProvider == nil {
					cfg.Profiles.ByProvider = map[string]string{}
				}
				cfg.Profiles.ByProvider[target] = name
			case strings.HasPrefix(target, "tool:"):
				tool := strings.TrimPrefix(target, "tool:")
				if tool == "" {
					return fmt.Errorf("tool: prefix needs a tool name (e.g. tool:cline)")
				}
				if cfg.Profiles.ByTool == nil {
					cfg.Profiles.ByTool = map[string]string{}
				}
				cfg.Profiles.ByTool[tool] = name
			default:
				return fmt.Errorf("unknown traffic class %q (valid: anthropic, openai, default, tool:NAME)", target)
			}
			if err := config.WriteToml(resolvedPath, cfg); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "assigned %s → %s (saved to %s)\n", target, name, resolvedPath)
			if pokeReload() {
				fmt.Fprintln(cmd.OutOrStdout(), "daemon reloaded — new sessions use this assignment now")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "no running daemon detected on the dashboard port — applies on next start")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// pokeReload points at pokeConfigReload; tests stub it so `profile
// assign` runs never touch a real daemon (WSL2 forwards localhost, so
// a live WSL daemon IS reachable from Windows-host test runs).
var pokeReload = pokeConfigReload

// pokeConfigReload asks a locally running daemon (dashboard on the
// default port) to re-read config for its hot-reloadable consumers —
// the P2.5 profile router. Best-effort: a short timeout, false on any
// failure, and false when the dashboard answered but no hook is wired
// (standalone `observer dashboard` with no proxy in-process).
func pokeConfigReload() bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Post("http://127.0.0.1:8081/api/config/reload", "application/json", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	var body struct {
		Reloaded bool `json:"reloaded"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false
	}
	return body.Reloaded
}

func profileStoreFor(configPath string) (config.ProfileStore, error) {
	resolvedPath, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return config.ProfileStore{}, fmt.Errorf("resolve config path: %w", err)
	}
	return config.ProfileStore{Dir: config.DefaultProfilesDir(resolvedPath)}, nil
}

func newProfileCreateCmd() *cobra.Command {
	var (
		configPath string
		from       string
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a custom profile (~/.observer/profiles/<name>.toml)",
		Long: "Creates a user profile file. --from seeds it: a built-in name copies\n" +
			"that recipe's keys verbatim (tuned starting point, comments included);\n" +
			"another user profile copies its file; omitted (or \"default\") writes an\n" +
			"empty parameter file — master passthrough until you set keys.\n" +
			"Edit with `observer profile set <name> <key> <value>`, then assign it.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := profileStoreFor(configPath)
			if err != nil {
				return err
			}
			if err := store.Create(args[0], from); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "created profile %s (from %s)\n", args[0], orDefault(from))
			fmt.Fprintf(cmd.OutOrStdout(), "  edit:   observer profile set %s compression.conversation.target_ratio 0.9\n", args[0])
			fmt.Fprintf(cmd.OutOrStdout(), "  assign: observer profile assign <anthropic|openai|default|tool:NAME> %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&from, "from", "", "Profile to seed from ("+strings.Join(config.ProfileNames(), ", ")+", or another user profile)")
	return cmd
}

func newProfileDeleteCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a custom profile (built-ins are immutable)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := profileStoreFor(configPath)
			if err != nil {
				return err
			}
			if err := store.Delete(args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted profile %s\n", args[0])
			fmt.Fprintln(cmd.OutOrStdout(), "sessions assigned to it fall back to master parameters (the default profile) until you reassign")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newProfileSetCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "set <name> <key> <value>",
		Short: "Set one compression key in a custom profile",
		Long: "Sets a dotted compression key in a user profile file, e.g.:\n" +
			"  observer profile set my-tuning compression.conversation.target_ratio 0.9\n" +
			"Built-ins are immutable — copy one first with `profile create --from`.\n" +
			"Edits apply to NEW sessions automatically (no restart, no poke): the\n" +
			"daemon folds the profile file's generation into its routing key.",
		Args: cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := profileStoreFor(configPath)
			if err != nil {
				return err
			}
			if err := store.SetKey(args[0], args[1], args[2]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "set %s = %s in profile %s\n", args[1], args[2], args[0])
			fmt.Fprintln(cmd.OutOrStdout(), "applies to new sessions automatically")
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func orDefault(from string) string {
	if from == "" {
		return config.DefaultProfileName
	}
	return from
}
