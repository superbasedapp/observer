package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigorg"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer agent-config`: the CLI twin of the dashboard's AI tool settings
// page (backlog items 2 and 7, phases P4 and P5). Every verb drives the same
// internal/agentconfigsvc boundary the dashboard does, so the sanity check,
// the backup, the read-back and the managed-node read-only posture are the
// same. Secrets are shown as present / absent, never by value.

func newAgentConfigCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "agent-config",
		Short: "Read and edit each AI tool's own settings and instruction files, with a sanity check before every save",
		Long: "Inspect and edit the settings files of every AI coding tool Observer knows\n" +
			"(the same view as the dashboard's AI tool settings page). Every write runs\n" +
			"the sanity check first: the file must still parse, the value must match the\n" +
			"tool's documented type, settings that loosen safety need --yes, Observer's\n" +
			"own hook and MCP entries are never removed, and the previous file is kept as\n" +
			"a backup and the new one read back before the save counts.",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.AddCommand(
		newAgentConfigInspectCmd(&configPath),
		newAgentConfigCoverageCmd(),
		newAgentConfigSetCmd(&configPath, false),
		newAgentConfigSetCmd(&configPath, true),
		newAgentConfigCommonCmd(&configPath),
		newAgentConfigInstructionsCmd(&configPath),
		newAgentConfigHistoryCmd(&configPath),
		newAgentConfigOrgCmd(&configPath),
	)
	return cmd
}

// agentConfigEnv is the service plus its cleanup.
type agentConfigEnv struct {
	svc *agentconfigsvc.Service
	// orgSvc is the same boundary with the "org" history origin (the org
	// AI tool policy apply).
	orgSvc *agentconfigsvc.Service
	access agentconfig.Access
	// st is the node store (nil when the database does not exist yet);
	// managed is a managed enrolment holding a live grant.
	st      *store.Store
	managed bool
	cleanup func()
}

// openAgentConfig builds the service the way the dashboard does: the node's
// layer store when its database exists, the hook package's settings lock,
// the captured-adapter list and the managed-node posture.
func openAgentConfig(ctx context.Context, configPath string) (agentConfigEnv, error) {
	resolved, err := config.ResolveGlobalPath(configPath)
	if err != nil {
		return agentConfigEnv{}, fmt.Errorf("resolve config path: %w", err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: resolved})
	if err != nil {
		return agentConfigEnv{}, fmt.Errorf("load config: %w", err)
	}
	env := agentConfigEnv{cleanup: func() {}, access: agentconfig.Access{SecretsPosture: agentconfig.SecretsWarn}}
	var st agentconfigsvc.LayerStore
	if _, statErr := os.Stat(cfg.Observer.DBPath); statErr == nil {
		database, cleanup, derr := openDBForConfig(ctx, cfg)
		if derr == nil {
			env.cleanup = cleanup
			st = store.New(database)
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			eff := repriceCLIGovernance(ctx, cfg, database, logger)(ctx)
			env.st, env.managed = store.New(database), eff.ManagedDefaultsApply()
			env.access = agentConfigCLIAccess(ctx, eff, env.st)
		} else {
			env.access = agentConfigUnreadablePosture(derr)
		}
	}
	captured := map[string]bool{}
	for _, a := range cfg.Observer.Watch.EnabledAdapters {
		captured[a] = true
	}
	port := cfg.Proxy.Port
	access := env.access
	build := func(origin string) *agentconfigsvc.Service {
		return agentconfigsvc.New(agentconfigsvc.Options{
			Store: st,
			Lock:  hook.LockSettingsFile,
			ProxyAddrs: []string{
				fmt.Sprintf("127.0.0.1:%d", port), fmt.Sprintf("localhost:%d", port), fmt.Sprintf("[::1]:%d", port),
			},
			Captured:   func(tool string) bool { return captured[tool] },
			Access:     func(context.Context) agentconfig.Access { return access },
			EditGrants: cliConfigEditGrants(env.st),
			Origin:     origin,
		})
	}
	env.svc, env.orgSvc = build("cli"), build("org")
	return env, nil
}

// agentConfigUnreadablePosture is the CLI editor's posture when the node
// database EXISTS but cannot be opened (review M3-15, D-102): the machine may
// be managed, and its org locks, grants and read-only default live in that
// database, so the editor fails closed (read-only, saying why) instead of
// treating the machine as unmanaged for this run. A machine with no database
// yet has never enrolled and stays editable (openAgentConfig's other branch).
func agentConfigUnreadablePosture(err error) agentconfig.Access {
	return agentconfig.Access{
		ReadOnly:       true,
		SecretsPosture: agentconfig.SecretsWarn,
		Reason: "Observer cannot read this machine's organization posture (" + err.Error() +
			"), so AI tool settings are read-only until it can. Check that the Observer database is readable, then try again.",
	}
}

// agentConfigCLIAccess is the dashboard's agentConfigAccess rule
// (agentconfigorg.NodeAccess): read-only on a managed node until its
// organization's AI tool policy arrives, then that policy's locks, grants
// and secrets posture; an org-pinned page is read-only anywhere.
func agentConfigCLIAccess(ctx context.Context, eff govern.Effective, st *store.Store) agentconfig.Access {
	lvl, src := eff.NavVisibility("agent-config")
	in := agentconfigorg.NodeAccessInput{
		Managed:         eff.ManagedDefaultsApply(),
		PageReadOnly:    lvl == nodegov.VisibilityReadOnly,
		PageFromDefault: src == govern.VisibilitySourceDefault,
	}
	if in.Managed && st != nil {
		if body, _, ok := st.OrgAgentConfigBody(ctx); ok {
			in.Body = &body
		}
		in.EditGrants = cliConfigEditGrants(st)(ctx, time.Now())
	}
	return agentconfigorg.NodeAccess(in)
}

// cliConfigEditGrants reads the honoured AI tool setting edit grants
// (T-436) from st's verified grant cache; nil st or any failure opens
// nothing.
func cliConfigEditGrants(st *store.Store) func(context.Context, time.Time) []string {
	return func(ctx context.Context, now time.Time) []string {
		if st == nil {
			return nil
		}
		got, err := orgclient.ConfigEditGrants(ctx, st, now)
		if err != nil {
			return nil
		}
		return got
	}
}

func absProject(p string) (string, error) {
	if strings.TrimSpace(p) == "" {
		return "", nil
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() { //nolint:gosec // G703: false positive; the operator's own --project flag on their own machine, only stat'd to check it is a directory
		return "", fmt.Errorf("--project %s is not a directory", p)
	}
	return abs, nil
}

func printJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newAgentConfigInspectCmd(configPath *string) *cobra.Command {
	var tool, project string
	var asJSON, all bool
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "List AI tools, or one tool's settings files and effective values",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := openAgentConfig(cmd.Context(), *configPath)
			if err != nil {
				return err
			}
			defer env.cleanup()
			out := cmd.OutOrStdout()
			if tool == "" {
				rows := env.svc.Tools(cmd.Context())
				if asJSON {
					return printJSON(out, rows)
				}
				tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
				fmt.Fprintln(tw, "TOOL\tINSTALLED\tFILES\tSETTINGS\tVERIFIED\tSOURCE")
				for _, r := range rows {
					fmt.Fprintf(tw, "%s\t%v\t%d/%d\t%d\t%d\t%s\n", r.Tool, r.Installed, r.FilesPresent, r.Files, r.Rows, r.Verified, r.Status)
				}
				return tw.Flush()
			}
			proj, err := absProject(project)
			if err != nil {
				return err
			}
			v, err := env.svc.Inspect(cmd.Context(), tool, proj)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(out, v)
			}
			printToolView(out, v, env.svc.RelocationNotes(tool, proj), all)
			return nil
		},
	}
	cmd.Flags().StringVar(&tool, "tool", "", "Tool id (see `observer agent-config inspect`)")
	cmd.Flags().StringVar(&project, "project", "", "Project root (adds the tool's project files)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	cmd.Flags().BoolVar(&all, "all", false, "List every catalogued setting, not only the ones set somewhere")
	return cmd
}

// printToolView prints a tool view; relocated maps a file id to the note
// saying which relocation variable moved it (Service.RelocationNotes).
func printToolView(out io.Writer, v agentconfig.ToolView, relocated map[string]string, all bool) {
	if v.Access.ReadOnly {
		fmt.Fprintf(out, "read-only: %s\n\n", v.Access.Reason)
	}
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tSCOPE\tSTATE\tPATH\tNOTES")
	for _, f := range v.Files {
		var notes []string
		if f.ParseError != "" {
			notes = append(notes, "does not parse")
		}
		if n := len(f.Secrets); n > 0 {
			notes = append(notes, agentconfig.CountNoun(n, "secret", "")+" present")
		}
		for _, sp := range f.Spans {
			if sp.Live {
				notes = append(notes, "observer entries")
				break
			}
		}
		if !f.Editable && f.NotEditable != "" && f.State != agentconfig.FileNeverRead {
			notes = append(notes, "read-only")
		}
		// Which relocation variable moved the file (so the PATH column is the
		// file a save edits), or why a set one leaves it without a path.
		if n := relocated[f.ID]; n != "" {
			notes = append(notes, n)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.ID, f.Scope, f.State, f.Path, strings.Join(notes, ", "))
	}
	_ = tw.Flush()
	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SETTING\tVALUE\tDECIDED BY")
	for _, s := range v.Settings {
		if !all && !s.Effective.Set {
			continue
		}
		val := "(tool default)"
		switch {
		case s.Effective.SecretPresent:
			val = "(set, hidden)"
		case s.Effective.Set:
			b, _ := json.Marshal(s.Effective.Value)
			val = string(b)
		}
		by := "tool default"
		if s.Effective.Set {
			by = string(s.Effective.Layer) + " " + s.Effective.FileID
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", s.Path, val, by)
	}
	_ = tw.Flush()
}

func newAgentConfigCoverageCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "coverage",
		Short: "Show how much of each tool's settings Observer's catalogue knows",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rows := agentconfig.Coverage()
			out := cmd.OutOrStdout()
			if asJSON {
				return printJSON(out, map[string]any{"coverage": rows, "schemas": agentconfig.SchemaPins()})
			}
			tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "TOOL\tSOURCE\tSETTINGS\tVERIFIED\tWRITABLE\tSAFETY\tCHECKED AGAINST")
			for _, c := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%d\t%d\t%s\n", c.Tool, c.Status, c.Rows, c.Verified, c.Writable, c.Dangerous, c.VerifiedAgainst)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return cmd
}

// parseCLIValue reads a value as JSON when it parses (numbers, booleans,
// arrays, objects, quoted strings) and as plain text otherwise.
func parseCLIValue(s string) any {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err == nil {
		return v
	}
	return s
}

// pickSettingFile resolves which file a setting is written to: --file when
// given, else the lowest-precedence editable file of the setting's shape in
// an allowed scope (the user file, or the project-local file with --project
// and --scope).
func pickSettingFile(v agentconfig.ToolView, s agentconfig.SettingView, fileID, scope string) (string, error) {
	if fileID != "" {
		return fileID, nil
	}
	var cands []agentconfig.FileView
	for _, f := range v.Files {
		if f.Shape != s.Shape || !f.Editable {
			continue
		}
		if scope != "" && string(f.Scope) != scope {
			continue
		}
		if len(s.Scopes) > 0 && !containsScope(s.Scopes, f.Scope) {
			continue
		}
		cands = append(cands, f)
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].Precedence < cands[j].Precedence })
	if len(cands) == 0 {
		// Say why before the generic note: an org lock or a missing grant
		// is what makes a managed machine's file read-only.
		switch {
		case s.Locked != "":
			return "", fmt.Errorf("%s is set by your organization's policy %s and cannot be changed here", s.ID, s.Locked)
		case s.ReadOnlyReason != "":
			return "", fmt.Errorf("%s: %s", s.ID, s.ReadOnlyReason)
		}
		return "", fmt.Errorf("no editable file of %s takes %s here (try --project or --file)", v.Tool, s.Path)
	}
	return cands[0].ID, nil
}

func containsScope(set []agentconfig.Scope, s agentconfig.Scope) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func findSetting(v agentconfig.ToolView, key string) (agentconfig.SettingView, bool) {
	for _, s := range v.Settings {
		if s.Path == key || s.ID == key {
			return s, true
		}
	}
	return agentconfig.SettingView{}, false
}

func newAgentConfigSetCmd(configPath *string, unset bool) *cobra.Command {
	var fileID, project, scope string
	var dryRun, yes bool
	use, short, nargs := "set <tool> <setting> <value>", "Set one setting in a tool's settings file (checked, backed up, read back)", 3
	if unset {
		use, short, nargs = "unset <tool> <setting>", "Remove one setting from a tool's settings file so the next layer decides", 2
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(nargs),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := openAgentConfig(cmd.Context(), *configPath)
			if err != nil {
				return err
			}
			defer env.cleanup()
			proj, err := absProject(project)
			if err != nil {
				return err
			}
			tool, key := args[0], args[1]
			v, err := env.svc.Inspect(cmd.Context(), tool, proj)
			if err != nil {
				return err
			}
			s, ok := findSetting(v, key)
			if !ok {
				return fmt.Errorf("%s has no catalogued setting %q (see `observer agent-config inspect --tool %s --all`)", tool, key, tool)
			}
			fid, err := pickSettingFile(v, s, fileID, scope)
			if err != nil {
				return err
			}
			edit := agentconfig.Edit{Path: agentconfig.KeyPath(strings.Split(s.Path, ".")), Op: agentconfig.OpDelete}
			if !unset {
				edit.Op, edit.Value = agentconfig.OpSet, parseCLIValue(args[2])
			}
			req := agentconfigsvc.SaveRequest{
				Target: agentconfigsvc.Target{Tool: tool, FileID: fid, Project: proj},
				Edits:  []agentconfig.Edit{edit},
			}
			return runAgentConfigSave(cmd.Context(), cmd.OutOrStdout(), env, req, dryRun, yes)
		},
	}
	cmd.Flags().StringVar(&fileID, "file", "", "File id to write (default: the tool's user settings file)")
	cmd.Flags().StringVar(&project, "project", "", "Project root (needed for a project-scope file)")
	cmd.Flags().StringVar(&scope, "scope", "", "Scope to write: user, project_shared or project_local")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Run the sanity check and print the diff without writing")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm a change that loosens the tool's safety")
	return cmd
}

// runAgentConfigSave previews, prints the findings and diff, and saves with
// the preview's etag (so a file that changed in between is refused).
func runAgentConfigSave(ctx context.Context, out io.Writer, env agentConfigEnv, req agentconfigsvc.SaveRequest, dryRun, yes bool) error {
	pv, err := env.svc.Preview(ctx, req)
	if err != nil {
		return err
	}
	printFindings(out, pv.Findings)
	if pv.NoChange {
		fmt.Fprintf(out, "%s already says this; nothing to save\n", pv.Path)
		return nil
	}
	fmt.Fprint(out, pv.Diff)
	if dryRun {
		fmt.Fprintf(out, "dry run: %s, +%d -%d lines; nothing written\n", verdictText(pv.SaveResult), pv.DiffStats.Added, pv.DiffStats.Removed)
		return nil
	}
	if env.access.ReadOnly {
		return errors.New("read-only: " + env.access.Reason)
	}
	if pv.NeedsConfirm && !yes {
		return errors.New("this change loosens the tool's safety; review the findings above and re-run with --yes")
	}
	req.PreviewEtag, req.Confirm = pv.PreviewEtag, yes
	res, err := env.svc.Save(ctx, req)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "saved %s", res.Path)
	if res.BackupPath != "" {
		fmt.Fprintf(out, " (previous file kept at %s)", res.BackupPath)
	}
	fmt.Fprintln(out)
	if res.Excluded != "" {
		fmt.Fprintf(out, "added %s to .git/info/exclude\n", res.Excluded)
	}
	return nil
}

func verdictText(r agentconfig.SaveResult) string {
	switch {
	case r.OK:
		return "ready to save"
	case r.NeedsConfirm:
		return "needs --yes"
	}
	return "refused"
}

func printFindings(out io.Writer, fs []agentconfig.Finding) {
	for _, f := range fs {
		path := ""
		if f.Path != "" {
			path = f.Path + ": "
		}
		fmt.Fprintf(out, "%s: %s%s\n", f.Severity, path, f.Message)
	}
}

func newAgentConfigCommonCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "common",
		Short: "Set one value in every installed AI tool that has it (model, approval mode, MCP servers, ...)",
	}
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List the shared keys with each tool's current value",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := openAgentConfig(cmd.Context(), *configPath)
			if err != nil {
				return err
			}
			defer env.cleanup()
			keys, err := env.svc.CommonView(cmd.Context(), "")
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), keys)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tTIER\tTOOLS\tSET IN")
			for _, k := range keys {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\n", k.Spec.Key, k.Spec.Tier, k.Exposed, k.SetIn)
			}
			return tw.Flush()
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	cmd.AddCommand(list, newAgentConfigCommonWriteCmd(configPath, false), newAgentConfigCommonWriteCmd(configPath, true))
	return cmd
}

func newAgentConfigCommonWriteCmd(configPath *string, clear bool) *cobra.Command {
	var dryRun, yes bool
	var project, placement string
	use, nargs := "set <key> <value>", 2
	short := "Write one value into every installed tool that exposes the key (all or nothing)"
	if clear {
		use, nargs, short = "clear <key>", 1, "Remove the key from every installed tool's user settings"
	}
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(nargs),
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := openAgentConfig(cmd.Context(), *configPath)
			if err != nil {
				return err
			}
			defer env.cleanup()
			root, err := absProject(project)
			if err != nil {
				return err
			}
			req := agentconfigsvc.CommonRequest{Key: agentconfig.CommonKey(args[0]), Clear: clear, Project: root, Placement: placement}
			if !clear {
				req.Value = parseCLIValue(args[1])
			}
			out := cmd.OutOrStdout()
			pv, err := env.svc.CommonPreview(cmd.Context(), req)
			if err != nil {
				return err
			}
			for _, t := range pv.Targets {
				line := fmt.Sprintf("%s: %s", t.Tool, t.Status)
				if t.Reason != "" {
					line += " (" + t.Reason + ")"
				}
				fmt.Fprintln(out, line)
				if t.Preview != nil {
					printFindings(out, t.Preview.Findings)
					fmt.Fprint(out, t.Preview.Diff)
				}
			}
			if dryRun {
				fmt.Fprintf(out, "dry run: %s would change; nothing written\n", agentconfig.CountNoun(pv.Writes, "file", ""))
				return nil
			}
			if env.access.ReadOnly {
				return errors.New("read-only: " + env.access.Reason)
			}
			if pv.NeedsConfirm && !yes {
				return errors.New("this change loosens the tools' safety; review the above and re-run with --yes")
			}
			req.PreviewEtag, req.Confirm = pv.PreviewEtag, yes
			res, err := env.svc.CommonSave(cmd.Context(), req)
			if err != nil {
				return err
			}
			for _, w := range res.Written {
				fmt.Fprintf(out, "saved %s\n", w.Path)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview every tool's change without writing")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm a change that loosens the tools' safety")
	cmd.Flags().StringVar(&project, "project", "", "Project root: write each tool's project file there instead of its user file")
	cmd.Flags().StringVar(&placement, "placement", agentconfigsvc.CommonPlacementLocalOnly, "With --project: local_only (each tool's personal, git-excluded file) or shared (the file a commit carries)")
	return cmd
}

func newAgentConfigInstructionsCmd(configPath *string) *cobra.Command {
	var tool, project string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "instructions",
		Short: "List a tool's instruction, rule, skill and subagent files",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tool == "" {
				return errors.New("--tool is required")
			}
			env, err := openAgentConfig(cmd.Context(), *configPath)
			if err != nil {
				return err
			}
			defer env.cleanup()
			proj, err := absProject(project)
			if err != nil {
				return err
			}
			files, err := env.svc.Instructions(cmd.Context(), tool, proj)
			if err != nil {
				return err
			}
			if asJSON {
				return printJSON(cmd.OutOrStdout(), files)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KIND\tSCOPE\tEXISTS\tPATH")
			for _, f := range files {
				p := f.Path
				if f.NewName {
					p = f.Glob + " (new)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%v\t%s\n", f.Kind, f.Scope, f.Exists, p)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&tool, "tool", "", "Tool id")
	cmd.Flags().StringVar(&project, "project", "", "Project root")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print JSON")
	return cmd
}

func newAgentConfigHistoryCmd(configPath *string) *cobra.Command {
	var tool string
	var limit int
	cmd := &cobra.Command{
		Use:   "history",
		Short: "List saves made through Observer (key names only, never values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			env, err := openAgentConfig(cmd.Context(), *configPath)
			if err != nil {
				return err
			}
			defer env.cleanup()
			rows, err := env.svc.History(cmd.Context(), tool, limit)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "WHEN\tTOOL\tFROM\tKEYS\tPATH")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.At.UTC().Format("2006-01-02 15:04"), r.Tool, r.Origin, strings.Join(r.ChangedKeys, ","), r.FilePath)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&tool, "tool", "", "Only this tool")
	cmd.Flags().IntVar(&limit, "limit", 50, "Rows to show")
	return cmd
}
