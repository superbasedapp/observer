package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
	"github.com/marmutapp/superbased-observer/internal/guardrecipesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newGuardRecipeCmd is `observer guard recipe`: quick-setup recipes for the
// developer guard. A recipe is a strictness LEVEL (none, loose, balanced,
// strict, lockdown, or one of your own) plus any number of function PACKS
// (frontend, backend-database, devops-infra, networking, data-ml, regulated,
// ...), applied to this machine or to one project as a managed file the guard
// folds in before your own policy file, so your own edits win and remove
// takes the whole block out again. The dashboard's Security > Rules > Recipes
// card runs the same service (internal/guardrecipesvc).
//
// apply, remove, save and delete change what the guard enforces, so guard
// rule R-165 denies an agent running them (internal/policy/
// rules_selfapproval.go): a recipe is a person's choice.
func newGuardRecipeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recipe",
		Short: "Quick-setup recipes: a strictness level plus function packs, applied as one removable block",
		Long: "A recipe sets the guard up in one step. Pick a strictness level\n" +
			"(none, loose, balanced, strict, lockdown) and any packs for the work\n" +
			"you do (frontend, backend-database, devops-infra, networking,\n" +
			"data-ml, regulated). Apply it to this machine or to one project:\n\n" +
			"  observer guard recipe list\n" +
			"  observer guard recipe apply --level strict --pack networking --dry-run\n" +
			"  observer guard recipe apply --level balanced --pack frontend --project . --yes\n" +
			"  observer guard recipe remove --yes\n\n" +
			"The recipe lands in a managed file beside your policy file\n" +
			"(guard-policy.recipe.toml, or <hash>.recipe.toml for a project).\n" +
			"Your own policy file still wins over it, and an organization's\n" +
			"policy wins over both. Your own recipes live in\n" +
			"~/.observer/guard-recipes/<name>.toml (see `recipe save`).",
	}
	cmd.AddCommand(newGuardRecipeListCmd())
	cmd.AddCommand(newGuardRecipeShowCmd())
	cmd.AddCommand(newGuardRecipeApplyCmd())
	cmd.AddCommand(newGuardRecipeRemoveCmd())
	cmd.AddCommand(newGuardRecipeSaveCmd())
	cmd.AddCommand(newGuardRecipeDeleteCmd())
	return cmd
}

// guardRecipeCLI is what every recipe verb needs: the service env, the
// catalog and the config file path the writes go to.
type guardRecipeCLI struct {
	env        guardrecipesvc.Env
	set        *guardrecipe.Set
	configPath string
	st         *store.Store
	closeDB    func()
}

// recipeDBUse says when a recipe verb opens observer.db (sweep finding
// SA-12): db.Open creates a missing file and migrates an old one, so a
// verb that only reads or previews must not open it for nothing.
type recipeDBUse int

const (
	// recipeDBNever: show, and a dry run without --replay. The known
	// project roots stay unknown (the "not seen yet" note is skipped).
	recipeDBNever recipeDBUse = iota
	// recipeDBIfPresent: list (the projects with a recipe come from the
	// known roots) and a dry run's --replay (the captured history). A
	// missing database is not created.
	recipeDBIfPresent
	// recipeDBWrite: apply, remove, save and delete, which write their
	// guard_recipe_* audit row into it.
	recipeDBWrite
)

// previewDBUse is the recipeDBUse of an apply or remove: a dry run is a
// preview, which reads the database only for --replay.
func (f *recipeWriteFlags) previewDBUse() recipeDBUse {
	switch {
	case !f.dryRun:
		return recipeDBWrite
	case f.replay > 0:
		return recipeDBIfPresent
	default:
		return recipeDBNever
	}
}

// openGuardRecipeCLI loads config, the known project roots (best effort:
// without a database the project list is just empty) and the catalog. use
// decides whether observer.db is opened at all.
func openGuardRecipeCLI(ctx context.Context, configFlag string, use recipeDBUse) (*guardRecipeCLI, error) {
	path, err := resolveGuardConfigPath(configFlag)
	if err != nil {
		return nil, err
	}
	cfg, gov, err := config.LoadGovernance(config.LoadOptions{GlobalPath: configFlag})
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	home, _ := os.UserHomeDir()
	c := &guardRecipeCLI{configPath: path, closeDB: func() {}}
	var roots []string
	if cfg.Observer.DBPath != "" && use != recipeDBNever {
		_, statErr := os.Stat(cfg.Observer.DBPath)
		if use == recipeDBWrite || statErr == nil {
			if database, derr := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath}); derr == nil {
				c.st = store.New(database)
				c.closeDB = func() { _ = database.Close() }
				roots, _ = c.st.ProjectRoots(ctx)
			}
		}
	}
	c.env = guardrecipesvc.Env{Config: cfg, Home: home, KnownProjectRoots: roots, GovernancePins: gov.PinsInForce}
	if c.st != nil {
		// A captured prompt a hook or proxy lane already judged before send is
		// not re-flagged by a replay, as in `observer guard simulate`.
		st := c.st
		c.env.Prepare = func(g *guard.Guard) { g.SetPromptPreSendLookup(preSendPromptLookup(st, nil)) }
	}
	set, err := guardrecipesvc.Catalog(c.env)
	if err != nil {
		c.closeDB()
		return nil, err
	}
	c.set = set
	return c, nil
}

// recipeScope resolves --project into a scope and a project root. "." (or
// any directory) resolves to its git root, as `observer guard test` does.
func recipeScope(project string) (guardrecipe.Scope, string, error) {
	if strings.TrimSpace(project) == "" {
		return guardrecipe.ScopeGlobal, "", nil
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return "", "", fmt.Errorf("--project: %w", err)
	}
	if r, ok := git.FindRoot(abs); ok {
		abs = r
	}
	return guardrecipe.ScopeProject, abs, nil
}

// audit writes one guard_recipe_* row for a CLI write, the row the
// dashboard's recordManageAudit writes for the same write, through the same
// store seam (store.InsertRemoteAudit; sweep finding CFG-6 / SA-11).
// Best-effort, as on the dashboard: the write already happened.
func (c *guardRecipeCLI) audit(ctx context.Context, action, detail string) {
	if c.st == nil {
		return
	}
	actx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = c.st.InsertRemoteAudit(actx, store.RemoteAuditEvent{
		Kind: "manage", Principal: "local", Route: "cli: observer guard recipe", Decision: "ok",
		Detail: strings.TrimSpace(action + " " + detail),
	})
}

// escapeTerminalControls makes text safe to print to a terminal (sweep
// finding RC-9, the output half): a recipe's title, summary, notes and
// advice, and an applied file's header, are file text, and a control
// character in one (ESC, BEL, a carriage return, a C1 CSI) would drive the
// terminal instead of being read. Newline and tab are kept; every other C0
// control and DEL prints as \xNN (a carriage return as \r), a C1 control
// (U+0080 to U+009F) as \uNNNN, and a raw byte 0x80 to 0x9F that is not
// UTF-8 (an 8-bit C1) as \xNN. JSON output stays valid: the encoder has
// already escaped every C0 control, and a C1 rune becomes a JSON \u escape.
func escapeTerminalControls(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if b := s[i]; (b < 0x20 && b != '\n' && b != '\t') || b == 0x7f || b == 0xc2 || (b >= 0x80 && b <= 0x9f) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			if c := s[i]; c >= 0x80 && c <= 0x9f {
				fmt.Fprintf(&b, `\x%02x`, c)
			} else {
				b.WriteByte(c)
			}
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r >= 0x80 && r <= 0x9f:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// controlEscapingWriter passes everything written through
// escapeTerminalControls. Each fmt.Fprint call writes whole strings, so a
// rune is never split across two writes.
type controlEscapingWriter struct{ w io.Writer }

func (c controlEscapingWriter) Write(p []byte) (int, error) {
	if _, err := io.WriteString(c.w, escapeTerminalControls(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}

// recipeOut is a recipe verb's output: escaped for a terminal.
func recipeOut(cmd *cobra.Command) io.Writer {
	return controlEscapingWriter{w: cmd.OutOrStdout()}
}

// writerIsTerminal reports whether w is a terminal (show --toml prints the
// file as it is unless a person is reading it there).
func writerIsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// knownRoot reports whether Observer has seen a session in root.
func (c *guardRecipeCLI) knownRoot(root string) bool {
	want := filepath.Clean(root)
	for _, r := range c.env.KnownProjectRoots {
		if filepath.Clean(r) == want {
			return true
		}
	}
	return false
}

func writeRecipeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func newGuardRecipeListCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the levels and packs, and what is applied where",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := openGuardRecipeCLI(cmd.Context(), configPath, recipeDBIfPresent)
			if err != nil {
				return err
			}
			defer c.closeDB()
			global, projects, issues := guardrecipesvc.ListApplied(c.env, c.set)
			issues = append(append([]string{}, c.set.Issues...), issues...)
			drift := guardrecipesvc.LevelDrift(c.env, global)
			out := recipeOut(cmd)
			if jsonOut {
				return writeRecipeJSON(out, map[string]any{
					"catalog":     guardrecipesvc.CatalogViews(c.set),
					"issues":      orEmpty(issues),
					"level":       c.env.Config.Guard.Level,
					"mode":        c.env.Config.Guard.Mode,
					"prompt_mode": c.env.Config.Guard.Prompt.Mode,
					"global":      global,
					"projects":    orEmptyApplied(projects),
					"level_drift": drift,
					"recipe_dir":  guard.RecipeDir(c.env.Config.Guard, c.env.Home),
				})
			}
			fmt.Fprintln(out, "Levels (one per scope, least to most strict):")
			for _, r := range c.set.Levels() {
				fmt.Fprintf(out, "  %-12s %-28s mode %-8s prompt %-8s %s\n", r.Name, recipeTitle(r), r.Mode, r.PromptMode, r.Summary)
			}
			fmt.Fprintln(out, "Packs (any number):")
			for _, r := range c.set.Packs() {
				fmt.Fprintf(out, "  %-18s %-28s %s\n", r.Name, recipeTitle(r), r.Summary)
			}
			fmt.Fprintln(out)
			fmt.Fprintf(out, "This machine:  %s\n", describeApplied(global))
			for _, p := range projects {
				fmt.Fprintf(out, "Project:       %s  %s\n", p.ProjectRoot, describeApplied(&p))
				if p.Drift != "" {
					fmt.Fprintf(out, "NOTE:          %s: %s\n", p.ProjectRoot, p.Drift)
				}
			}
			if drift != "" {
				fmt.Fprintf(out, "NOTE:          %s\n", drift)
			}
			for _, s := range issues {
				fmt.Fprintf(out, "ISSUE:         %s\n", s)
			}
			if dir := guard.RecipeDir(c.env.Config.Guard, c.env.Home); dir != "" {
				fmt.Fprintf(out, "Your recipes:  %s\n", dir)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

// recipeTitle is the title with a "(yours)" mark for a user recipe.
func recipeTitle(r *guardrecipe.Recipe) string {
	if r.Source == guardrecipe.SourceUser {
		return r.Title + " (yours)"
	}
	return r.Title
}

// describeApplied is one line naming what a scope has applied.
func describeApplied(a *guardrecipesvc.Applied) string {
	if a == nil {
		return "no recipe applied"
	}
	if !a.Readable {
		return fmt.Sprintf("a file in the recipe slot this Observer cannot read (%s): it still loads as policy, and apply or remove replaces it", a.Path)
	}
	var parts []string
	if a.Meta.Level != nil {
		parts = append(parts, fmt.Sprintf("level %s v%d", a.Meta.Level.Name, a.Meta.Level.Version))
	}
	for _, p := range a.Meta.Packs {
		parts = append(parts, fmt.Sprintf("pack %s v%d", p.Name, p.Version))
	}
	s := strings.Join(parts, " + ")
	if a.Meta.AppliedAt != "" {
		s += fmt.Sprintf(" (applied %s", a.Meta.AppliedAt)
		if a.Meta.AppliedVia != "" {
			s += " from the " + a.Meta.AppliedVia
		}
		s += ")"
	}
	for _, u := range a.Updates {
		s += "; update available: " + u
	}
	for _, m := range a.Missing {
		s += "; no longer in the catalog: " + m
	}
	return s
}

func newGuardRecipeShowCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		tomlOut    bool
	)
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show what one recipe sets (--toml prints the file, ready to copy and edit)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := openGuardRecipeCLI(cmd.Context(), configPath, recipeDBNever)
			if err != nil {
				return err
			}
			defer c.closeDB()
			r, ok := c.set.Get(args[0])
			if !ok {
				return fmt.Errorf("no recipe named %q (see `observer guard recipe list`)", args[0])
			}
			if tomlOut {
				// The file as it is, ready to redirect into a copy; escaped
				// only when a person reads it in a terminal.
				raw := cmd.OutOrStdout()
				if writerIsTerminal(raw) {
					raw = recipeOut(cmd)
				}
				_, err := raw.Write(r.Raw)
				return err
			}
			out := recipeOut(cmd)
			if jsonOut {
				return writeRecipeJSON(out, map[string]any{"recipe": guardrecipesvc.ViewOf(r), "toml": string(r.Raw)})
			}
			v := guardrecipesvc.ViewOf(r)
			fmt.Fprintf(out, "%s: %s (%s v%d, %s)\n", v.Name, v.Title, v.Kind, v.Version, v.Source)
			fmt.Fprintf(out, "  %s\n", v.Summary)
			if v.Kind == guardrecipe.KindLevel {
				fmt.Fprintf(out, "Mode:     [guard] mode %q, [guard.prompt] mode %q (on this machine; a project holds it with rows)\n", v.Mode, v.PromptMode)
			}
			if v.Extends != "" {
				fmt.Fprintf(out, "Extends:  %s (its rows come first)\n", v.Extends)
			}
			for _, o := range v.Overrides {
				fmt.Fprintf(out, "Override: %-10s %s\n", o.Rule, describeOverride(o))
			}
			for _, id := range v.RuleIDs {
				fmt.Fprintf(out, "Adds:     %s\n", id)
			}
			for _, in := range v.Inputs {
				fmt.Fprintf(out, "Reads:    %s\n", in)
			}
			for _, a := range v.Advice {
				fmt.Fprintf(out, "Advice:   %s\n", a)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&tomlOut, "toml", false, "print the recipe file as it is")
	return cmd
}

// describeOverride renders one override row's effect.
func describeOverride(o guardrecipesvc.OverrideView) string {
	var parts []string
	if o.Decision != "" {
		parts = append(parts, "decision "+o.Decision)
	}
	if o.Enforce != nil {
		if *o.Enforce {
			parts = append(parts, "holds in observe mode too")
		} else {
			parts = append(parts, "capped at flag")
		}
	}
	s := strings.Join(parts, ", ")
	if o.Note != "" {
		s += " - " + o.Note
	}
	return s
}

// recipeWriteFlags are the flags apply and remove share.
type recipeWriteFlags struct {
	configPath string
	project    string
	dryRun     bool
	yes        bool
	replay     time.Duration
	jsonOut    bool
	showFile   bool
}

func (f *recipeWriteFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&f.project, "project", "", "apply to one project (a directory; . is this repo) instead of this machine")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "show what would change and write nothing")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "apply without asking")
	cmd.Flags().DurationVar(&f.replay, "replay", 0, "also replay this much captured history under the policy before and after (168h = a week)")
	cmd.Flags().BoolVar(&f.jsonOut, "json", false, "emit JSON (the preview, then the result)")
	cmd.Flags().BoolVar(&f.showFile, "show-file", false, "print the recipe file the apply writes")
}

// confirmRecipeWrite asks before a write unless --yes; a non-interactive
// run without --yes refuses (the preview is already printed).
func confirmRecipeWrite(cmd *cobra.Command, f *recipeWriteFlags, question string) (bool, error) {
	if f.yes {
		return true, nil
	}
	if !isInteractiveTerminal(cmd) {
		return false, errors.New("nothing written: re-run with --yes to apply (or --dry-run to only preview)")
	}
	return promptYesNo(cmd, question+" [y/N] ")
}

// loadRecipeReplay loads captured history for --replay, nil when off.
func (c *guardRecipeCLI) loadRecipeReplay(ctx context.Context, window time.Duration) ([]guard.ActionInput, error) {
	if window <= 0 {
		return nil, nil
	}
	if c.st == nil {
		return nil, errors.New("--replay needs the Observer database, which did not open")
	}
	return c.st.LoadGuardReplayInputs(ctx, time.Now().UTC().Add(-window), 50000)
}

func newGuardRecipeApplyCmd() *cobra.Command {
	var (
		f     recipeWriteFlags
		level string
		packs []string
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply a level and packs to this machine or one project (previews first)",
		Long: "Shows every rule whose decision changes, then asks. On this machine a\n" +
			"level also sets [guard] level, [guard] mode and [guard.prompt] mode\n" +
			"(remove puts back what was there before the first apply). In a project\n" +
			"the machine-wide mode stays as it is, and the level's mode is held in\n" +
			"that project with explicit rows. Applying again replaces the previous\n" +
			"recipe of the same scope. The daemon picks the change up on restart;\n" +
			"hooks follow at once.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := openGuardRecipeCLI(cmd.Context(), f.configPath, f.previewDBUse())
			if err != nil {
				return err
			}
			defer c.closeDB()
			scope, root, err := recipeScope(f.project)
			if err != nil {
				return err
			}
			req := guardrecipesvc.Request{Level: level, Packs: splitPackFlags(packs), Scope: scope, ProjectRoot: root, Via: "cli"}
			inputs, err := c.loadRecipeReplay(cmd.Context(), f.replay)
			if err != nil {
				return err
			}
			var (
				pv  *guardrecipesvc.Preview
				rep *guardrecipesvc.Replay
			)
			if f.replay > 0 {
				rep, pv, err = guardrecipesvc.ReplayApply(c.env, c.set, req, inputs)
			} else {
				pv, err = guardrecipesvc.PreviewApply(c.env, c.set, req)
			}
			if err != nil {
				return err
			}
			out := recipeOut(cmd)
			if f.jsonOut {
				if err := writeRecipeJSON(out, map[string]any{"preview": pv, "replay": rep}); err != nil {
					return err
				}
			} else {
				// The known roots come from the database, which a dry run
				// does not open (recipeDBUse); unknown is not "not seen".
				if scope == guardrecipe.ScopeProject && c.st != nil && !c.knownRoot(root) {
					fmt.Fprintf(out, "NOTE: Observer has not seen a session in %s yet; the recipe applies once it does.\n", root)
				}
				printRecipePreview(out, pv, f.showFile)
				printRecipeReplay(out, f.replay, rep)
			}
			if f.dryRun {
				return nil
			}
			if len(pv.Problems) > 0 {
				return recipeRefusal("not applied: the recipe is refused:", pv.Problems)
			}
			ok, err := confirmRecipeWrite(cmd, &f, "Apply this recipe?")
			if err != nil || !ok {
				if err == nil {
					fmt.Fprintln(out, "Nothing written.")
				}
				return err
			}
			res, err := guardrecipesvc.Apply(c.env, c.set, req, guardrecipesvc.FileConfigWriter(c.configPath))
			if err != nil {
				return err
			}
			c.audit(cmd.Context(), "guard_recipe_apply", fmt.Sprintf("scope=%s level=%s packs=%s changes=%d config_changed=%t",
				req.Scope, req.Level, strings.Join(req.Packs, ","), len(res.Preview.Changes), res.ConfigChanged))
			if f.jsonOut {
				return writeRecipeJSON(out, map[string]any{"applied": true, "result": res, "restart_required": true})
			}
			fmt.Fprintf(out, "Applied: wrote %s", res.Wrote)
			if res.ConfigChanged {
				fmt.Fprintf(out, " and [guard] keys in %s", c.configPath)
			}
			fmt.Fprintln(out, ".\nRestart the daemon (`observer start`) for the watcher seam; hooks follow immediately.")
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&level, "level", "", "strictness level: none, loose, balanced, strict, lockdown, or one of yours")
	cmd.Flags().StringSliceVar(&packs, "pack", nil, "a pack to add (repeat, or comma-separate)")
	return cmd
}

// splitPackFlags trims and de-duplicates --pack values, keeping order.
func splitPackFlags(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range in {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func newGuardRecipeRemoveCmd() *cobra.Command {
	var f recipeWriteFlags
	cmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove the applied recipe of this machine or one project (previews first)",
		Long: "Deletes the managed recipe file. On this machine it also puts back the\n" +
			"[guard] level, mode and prompt mode the first apply replaced, each only\n" +
			"while it still holds what the recipe set: a change you made since stays.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := openGuardRecipeCLI(cmd.Context(), f.configPath, f.previewDBUse())
			if err != nil {
				return err
			}
			defer c.closeDB()
			scope, root, err := recipeScope(f.project)
			if err != nil {
				return err
			}
			inputs, err := c.loadRecipeReplay(cmd.Context(), f.replay)
			if err != nil {
				return err
			}
			var (
				pv  *guardrecipesvc.Preview
				rep *guardrecipesvc.Replay
				ok  bool
			)
			if f.replay > 0 {
				rep, pv, ok, err = guardrecipesvc.ReplayRemove(c.env, c.set, scope, root, inputs)
			} else {
				pv, ok, err = guardrecipesvc.PreviewRemove(c.env, c.set, scope, root)
			}
			if err != nil {
				return err
			}
			out := recipeOut(cmd)
			if !ok {
				if f.jsonOut {
					return writeRecipeJSON(out, map[string]any{"removed": false})
				}
				fmt.Fprintln(out, "No recipe is applied there; nothing to remove.")
				return nil
			}
			if f.jsonOut {
				if err := writeRecipeJSON(out, map[string]any{"preview": pv, "replay": rep}); err != nil {
					return err
				}
			} else {
				printRecipePreview(out, pv, false)
				printRecipeReplay(out, f.replay, rep)
			}
			if len(pv.Problems) > 0 {
				return recipeRefusal("not removed: removing the recipe is refused:", pv.Problems)
			}
			if f.dryRun {
				return nil
			}
			yes, err := confirmRecipeWrite(cmd, &f, "Remove this recipe?")
			if err != nil || !yes {
				if err == nil {
					fmt.Fprintln(out, "Nothing written.")
				}
				return err
			}
			res, removed, err := guardrecipesvc.Remove(c.env, c.set, scope, root, guardrecipesvc.FileConfigWriter(c.configPath))
			if err != nil {
				return err
			}
			if removed {
				c.audit(cmd.Context(), "guard_recipe_remove", fmt.Sprintf("scope=%s changes=%d config_changed=%t", scope, len(res.Preview.Changes), res.ConfigChanged))
			}
			if f.jsonOut {
				return writeRecipeJSON(out, map[string]any{"removed": removed, "result": res, "restart_required": removed})
			}
			if !removed {
				fmt.Fprintln(out, "No recipe is applied there; nothing to remove.")
				return nil
			}
			fmt.Fprintf(out, "Removed %s", res.Wrote)
			if res.ConfigChanged {
				fmt.Fprintf(out, " and put back the [guard] keys in %s", c.configPath)
			}
			fmt.Fprintln(out, ".\nRestart the daemon (`observer start`) for the watcher seam; hooks follow immediately.")
			return nil
		},
	}
	f.register(cmd)
	return cmd
}

// printRecipePreview renders the human preview of an apply or remove.
func printRecipePreview(out io.Writer, pv *guardrecipesvc.Preview, showFile bool) {
	where := "this machine"
	if pv.Scope == guardrecipe.ScopeProject {
		where = "project " + pv.ProjectRoot
	}
	if pv.Remove {
		fmt.Fprintf(out, "Remove the recipe of %s (%s)\n", where, pv.Path)
	} else {
		var sel []string
		if pv.Level != "" {
			sel = append(sel, "level "+pv.Level)
		}
		for _, p := range pv.Packs {
			sel = append(sel, "pack "+p)
		}
		fmt.Fprintf(out, "Apply %s to %s (%s)\n", strings.Join(sel, " + "), where, pv.Path)
	}
	if pv.Replaces != nil {
		fmt.Fprintf(out, "Replaces:     %s\n", describeApplied(pv.Replaces))
	}
	if pv.LevelBefore != pv.LevelAfter {
		fmt.Fprintf(out, "Config:       [guard] level %q -> %q\n", pv.LevelBefore, pv.LevelAfter)
	}
	if pv.ModeBefore != pv.ModeAfter {
		fmt.Fprintf(out, "Config:       [guard] mode %q -> %q\n", pv.ModeBefore, pv.ModeAfter)
	}
	if pv.PromptModeBefore != pv.PromptModeAfter {
		fmt.Fprintf(out, "Config:       [guard.prompt] mode %q -> %q\n", pv.PromptModeBefore, pv.PromptModeAfter)
	}
	if pv.ModeNote != "" {
		fmt.Fprintf(out, "Note:         %s\n", pv.ModeNote)
	}
	if len(pv.Changes) == 0 {
		fmt.Fprintln(out, "Rules:        no rule changes its decision")
	} else {
		fmt.Fprintf(out, "Rules:        %d change their decision on a match:\n", len(pv.Changes))
		changes := append([]guardrecipesvc.Change(nil), pv.Changes...)
		sort.SliceStable(changes, func(i, j int) bool {
			if changes[i].Category != changes[j].Category {
				return changes[i].Category < changes[j].Category
			}
			return changes[i].RuleID < changes[j].RuleID
		})
		for _, ch := range changes {
			fmt.Fprintf(out, "  %-10s %-12s %-6s -> %-6s %s\n", ch.RuleID, ch.Category, ch.Before, ch.After, truncateDoc(ch.Doc, 80))
		}
	}
	for _, p := range pv.Problems {
		fmt.Fprintf(out, "PROBLEM:      %s\n", p)
	}
	for _, s := range pv.Issues {
		fmt.Fprintf(out, "ISSUE:        %s\n", s)
	}
	for _, in := range pv.Inputs {
		fmt.Fprintf(out, "Reads:        %s (set it in config.toml or Settings > Guard)\n", in)
	}
	for _, a := range pv.Advice {
		fmt.Fprintf(out, "Advice:       %s\n", a)
	}
	if showFile && pv.Text != "" {
		fmt.Fprintf(out, "\n--- %s ---\n%s", pv.Path, pv.Text)
	}
}

// printRecipeReplay renders a --replay comparison.
func printRecipeReplay(out io.Writer, window time.Duration, rep *guardrecipesvc.Replay) {
	if rep == nil {
		return
	}
	fmt.Fprintf(out, "Replay:       the last %s, %d captured actions\n", window, rep.Scanned)
	fmt.Fprintf(out, "  today:      %s (mode %s)\n", replayCounts(rep.Before), rep.Before.Mode)
	fmt.Fprintf(out, "  after:      %s (mode %s)\n", replayCounts(rep.After), rep.After.Mode)
	if rep.Scanned == 50000 {
		fmt.Fprintln(out, "  NOTE: the 50k replay cap was hit - narrow --replay for full coverage")
	}
}

func replayCounts(s guardrecipesvc.ReplaySummary) string {
	return fmt.Sprintf("%d flag, %d ask, %d deny", s.ByDecision["flag"], s.ByDecision["ask"], s.ByDecision["deny"])
}

// truncateDoc cuts a rule doc to n runes for a table row.
func truncateDoc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func newGuardRecipeSaveCmd() *cobra.Command {
	var (
		configPath string
		file       string
	)
	cmd := &cobra.Command{
		Use:   "save <name> --file <recipe.toml|->",
		Short: "Save one of your own recipes (checked first; changes no policy until applied)",
		Long: "Copies a recipe file into ~/.observer/guard-recipes/<name>.toml after\n" +
			"checking it parses, fits the catalog (its extends target exists) and\n" +
			"compiles to a policy that lints clean. Start from a built-in one:\n\n" +
			"  observer guard recipe show strict --toml > my-strict.toml\n" +
			"  # edit name/title, then:\n" +
			"  observer guard recipe save my-strict --file my-strict.toml",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if file == "" {
				return errors.New("--file is required (- reads standard input)")
			}
			var raw []byte
			var err error
			if file == "-" {
				raw, err = io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1<<20))
			} else {
				raw, err = os.ReadFile(file) //nolint:gosec // the operator names the file to import
			}
			if err != nil {
				return fmt.Errorf("read recipe: %w", err)
			}
			c, err := openGuardRecipeCLI(cmd.Context(), configPath, recipeDBWrite)
			if err != nil {
				return err
			}
			defer c.closeDB()
			r, err := guardrecipesvc.SaveUserRecipe(c.env, args[0], raw)
			if err != nil {
				return err
			}
			c.audit(cmd.Context(), "guard_recipe_save", fmt.Sprintf("name=%s kind=%s version=%d", r.Name, r.Kind, r.Version))
			fmt.Fprintf(recipeOut(cmd), "Saved %s (%s v%d) in %s. Apply it with `observer guard recipe apply --%s %s`.\n",
				r.Name, r.Kind, r.Version, guard.RecipeDir(c.env.Config.Guard, c.env.Home), recipeFlagFor(r.Kind), r.Name)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&file, "file", "", "the recipe file to save (- reads standard input)")
	return cmd
}

func recipeFlagFor(k guardrecipe.Kind) string {
	if k == guardrecipe.KindLevel {
		return "level"
	}
	return "pack"
}

func newGuardRecipeDeleteCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete one of your own recipes (an applied copy keeps working)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := openGuardRecipeCLI(cmd.Context(), configPath, recipeDBWrite)
			if err != nil {
				return err
			}
			defer c.closeDB()
			if err := guardrecipesvc.DeleteUserRecipe(c.env, args[0]); err != nil {
				return err
			}
			c.audit(cmd.Context(), "guard_recipe_delete", "name="+strings.TrimSpace(args[0]))
			fmt.Fprintf(recipeOut(cmd), "Deleted %s. Where it is applied it keeps working (the applied file is a copy); `recipe list` shows it as no longer in the catalog.\n", args[0])
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// orEmpty returns a non-nil slice for JSON.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func orEmptyApplied(s []guardrecipesvc.Applied) []guardrecipesvc.Applied {
	if s == nil {
		return []guardrecipesvc.Applied{}
	}
	return s
}

// guardRecipeStatusLines are the `observer guard status` lines for the
// applied guard recipe of this machine: what is applied, and a [guard]
// level that disagrees with it. Empty when no recipe is applied and the
// level key is empty; a catalog that does not load is reported, not fatal.
func guardRecipeStatusLines(cfg config.Config) []string {
	home, _ := os.UserHomeDir()
	env := guardrecipesvc.Env{Config: cfg, Home: home}
	set, err := guardrecipesvc.Catalog(env)
	if err != nil {
		return []string{"Recipe:       the recipe catalog did not load: " + err.Error()}
	}
	global, err := guardrecipesvc.ReadApplied(env, set, guardrecipe.ScopeGlobal, "")
	if err != nil {
		return nil
	}
	var out []string
	if global != nil {
		// The header is file text (RC-9): escaped like the recipe verbs'.
		out = append(out, "Recipe:       "+escapeTerminalControls(describeApplied(global)))
	}
	if drift := guardrecipesvc.LevelDrift(env, global); drift != "" {
		out = append(out, "NOTE:         "+escapeTerminalControls(drift))
	}
	_, projects, _ := guardrecipesvc.ListApplied(env, set)
	for _, p := range projects {
		if p.Drift != "" {
			out = append(out, "NOTE:         "+escapeTerminalControls(p.ProjectRoot+": "+p.Drift))
		}
	}
	return out
}

// recipeRefusal is the error for an apply or remove the service refuses: the
// head line, then EVERY problem, each on its own line and escaped.
func recipeRefusal(head string, problems []string) error {
	var b strings.Builder
	b.WriteString(head)
	for _, p := range problems {
		b.WriteString("\n  - " + escapeTerminalControls(p))
	}
	return errors.New(b.String())
}
