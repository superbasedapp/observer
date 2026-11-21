package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/promptreg"
)

// obs_prompts.go is `observer obs prompts` (Plane A lane C8, review finding
// R-B15): the machine's prompt registry from the terminal, so an individual
// on destination local can author the prompts get_prompt() reads. It works
// on the same node-local obs store as Your apps > Prompts and the local SDK
// fetch (/api/obs/sdk/prompts), through the pure registry core
// internal/promptreg. It imports no internal/obs package
// (tests/invariant/obs_boundary_test.go): obs_wire_prompts.go sets
// openObsPrompts in an obs build; without it every verb refuses. Approval is
// an org rule (a second member approves); a machine has one user, so there
// is no propose or approve verb here.

// obsPromptStore is the machine prompt store as this CLI uses it (the obs
// store's own method set).
type obsPromptStore interface {
	ListPrompts(ctx context.Context, q promptreg.ListQuery) ([]byte, error)
	PromptDetail(ctx context.Context, name string) (promptreg.DetailBody, error)
	CreatePromptVersion(ctx context.Context, name string, d promptreg.Draft, actor string, at time.Time) (promptreg.Version, error)
	MovePromptLabel(ctx context.Context, name, label string, to int, actor string, at time.Time) (promptreg.Move, error)
	RollbackPromptLabel(ctx context.Context, name, label string, actor string, at time.Time) (promptreg.Move, error)
	SetPromptRollout(ctx context.Context, name, label string, candidate, percent int, actor string, at time.Time) (promptreg.Move, error)
	PromptDiff(ctx context.Context, name string, from, to int) (promptreg.DiffBody, error)
}

// openObsPrompts opens the machine prompt store over the daemon's database.
// obs_wire_prompts.go sets it in an obs build; nil means obs is compiled out.
var openObsPrompts func(ctx context.Context, db *sql.DB) (obsPromptStore, error)

// errObsPromptsUnavailable is the refusal of a build without observability.
var errObsPromptsUnavailable = errors.New("this binary was built without app observability, so it has no prompt registry")

// obsPromptActor is the actor recorded on the machine's versions and moves
// (the dashboard records "local").
const obsPromptActor = "local"

// withObsPrompts loads the config, opens the store and runs fn.
func withObsPrompts(cmd *cobra.Command, configPath string, fn func(context.Context, obsPromptStore) (any, error)) error {
	if openObsPrompts == nil {
		return errObsPromptsUnavailable
	}
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := requireAppObs(cfg.Observability.Enabled); err != nil {
		return err
	}
	st, err := openObsPrompts(cmd.Context(), database)
	if err != nil {
		return err
	}
	out, err := fn(cmd.Context(), st)
	if err != nil {
		return obsPromptError(err)
	}
	if raw, ok := out.(json.RawMessage); ok {
		var v any
		if err := json.Unmarshal(raw, &v); err == nil {
			out = v
		}
	}
	return traceJSON(cmd.OutOrStdout(), out)
}

// obsPromptError names a registry refusal by its wire code.
func obsPromptError(err error) error {
	if _, code, ok := promptreg.ErrorStatus(err); ok {
		return fmt.Errorf("prompts: %s: %w", code, err)
	}
	return fmt.Errorf("prompts: %w", err)
}

func newObsPromptsCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "prompts",
		Short: "Your apps' prompts on this machine: list, show, create a version, move a label, roll out, diff",
		Long: "The prompt registry your apps read with the SDK's get_prompt() when their\n" +
			"destination is local (the same data as the dashboard's Your apps > Prompts).\n" +
			"A version never changes once created; moving the production or staging label\n" +
			"is the release, a rollback moves it back, and a rollout serves a candidate\n" +
			"version to a percent of end users. Requires [observability] enabled = true;\n" +
			"nothing here leaves the machine.",
	}
	cmd.PersistentFlags().StringVar(&configPath, "config", "", "path to config.toml")
	run := func(cmd *cobra.Command, fn func(context.Context, obsPromptStore) (any, error)) error {
		return withObsPrompts(cmd, configPath, fn)
	}
	var (
		typ, file, text, config, note string
		labels                        []string
	)
	create := &cobra.Command{
		Use: "create <name>", Short: "Create the next version of a prompt (the first creates it)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			d, err := obsPromptDraft(typ, file, text, config, note, labels)
			if err != nil {
				return err
			}
			return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) {
				if _, err := st.CreatePromptVersion(ctx, args[0], d, obsPromptActor, time.Now()); err != nil {
					return nil, err
				}
				return st.PromptDetail(ctx, args[0])
			})
		},
	}
	create.Flags().StringVar(&typ, "type", "text", "text or chat")
	create.Flags().StringVar(&file, "file", "", "read the body from this file (a chat body is a JSON list of {role, content})")
	create.Flags().StringVar(&text, "text", "", "the body inline; placeholders are {{name}}")
	create.Flags().StringVar(&config, "prompt-config", "", "an optional JSON object returned to the SDK as written (model, temperature...)")
	create.Flags().StringVar(&note, "note", "", "an optional note on the version")
	create.Flags().StringSliceVar(&labels, "label", nil, "move this label onto the new version (production, staging; repeatable)")

	var from int
	diff := &cobra.Command{
		Use: "diff <name> <version>", Short: "Compare a version with the one before it (or --from)", Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			to, err := obsPromptVersionArg("diff", args[1], 1)
			if err != nil {
				return err
			}
			f := to - 1
			if from > 0 {
				f = from
			}
			return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) { return st.PromptDiff(ctx, args[0], f, to) })
		},
	}
	diff.Flags().IntVar(&from, "from", 0, "the version to compare from (default: the one before)")

	cmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "Print every prompt with its latest version, labels and rollouts", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) {
					b, err := st.ListPrompts(ctx, promptreg.ListQuery{Limit: promptreg.MaxListLimit})
					return json.RawMessage(b), err
				})
			},
		},
		&cobra.Command{
			Use: "show <name>", Short: "Print one prompt's versions, labels, rollouts and label history", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) { return st.PromptDetail(ctx, args[0]) })
			},
		},
		create,
		&cobra.Command{
			Use: "label <name> <production|staging> <version>", Short: "Point a label at a version", Args: cobra.ExactArgs(3),
			RunE: func(cmd *cobra.Command, args []string) error {
				v, err := obsPromptVersionArg("label", args[2], 1)
				if err != nil {
					return err
				}
				return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) {
					if _, err := st.MovePromptLabel(ctx, args[0], args[1], v, obsPromptActor, time.Now()); err != nil {
						return nil, err
					}
					return st.PromptDetail(ctx, args[0])
				})
			},
		},
		&cobra.Command{
			Use:   "rollback <name> <production|staging>",
			Short: "End the label's rollout, or move it back to the version it held before its last promotion",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) {
					if _, err := st.RollbackPromptLabel(ctx, args[0], args[1], obsPromptActor, time.Now()); err != nil {
						return nil, err
					}
					return st.PromptDetail(ctx, args[0])
				})
			},
		},
		&cobra.Command{
			Use:   "rollout <name> <production|staging> <candidate version> <percent>",
			Short: "Serve a candidate version to a percent of end users (100 promotes it, 0 ends the rollout)",
			Args:  cobra.ExactArgs(4),
			RunE: func(cmd *cobra.Command, args []string) error {
				v, err := obsPromptVersionArg("rollout", args[2], 0)
				if err != nil {
					return err
				}
				pct, err := strconv.Atoi(args[3])
				if err != nil || pct < 0 || pct > 100 {
					return fmt.Errorf("prompts rollout: %q is not a percent (0 to 100)", args[3])
				}
				return run(cmd, func(ctx context.Context, st obsPromptStore) (any, error) {
					if _, err := st.SetPromptRollout(ctx, args[0], args[1], v, pct, obsPromptActor, time.Now()); err != nil {
						return nil, err
					}
					return st.PromptDetail(ctx, args[0])
				})
			},
		},
		diff,
	)
	return cmd
}

// obsPromptVersionArg parses a version argument of at least min.
func obsPromptVersionArg(verb, s string, minimum int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < minimum {
		return 0, fmt.Errorf("prompts %s: %q is not a version number", verb, s)
	}
	return n, nil
}

// obsPromptDraft builds a create request from the flags; the registry core
// validates it.
func obsPromptDraft(typ, file, text, config, note string, labels []string) (promptreg.Draft, error) {
	if (file == "") == (text == "") {
		return promptreg.Draft{}, fmt.Errorf("prompts create: give exactly one of --file or --text")
	}
	body := text
	if file != "" {
		var r io.Reader = os.Stdin
		if file != "-" {
			f, err := os.Open(file) //nolint:gosec // G304: the operator names the file to read
			if err != nil {
				return promptreg.Draft{}, fmt.Errorf("prompts create: %w", err)
			}
			defer func() { _ = f.Close() }()
			r = f
		}
		b, err := io.ReadAll(io.LimitReader(r, int64(promptreg.MaxBodyBytes)*4))
		if err != nil {
			return promptreg.Draft{}, fmt.Errorf("prompts create: %w", err)
		}
		body = string(b)
	}
	t := promptreg.Type(strings.TrimSpace(typ))
	d := promptreg.Draft{Type: t, CommitMessage: note, Labels: labels}
	if t == promptreg.TypeChat {
		d.Prompt = json.RawMessage(body)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			return promptreg.Draft{}, err
		}
		d.Prompt = raw
	}
	if config != "" {
		d.Config = json.RawMessage(config)
	}
	return d, nil
}
