package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// tagGrammarHelp documents the ONE add/remove grammar the `observer tag`
// command accepts. Cobra/pflag consumes any bare `-junk` token as a flag before
// the command ever sees it, so `--rm` is the PRIMARY remove spelling; the
// `-tag` spelling works only after the `--` end-of-flags marker.
//
// Every example below is executed verbatim by
// TestTagGrammarHelpExamplesActuallyWork — the help text and the parser cannot
// drift apart (the plan's `observer tag id +experiment -junk --favorite` line
// never parsed: pflag claimed `-junk` as a shorthand flag cluster).
const tagGrammarHelp = "Grammar:\n" +
	"  +<tag>        add a tag (positional; repeatable)\n" +
	"  --rm <tag>    remove a tag (repeatable) — the primary remove spelling\n" +
	"  -- -<tag>     remove a tag using the '-' spelling. The '--' end-of-flags\n" +
	"                marker is REQUIRED: a bare -tag looks like a flag to the\n" +
	"                argument parser and is rejected before this command runs.\n\n" +
	"Flag placement: every flag (--rm, --favorite, --note, --config, --json …)\n" +
	"must come BEFORE the '--' marker. Tokens after '--' are tag tokens only —\n" +
	"a '--favorite' written after '--' is read as a tag, not as a flag.\n\n" +
	"Tags are normalized on write: trimmed, lowercased, spaces become '-',\n" +
	"charset [a-z0-9._-], at most 40 characters, at most 16 tags per session.\n\n" +
	"Examples:\n" +
	"  observer tag a1b2c3 +experiment +backend --favorite --note \"baseline run\"\n" +
	"  observer tag a1b2c3 +a --rm b --favorite --note x\n" +
	"  observer tag a1b2c3 --rm junk\n" +
	"  observer tag a1b2c3 --favorite -- +keep -junk\n"

// newTagCmd implements `observer tag <session-id-prefix> [+tag …] [--rm tag …]
// [--favorite|--no-favorite] [--note "…"]` — the per-session classification
// write (docs/plans/session-classification-tags-plan-2026-07-31.md §6).
//
// The session id may be abbreviated to any unique prefix; an ambiguous prefix
// errors with the candidate list rather than guessing.
func newTagCmd() *cobra.Command {
	var (
		configPath  string
		removeFlags []string
		favorite    bool
		noFavorite  bool
		note        string
		clearNote   bool
		rating      int
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "tag <session-id-prefix> [+tag ...] [--rm tag]",
		Short: "Tag, star, or annotate a session (classification for later review)",
		Long: "Applies the session-classification primitives — tags, the favorite\n" +
			"star, and the free-text note — to one session. The session id may be\n" +
			"abbreviated to any unique prefix.\n\n" + tagGrammarHelp,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if favorite && noFavorite {
				return errors.New("--favorite and --no-favorite are mutually exclusive")
			}
			if note != "" && clearNote {
				return errors.New("--note and --clear-note are mutually exclusive")
			}
			prefix := args[0]
			add, remove, err := parseTagTokens(args[1:])
			if err != nil {
				return err
			}
			remove = append(remove, removeFlags...)

			var favPtr *bool
			if favorite || noFavorite {
				v := favorite
				favPtr = &v
			}
			var notePtr *string
			switch {
			case clearNote:
				empty := ""
				notePtr = &empty
			case note != "":
				notePtr = &note
			}
			// --rating is a pointer only when the operator actually passed it, so
			// omitting the flag leaves the rating unchanged while `--rating 0`
			// clears it (Changed distinguishes the two — an int flag can't).
			var ratingPtr *int
			if cmd.Flags().Changed("rating") {
				ratingPtr = &rating
			}
			// Validate the WHOLE mutation — tags, note AND rating — before opening
			// the DB or writing anything. The tag write and the annotation write
			// are two store calls, so an invocation with valid tags and an
			// over-long note (or out-of-range rating) would otherwise commit the
			// tags and then fail, leaving a partial write behind. Mirrors the
			// handler's pre-flight.
			// `observer tag` does not expose a --title flag (title is a
			// dashboard/web concept for now); title is always nil here, which
			// keeps this command's behaviour byte-for-byte unchanged.
			if err := store.ValidateClassificationInput(add, remove, notePtr, ratingPtr, nil); err != nil {
				return err
			}

			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			sessionID, err := resolveSessionPrefix(cmd.Context(), st, prefix)
			if err != nil {
				return err
			}
			if len(add) > 0 || len(remove) > 0 {
				if err := st.MutateSessionTags(cmd.Context(), sessionID, add, remove); err != nil {
					return err
				}
			}
			if favPtr != nil || notePtr != nil || ratingPtr != nil {
				if err := st.SetSessionAnnotation(cmd.Context(), sessionID, favPtr, notePtr, ratingPtr, nil); err != nil {
					return err
				}
			}

			tags, err := st.SessionTags(cmd.Context(), sessionID)
			if err != nil {
				return err
			}
			if tags == nil {
				// Empty LIST, never null — the HTTP surface emits [] for an
				// untagged session and a `--json` consumer must not have to
				// handle two spellings of "no tags" depending on which surface
				// produced the document.
				tags = []string{}
			}
			annot, err := st.GetSessionAnnotation(cmd.Context(), sessionID)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				body, _ := json.MarshalIndent(map[string]any{
					"session_id": sessionID,
					"tags":       tags,
					"favorite":   annot.Favorite,
					"note":       annot.Note,
					"rating":     annot.Rating,
				}, "", "  ")
				fmt.Fprintln(out, string(body))
				return nil
			}
			star := ""
			if annot.Favorite {
				star = "  ★ favorite"
			}
			fmt.Fprintf(out, "%s%s\n", sessionID, star)
			if len(tags) == 0 {
				fmt.Fprintln(out, "  tags: (none)")
			} else {
				fmt.Fprintf(out, "  tags: %s\n", strings.Join(tags, ", "))
			}
			if annot.Rating > 0 {
				fmt.Fprintf(out, "  rating: %d/%d\n", annot.Rating, store.MaxRating)
			}
			if annot.Note != "" {
				fmt.Fprintf(out, "  note: %s\n", annot.Note)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringArrayVar(&removeFlags, "rm", nil, "Remove a tag (repeatable). Same as the '-tag' form after a '--' marker.")
	cmd.Flags().BoolVar(&favorite, "favorite", false, "Star the session")
	cmd.Flags().BoolVar(&noFavorite, "no-favorite", false, "Un-star the session")
	cmd.Flags().StringVar(&note, "note", "", "Set the session note (max 500 characters)")
	cmd.Flags().BoolVar(&clearNote, "clear-note", false, "Clear the session note")
	cmd.Flags().IntVar(&rating, "rating", 0, "Set the overall session rating 1-10 (0 clears it)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}

// parseTagTokens splits positional classification tokens into add/remove lists.
// `+tag` adds; `-tag` removes (reachable only after a `--` end-of-flags marker,
// since pflag would otherwise claim the token as a flag). A bare token with no
// sign is an error rather than a guess — silently defaulting to "add" would
// make a typo'd removal look like it worked.
func parseTagTokens(tokens []string) (add, remove []string, err error) {
	for _, tok := range tokens {
		switch {
		case strings.HasPrefix(tok, "+"):
			add = append(add, strings.TrimPrefix(tok, "+"))
		case strings.HasPrefix(tok, "-"):
			remove = append(remove, strings.TrimPrefix(tok, "-"))
		default:
			return nil, nil, fmt.Errorf("tag token %q must start with '+' (add) or '-' (remove)\n\n%s", tok, tagGrammarHelp)
		}
	}
	return add, remove, nil
}

// resolveSessionPrefix resolves a (possibly abbreviated) session id, rendering
// the store's ambiguity error as an operator-readable candidate list.
func resolveSessionPrefix(ctx context.Context, st *store.Store, prefix string) (string, error) {
	id, err := st.ResolveSessionIDPrefix(ctx, prefix, 10)
	if err == nil {
		return id, nil
	}
	var amb *store.ErrSessionPrefixAmbiguous
	if errors.As(err, &amb) {
		// MatchCountLabel, not len(Candidates): the candidate list is capped, so
		// a prefix matching more sessions than the cap must read "10+ sessions"
		// instead of understating the ambiguity as exactly 10.
		return "", fmt.Errorf("session id prefix %q matches %s sessions — be more specific:\n  %s",
			amb.Prefix, amb.MatchCountLabel(), strings.Join(amb.Candidates, "\n  "))
	}
	return "", err
}

// newTagsCmd is the `observer tags` vocabulary group: the per-tag rollup plus
// rename / rm management (plan §6). Vocabulary management needs no defs table —
// a tag exists exactly as long as a session carries it.
func newTagsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tags",
		Short: "Session tag vocabulary: per-tag session counts + cost, rename, remove",
		Long: "Lists the tag vocabulary derived from the tags actually in use, with\n" +
			"per-tag session counts and the summed cost of the sessions carrying\n" +
			"each tag — the 'analysis by label' surface. Use `observer tag` to\n" +
			"classify an individual session.",
	}
	cmd.AddCommand(newTagsListCmd())
	cmd.AddCommand(newTagsRenameCmd())
	cmd.AddCommand(newTagsRmCmd())
	// Bare `observer tags` lists, so the common case needs no subcommand.
	list := newTagsListCmd()
	cmd.RunE = list.RunE
	cmd.Args = cobra.NoArgs
	cmd.Flags().AddFlagSet(list.Flags())
	return cmd
}

// tagRollupRow is one CLI rollup row: a tag, the sessions carrying it, and
// their summed cost/tokens.
type tagRollupRow struct {
	Tag      string  `json:"tag"`
	Sessions int     `json:"sessions"`
	CostUSD  float64 `json:"cost_usd"`
	Tokens   int64   `json:"tokens"`
}

// computeTagRollup folds the tag assignments against ONE cost-engine pass
// (GroupBySession over exactly the tagged session ids) — never one query per
// tag. Mirrors the dashboard's GET /api/sessions/tags so both surfaces report
// the same numbers.
func computeTagRollup(ctx context.Context, cfg config.Config, database *sql.DB, st *store.Store) ([]tagRollupRow, error) {
	assignments, err := st.TagAssignments(ctx)
	if err != nil {
		return nil, err
	}
	rows := []tagRollupRow{}
	if len(assignments) == 0 {
		return rows, nil
	}
	ids := make([]string, 0, len(assignments))
	for id := range assignments {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// cost.Engine.SessionRowsByID chunks the id set at
	// cost.MaxSessionIDsPerScope: a single IN list of every tagged session
	// exceeds SQLite's 32766 bind-variable ceiling once the vocabulary covers
	// enough sessions, and the swallowed error below would render that as
	// silently zeroed cost/token columns. The dashboard's Server.tagRollup
	// (internal/intelligence/dashboard/sessiontags.go) shares the same helper so
	// both surfaces report the same numbers at any vocabulary size.
	byID, cErr := acquireProcessCostEngine(ctx, cfg, database, slog.Default()).SessionRowsByID(ctx, database, cost.Options{
		Days:   36500,
		Source: cost.SourceAuto,
	}, ids)
	if cErr != nil {
		// Cost is an enrichment of the vocabulary, not its substance.
		byID = map[string]cost.Row{}
	}

	agg := map[string]*tagRollupRow{}
	for _, id := range ids {
		row, hasCost := byID[id]
		for _, tag := range assignments[id] {
			e, ok := agg[tag]
			if !ok {
				e = &tagRollupRow{Tag: tag}
				agg[tag] = e
			}
			e.Sessions++
			if hasCost {
				e.CostUSD += row.CostUSD
				e.Tokens += row.Tokens.Input + row.Tokens.Output +
					row.Tokens.CacheRead + row.Tokens.CacheCreation
			}
		}
	}
	for _, e := range agg {
		rows = append(rows, *e)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].CostUSD != rows[j].CostUSD {
			return rows[i].CostUSD > rows[j].CostUSD
		}
		if rows[i].Sessions != rows[j].Sessions {
			return rows[i].Sessions > rows[j].Sessions
		}
		return rows[i].Tag < rows[j].Tag
	})
	return rows, nil
}

// newTagsListCmd implements `observer tags [list]`.
func newTagsListCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Tag vocabulary with per-tag session counts and cost",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			rows, err := computeTagRollup(cmd.Context(), cfg, database, store.New(database))
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				body, _ := json.MarshalIndent(map[string]any{"tags": rows}, "", "  ")
				fmt.Fprintln(out, string(body))
				return nil
			}
			printTagRollup(out, rows)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	return cmd
}

// printTagRollup renders the vocabulary as an aligned table.
func printTagRollup(w io.Writer, rows []tagRollupRow) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "No tags yet. Classify a session with: observer tag <session-id> +experiment")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TAG\tSESSIONS\tTOKENS\tCOST USD")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.4f\n", r.Tag, r.Sessions, r.Tokens, r.CostUSD)
	}
	_ = tw.Flush()
}

// newTagsRenameCmd implements `observer tags rename <from> <to>`. A session
// already carrying both tags MERGES onto the destination.
func newTagsRenameCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "rename <from> <to>",
		Short: "Rename a tag across every session (merges on collision)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			n, err := store.New(database).RenameTag(cmd.Context(), args[0], args[1])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "renamed %q → %q across %d session(s)\n", args[0], args[1], n)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}

// newTagsRmCmd implements `observer tags rm <tag>`.
func newTagsRmCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "rm <tag>",
		Short: "Remove a tag from every session that carries it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			n, err := store.New(database).DeleteTag(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %q from %d session(s)\n", args[0], n)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	return cmd
}
