//go:build !sbo_omit_security

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secchange"
	"github.com/marmutapp/superbased-observer/internal/secchangeexport"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_provenance_export.go is `observer security provenance export`
// (security plan 7.10, gap G7, lane GATES-SEC): this node's VERIFIED change
// records for one repository in an external format, pinned and labelled
// experimental while the spec is a draft (internal/secchangeexport). It
// writes nothing unless asked: stdout, or --out; and with --notes (git-ai
// only) a git note under refs/notes/ai, only in a repository the person
// gave the notes consent for, only on a commit that has no git-ai note yet,
// never rewriting history.

const provExportGitTimeout = 20 * time.Second

// The export reads the repository's records in pages (audit finding F8):
// provExportPageSize per query, at most provExportMaxRecords in all; past
// that it says the export was cut. Vars so a test can shrink them.
var (
	provExportPageSize   = 500
	provExportMaxRecords = 20000
)

var provExportRangeRE = regexp.MustCompile(`^[0-9a-f]{7,64}\.\.[0-9a-f]{7,64}$`)

// provExportOpts are the verb's flags.
type provExportOpts struct {
	configPath, dir, format string
	commit, rng, out        string
	notes                   bool
}

func newProvenanceExportCmd() *cobra.Command {
	var o provExportOpts
	cmd := &cobra.Command{
		Use:   "export --format agent-trace|git-ai [--commit <sha>|--range <a>..<b>] [--out <file>] [--notes]",
		Short: "Export verified change records as Agent Trace or git-ai (experimental)",
		Long: "Print this node's verified AI change records for one repository in an external format.\n" +
			"EXPERIMENTAL: both formats are pinned drafts (Agent Trace " + secchangeexport.Specs[secchangeexport.FormatAgentTrace].Version +
			", git-ai " + secchangeexport.Specs[secchangeexport.FormatGitAI].Version + ") and the output may change\n" +
			"with them. A record that does not verify is refused. Fields a record lacks stay absent:\n" +
			"there are no line ranges, and prompts appear by id only, never by text. With --notes\n" +
			"(git-ai only) the log is written as a git note under " + secchangeexport.GitAINotesRef + ", only in a repository\n" +
			"you gave the notes consent for (`provenance consent --notes=true`) and only on a commit\n" +
			"that has no such note yet; history is never rewritten.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runProvenanceExport(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.configPath, "config", "", "config file path")
	f.StringVar(&o.dir, "dir", ".", "the repository")
	f.StringVar(&o.format, "format", "", "agent-trace or git-ai")
	f.StringVar(&o.commit, "commit", "", "only this commit (hex)")
	f.StringVar(&o.rng, "range", "", "only the commits of <a>..<b> (hex)")
	f.StringVar(&o.out, "out", "", "write to this file instead of stdout")
	f.BoolVar(&o.notes, "notes", false, "git-ai only: write each log as a git note under refs/notes/ai (needs the repository's notes consent)")
	return cmd
}

// provExportCommits resolves the commits asked for (nil: every record of
// the repository).
func provExportCommits(ctx context.Context, root string, o provExportOpts) (map[string]bool, error) {
	switch {
	case o.commit != "" && o.rng != "":
		return nil, errors.New("--commit and --range are exclusive")
	case o.commit != "":
		if !verifyRevRE.MatchString(o.commit) {
			return nil, errors.New("--commit must be a hex commit id")
		}
		out, _, err := gitview.RunReadOnlyTimeout(ctx, root, 4096, provExportGitTimeout, "rev-parse", "--verify", "--end-of-options", o.commit+"^{commit}")
		if err != nil {
			return nil, fmt.Errorf("commit %s: %w", o.commit, err)
		}
		return map[string]bool{strings.TrimSpace(string(out)): true}, nil
	case o.rng != "":
		if !provExportRangeRE.MatchString(o.rng) {
			return nil, errors.New("--range must be <a>..<b> with hex commit ids")
		}
		out, over, err := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, provExportGitTimeout, "rev-list", "--max-count=500", "--end-of-options", o.rng)
		if err != nil {
			return nil, fmt.Errorf("range %s: %w", o.rng, err)
		}
		if over {
			return nil, fmt.Errorf("range %s: too many commits", o.rng)
		}
		set := map[string]bool{}
		for _, l := range strings.Fields(string(out)) {
			set[l] = true
		}
		return set, nil
	}
	return nil, nil
}

// provExportFacts reads the commit's tree and its changed paths, keyed by
// their path hash (internal/loc.PathHash: SHA-256 of the relative path).
func provExportFacts(ctx context.Context, root, sha string) (secchange.CommitFacts, map[string]string, error) {
	tree, _, err := gitview.RunReadOnlyTimeout(ctx, root, 4096, provExportGitTimeout, "rev-parse", "--verify", "--end-of-options", sha+"^{tree}")
	if err != nil {
		return secchange.CommitFacts{}, nil, err
	}
	names, over, err := gitview.RunReadOnlyTimeout(ctx, root, 4<<20, provExportGitTimeout,
		"diff-tree", "--no-commit-id", "--name-only", "--no-renames", "-r", "-z", "--root", "--end-of-options", sha)
	if err != nil {
		return secchange.CommitFacts{}, nil, fmt.Errorf("changed paths: %w", err)
	}
	if over {
		return secchange.CommitFacts{}, nil, errors.New("changed paths: over the cap")
	}
	paths := map[string]string{}
	for _, p := range strings.Split(string(names), "\x00") {
		if p != "" {
			paths[secchangeexport.PathHash(p)] = p
		}
	}
	return secchange.CommitFacts{SHA: sha, Tree: strings.TrimSpace(string(tree))}, paths, nil
}

func runProvenanceExport(ctx context.Context, stdout, stderr io.Writer, o provExportOpts) error {
	if _, ok := secchangeexport.Specs[o.format]; !ok {
		return secchangeexport.ErrFormat
	}
	if o.notes && o.format != secchangeexport.FormatGitAI {
		return errors.New("--notes writes git-ai logs only (--format git-ai)")
	}
	root, err := provenanceResolveRoot(ctx, gitview.RunReadOnlyTimeout, o.dir)
	if err != nil {
		return err
	}
	_, database, cleanup, err := loadConfigAndDB(ctx, o.configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	return provenanceExport(ctx, store.New(database), root, o, stdout, stderr)
}

// provenanceExport is the verb over an open store and a resolved root.
func provenanceExport(ctx context.Context, st *store.Store, root string, o provExportOpts, stdout, stderr io.Writer) error {
	rootHash := secposture.ProjectRootHash(root)
	if o.notes {
		ok, err := provExportNotesConsent(ctx, st, rootHash)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("--notes needs the notes consent for %s: run `observer security provenance consent --notes=true --trailer=<...> --dir %s` first", root, root)
		}
	}
	want, err := provExportCommits(ctx, root, o)
	if err != nil {
		return err
	}
	recs, cut, err := provExportRecords(ctx, st, rootHash)
	if err != nil {
		return err
	}
	kf, err := provenanceKeysFile(ctx, st)
	if err != nil {
		return err
	}
	trust, err := secchange.NewTrustSet(kf)
	if err != nil {
		return err
	}
	spec := secchangeexport.Specs[o.format]
	fmt.Fprintf(stderr, "EXPERIMENTAL: %s %s (a draft spec, read %s); the output may change with it\n", spec.Format, spec.Version, spec.Read)
	var buf bytes.Buffer
	exported, refused, notes := 0, 0, 0
	for _, r := range recs {
		if want != nil && !want[r.CommitSHA] {
			continue
		}
		facts, paths, err := provExportFacts(ctx, root, r.CommitSHA)
		if err != nil {
			refused++
			fmt.Fprintf(stderr, "%s: refused: the commit is not in this repository (%v)\n", shortSHA(r.CommitSHA), err)
			continue
		}
		out, err := secchangeexport.Export(o.format, secchangeexport.Input{Envelope: r.Envelope, Trust: trust, Commit: facts, Paths: paths, ToolVersion: version})
		if err != nil {
			refused++
			fmt.Fprintf(stderr, "%s: refused: %v\n", shortSHA(r.CommitSHA), err)
			continue
		}
		exported++
		if o.notes {
			wrote, err := provExportWriteNote(ctx, root, r.CommitSHA, out)
			switch {
			case err != nil:
				fmt.Fprintf(stderr, "%s: note not written: %v\n", shortSHA(r.CommitSHA), err)
			case wrote:
				notes++
			default:
				fmt.Fprintf(stderr, "%s: already has a git-ai note; left as it is\n", shortSHA(r.CommitSHA))
			}
		}
		if o.format == secchangeexport.FormatGitAI {
			fmt.Fprintf(&buf, "commit %s\n", r.CommitSHA)
		}
		buf.Write(out)
	}
	summary := fmt.Sprintf("%d exported, %d refused", exported, refused)
	if o.notes {
		summary += fmt.Sprintf(", %d git notes written under %s", notes, secchangeexport.GitAINotesRef)
	}
	fmt.Fprintln(stderr, summary)
	if cut {
		fmt.Fprintf(stderr, "CUT: only the newest %d change records of this repository were read; older ones were not exported\n", provExportMaxRecords)
	}
	if o.out != "" {
		return os.WriteFile(o.out, buf.Bytes(), 0o600)
	}
	_, err = stdout.Write(buf.Bytes())
	return err
}

// provExportRecords reads the repository's change records page by page,
// newest first, up to provExportMaxRecords; cut reports that more exist.
func provExportRecords(ctx context.Context, st *store.Store, rootHash string) (recs []store.ChangeRecordRow, cut bool, err error) {
	at, id := "", int64(0)
	for {
		page, err := st.ListChangeRecordsBefore(ctx, rootHash, at, id, provExportPageSize)
		if err != nil {
			return nil, false, err
		}
		if room := provExportMaxRecords - len(recs); len(page) > room {
			return append(recs, page[:room]...), true, nil
		}
		recs = append(recs, page...)
		if len(page) < provExportPageSize {
			return recs, false, nil
		}
		last := page[len(page)-1]
		at, id = last.RecordedAt, last.ID
		if len(recs) == provExportMaxRecords {
			more, err := st.ListChangeRecordsBefore(ctx, rootHash, at, id, 1)
			return recs, len(more) > 0, err
		}
	}
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// provExportNotesConsent reports the repository's live notes consent.
func provExportNotesConsent(ctx context.Context, st *store.Store, rootHash string) (bool, error) {
	cs, err := st.ChangeConsents(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range cs {
		if c.ProjectRootHash == rootHash && c.Notes && c.RevokedAt == "" {
			return true, nil
		}
	}
	return false, nil
}

// provExportWriteNote adds the log as the commit's note under
// refs/notes/ai, only when it has none (`git notes add` without -f refuses
// to replace one, so nothing is ever overwritten).
func provExportWriteNote(ctx context.Context, root, sha string, body []byte) (bool, error) {
	if _, _, err := gitview.RunReadOnlyTimeout(ctx, root, 1<<20, provExportGitTimeout, "notes", "--ref="+secchangeexport.GitAINotesRef, "show", sha); err == nil {
		return false, nil
	}
	if _, err := provenanceGitWrite(ctx, root, body, provExportGitTimeout, "notes", "--ref="+secchangeexport.GitAINotesRef, "add", "-F", "-", sha); err != nil {
		return false, err
	}
	return true, nil
}
