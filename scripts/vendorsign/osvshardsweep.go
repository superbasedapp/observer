package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// osvshardsweep.go is the `vendorsign osvshardsweep` verb: it decides which
// objects of the public shard bucket no published security.osv_shards
// manifest has named for N days, so the publisher can delete them
// (deploy/feed-publisher/README.md, "Remote-lookup shards"). Without it the
// bucket only grows: every shard is named by the sha256 of its bytes, a
// changed shard is a new object, and the old one stays.
//
// It decides from the publisher's own records, never from a bucket
// listing:
//
//	<state>/published/<version>.json  one record per manifest osvshards
//	                                  signed: its version, the version
//	                                  before it, its issued_at, the sha256
//	                                  of the envelope and every object path
//	                                  it names (osvshards writes it before
//	                                  objects.txt and the manifest, so every
//	                                  manifest that can be uploaded has one)
//	<state>/manifest.json, state.json the last manifest osvshards signed
//	<objects>/objects.txt             what the last build names
//	-uploaded FILE                    publish.sh's shards-uploaded.txt: every
//	                                  object it uploaded to the bucket
//	-pending FILE                     the delete journal: the last decision
//	                                  that rclone has not finished deleting
//
// Why issued_at bounds it: a node uses a manifest for at most the kind's
// age floor after its issued_at (content.FreshnessAt: past it the data is
// unknown). An object is "last named" at the issued_at of the newest
// manifest that names it; once that is more than the window (N days, never
// less than the age floor) ago, no manifest a node may still use names it.
// The records must cover the whole window for that to hold, so the sweep
// deletes nothing until the oldest record is at least N days old, and
// nothing when the records' version chain has a gap inside the window or
// the last signed manifest has no record.
//
// An age-based R2 lifecycle rule cannot do this: an unchanged shard keeps
// the date it was first uploaded, so such a rule would delete objects the
// current manifest still names.
//
// The decision is the rule table sweepRules, walked top-down; the first
// rule that matches an object decides it. In delete mode the verb writes the
// delete list to -pending FIRST, then removes those paths from -uploaded
// (so a later build that names one again uploads it again), then drops the
// records older than the window's anchor; publish.sh deletes the listed
// objects with rclone and removes -pending only when that succeeded. A
// pending list left by a failed delete is merged into the next decision, and
// each of its paths is checked again (one named again since is kept).

const (
	osvShardSweepVerb = "osvshardsweep"
	// osvShardsPublishedDir is the state subdirectory of the published
	// records.
	osvShardsPublishedDir = "published"
	// osvShardSweepDefaultDays is the default window.
	osvShardSweepDefaultDays = 30
	// osvShardSweepClockSlack is how far in the future a record's issued_at
	// may be before the sweep refuses to trust the clock.
	osvShardSweepClockSlack = time.Hour
)

// shardObjectRE is the only shape of a shard bucket object path
// (osvshardkey.ShardPath and IndexPath); publish.sh's SHARD_OBJECT_RE is
// the same expression. A path of any other shape in any input refuses the
// sweep.
var shardObjectRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}/(obj/[0-9a-f]{64}\.json\.gz|index/[0-9a-f]{64}\.json)$`)

// shardPublishedRecord is one published/<version>.json.
type shardPublishedRecord struct {
	ManifestVersion int64    `json:"manifest_version"`
	PreviousVersion int64    `json:"previous_version"`
	IssuedAt        string   `json:"issued_at"`
	ManifestSHA256  string   `json:"manifest_sha256"`
	Objects         []string `json:"objects"`
}

// writeShardPublishedRecord writes the record of one manifest osvshards is
// about to publish (temp + rename). objects is sorted.
func writeShardPublishedRecord(state string, rec shardPublishedRecord) error {
	dir := filepath.Join(state, osvShardsPublishedDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vendorsign %s: %w", osvShardsVerb, err)
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("vendorsign %s: %w", osvShardsVerb, err)
	}
	return writeFileAtomic(filepath.Join(dir, strconv.FormatInt(rec.ManifestVersion, 10)+".json"), append(raw, '\n'), 0o600)
}

// sweepRecord is a record as the plan reads it.
type sweepRecord struct {
	version, previous int64
	issued            time.Time
	sha256            string
	objects           []string
}

// sweepInput is everything the plan decides from, already read.
type sweepInput struct {
	now    time.Time
	window time.Duration
	// records are every published record, in any order.
	records []sweepRecord
	// signedVersion and signedSHA256 are the last manifest osvshards signed
	// (state.json's version, the sha256 of state/manifest.json); 0 and ""
	// when it signed none.
	signedVersion int64
	signedSHA256  string
	// current is objects.txt; uploaded is shards-uploaded.txt; pending is a
	// delete journal a failed delete left.
	current, uploaded, pending []string
}

// sweepVerdict is what one rule decides for an object.
type sweepVerdict int

const (
	sweepKeep sweepVerdict = iota
	sweepDelete
)

// sweepFacts is what the rules know about one object (every object the
// plan looks at is uploaded or pending: nothing else is ours to delete).
type sweepFacts struct {
	inCurrent bool
	inNewest  bool
	inWindow  bool
	covered   bool
}

// sweepRule is one row of the decision table.
type sweepRule struct {
	name    string
	match   func(sweepFacts) bool
	verdict sweepVerdict
}

// sweepRules is the decision table, walked top-down, first match wins.
var sweepRules = []sweepRule{
	{"named by objects.txt (the last build)", func(f sweepFacts) bool { return f.inCurrent }, sweepKeep},
	{"named by the newest published manifest", func(f sweepFacts) bool { return f.inNewest }, sweepKeep},
	{"named by a manifest issued inside the window", func(f sweepFacts) bool { return f.inWindow }, sweepKeep},
	{"the records do not cover the window yet", func(f sweepFacts) bool { return !f.covered }, sweepKeep},
	{"named by no manifest a node may still use", func(sweepFacts) bool { return true }, sweepDelete},
}

// sweepPlan is one decision.
type sweepPlan struct {
	// noRecords is a sweep before any published record exists.
	noRecords bool
	// covered is whether the records reach back to the window's start;
	// coveredOn is when they will (the oldest record's issued_at plus the
	// window) when they do not yet.
	covered   bool
	coveredOn time.Time
	// anchor is the newest record issued at or before the window's start
	// (0 when none); records older than it are pruned.
	anchor  int64
	prune   []int64
	delete  []string
	kept    int
	records int
	oldest  time.Time
	newest  time.Time
	// reasons counts the kept objects per rule.
	reasons map[string]int
}

// planShardSweep decides which uploaded objects to delete. It fails closed:
// a malformed path, a record chain gap inside the window, a record issued in
// the future or before an earlier version's, or a signed manifest with no
// record is an error, never a smaller protected set.
func planShardSweep(in sweepInput) (sweepPlan, error) {
	verb := osvShardSweepVerb
	for _, l := range [][]string{in.current, in.uploaded, in.pending} {
		for _, p := range l {
			if !shardObjectRE.MatchString(p) || strings.Contains(p, "..") {
				return sweepPlan{}, fmt.Errorf("vendorsign %s: %q is not a shard or index object path", verb, p)
			}
		}
	}
	if len(in.records) == 0 {
		// Before osvshards signed its first manifest with a record (the
		// sweep's first deployment): nothing is known, nothing is deleted.
		return sweepPlan{noRecords: true, kept: len(in.uploaded), reasons: map[string]int{"no published record yet": len(in.uploaded)}}, nil
	}
	recs := append([]sweepRecord(nil), in.records...)
	sort.Slice(recs, func(i, j int) bool { return recs[i].version < recs[j].version })
	for i, r := range recs {
		if i > 0 && r.version == recs[i-1].version {
			return sweepPlan{}, fmt.Errorf("vendorsign %s: two records of manifest %d", verb, r.version)
		}
		// The window is cut by issued_at and the records are walked by
		// version, so a later manifest issued earlier (a clock that went
		// back) could leave one inside the window unprotected.
		if i > 0 && r.issued.Before(recs[i-1].issued) {
			return sweepPlan{}, fmt.Errorf("vendorsign %s: manifest %d was issued at %s, before manifest %d (%s); refusing to trust the clock", verb, r.version, r.issued.Format(time.RFC3339), recs[i-1].version, recs[i-1].issued.Format(time.RFC3339))
		}
		if r.issued.After(in.now.Add(osvShardSweepClockSlack)) {
			return sweepPlan{}, fmt.Errorf("vendorsign %s: manifest %d was issued at %s, after now (%s); refusing to trust the clock", verb, r.version, r.issued.Format(time.RFC3339), in.now.Format(time.RFC3339))
		}
		for _, p := range r.objects {
			if !shardObjectRE.MatchString(p) || strings.Contains(p, "..") {
				return sweepPlan{}, fmt.Errorf("vendorsign %s: manifest %d names %q, which is not a shard or index object path", verb, r.version, p)
			}
		}
	}
	newest := recs[len(recs)-1]
	if in.signedVersion > 0 {
		found := false
		for _, r := range recs {
			if r.version == in.signedVersion {
				if r.sha256 != in.signedSHA256 {
					return sweepPlan{}, fmt.Errorf("vendorsign %s: the record of manifest %d does not match the manifest osvshards signed", verb, r.version)
				}
				found = true
			}
		}
		if !found {
			return sweepPlan{}, fmt.Errorf("vendorsign %s: the last signed manifest (%d) has no record; nothing is deleted until a manifest is published with one", verb, in.signedVersion)
		}
	}

	plan := sweepPlan{records: len(recs), oldest: recs[0].issued, newest: newest.issued, reasons: map[string]int{}}
	start := in.now.Add(-in.window)
	anchorAt := -1
	for i, r := range recs {
		if !r.issued.After(start) {
			anchorAt = i
		}
	}
	plan.covered = anchorAt >= 0
	if !plan.covered {
		plan.coveredOn = recs[0].issued.Add(in.window)
	} else {
		plan.anchor = recs[anchorAt].version
		for _, r := range recs[:anchorAt] {
			plan.prune = append(plan.prune, r.version)
		}
		// Every record from the anchor on must chain to the one before it,
		// or a manifest published in the window may be missing.
		for i := anchorAt + 1; i < len(recs); i++ {
			if recs[i].previous != recs[i-1].version {
				return sweepPlan{}, fmt.Errorf("vendorsign %s: manifest %d follows %d, but its record names %d before it; a published manifest may have no record, so nothing is deleted until the gap is older than the window", verb, recs[i].version, recs[i-1].version, recs[i].previous)
			}
		}
	}

	set := func(l []string) map[string]bool {
		m := make(map[string]bool, len(l))
		for _, p := range l {
			m[p] = true
		}
		return m
	}
	current := set(in.current)
	newestSet := set(newest.objects)
	window := map[string]bool{}
	if plan.covered {
		for _, r := range recs[anchorAt+1:] {
			for _, p := range r.objects {
				window[p] = true
			}
		}
	}
	all := set(in.uploaded)
	for _, p := range in.pending {
		all[p] = true
	}
	paths := make([]string, 0, len(all))
	for p := range all {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		f := sweepFacts{inCurrent: current[p], inNewest: newestSet[p], inWindow: window[p], covered: plan.covered}
		for _, r := range sweepRules {
			if !r.match(f) {
				continue
			}
			if r.verdict == sweepDelete {
				plan.delete = append(plan.delete, p)
			} else {
				plan.kept++
				plan.reasons[r.name]++
			}
			break
		}
	}
	return plan, nil
}

// osvShardSweepOptions is one sweep.
type osvShardSweepOptions struct {
	State, Objects, Uploaded, Pending string
	// Report, in dry-run mode, is where the delete list is written (""
	// writes it to the output).
	Report string
	Days   int
	DryRun bool
	Now    time.Time
}

func runOSVShardSweep(args []string, out *os.File) error {
	fsx := flag.NewFlagSet(osvShardSweepVerb, flag.ContinueOnError)
	state := fsx.String("state", "", "osvshards' state directory (its published/ records)")
	objects := fsx.String("objects", "", "osvshards' object store (its objects.txt)")
	uploaded := fsx.String("uploaded", "", "the record of every object uploaded to the shard bucket (publish.sh's shards-uploaded.txt)")
	pending := fsx.String("pending", "", "the delete journal: written in delete mode, merged when a failed delete left one")
	days := fsx.Int("days", osvShardSweepDefaultDays, "delete objects no manifest has named for this many days (at least the kind's age floor)")
	dryRun := fsx.Bool("dry-run", false, "print what would be deleted and change nothing")
	report := fsx.String("report", "", "dry run: write the delete list here instead of the output")
	if err := fsx.Parse(args); err != nil {
		return err
	}
	if *state == "" || *objects == "" || *uploaded == "" || *pending == "" {
		return errors.New("vendorsign osvshardsweep: -state, -objects, -uploaded and -pending are required")
	}
	if *report != "" && !*dryRun {
		return errors.New("vendorsign osvshardsweep: -report is for -dry-run; a real sweep writes its list to -pending")
	}
	return sweepOSVShards(osvShardSweepOptions{
		State: *state, Objects: *objects, Uploaded: *uploaded, Pending: *pending, Report: *report,
		Days: *days, DryRun: *dryRun, Now: time.Now().UTC(),
	}, out)
}

// sweepOSVShards reads the records, plans the sweep, prints the summary and,
// unless it is a dry run, writes the delete journal, then the uploaded
// record without those paths, then prunes the records older than the
// anchor. It never touches the bucket.
func sweepOSVShards(o osvShardSweepOptions, out io.Writer) error {
	verb := osvShardSweepVerb
	ks, ok := content.KindOf(content.OSVShards)
	if !ok {
		return fmt.Errorf("vendorsign %s: %s is not a content kind", verb, content.OSVShards)
	}
	window := time.Duration(o.Days) * 24 * time.Hour
	if window < ks.AgeFloor {
		return fmt.Errorf("vendorsign %s: -days %d is under the kind's age floor of %d days; a node may still use a manifest that names what it would delete", verb, o.Days, int(ks.AgeFloor/(24*time.Hour)))
	}
	raw, err := os.ReadFile(filepath.Join(o.State, osvKindFile)) //nolint:gosec // osvshards' own state directory
	if err != nil {
		return fmt.Errorf("vendorsign %s: %s is not an osvshards state directory: %w", verb, o.State, err)
	}
	if got := strings.TrimSpace(string(raw)); got != string(content.OSVShards) {
		return fmt.Errorf("vendorsign %s: the state directory %s belongs to %s, not %s", verb, o.State, got, content.OSVShards)
	}
	in := sweepInput{now: o.Now.UTC(), window: window}
	if in.records, err = readShardRecords(o.State); err != nil {
		return err
	}
	st, err := loadOSVState(o.State)
	if err != nil {
		return err
	}
	if st.ManifestVersion > 0 {
		env, err := os.ReadFile(filepath.Join(o.State, "manifest.json")) //nolint:gosec // osvshards' own state directory
		if err != nil {
			return fmt.Errorf("vendorsign %s: %w", verb, err)
		}
		in.signedVersion, in.signedSHA256 = st.ManifestVersion, content.HashBytes(env)
	}
	if in.current, err = readPathList(filepath.Join(o.Objects, osvShardsObjectsList), true); err != nil {
		return err
	}
	if in.uploaded, err = readPathList(o.Uploaded, true); err != nil {
		return err
	}
	if in.pending, err = readPathList(o.Pending, false); err != nil {
		return err
	}
	plan, err := planShardSweep(in)
	if err != nil {
		return err
	}
	printShardSweep(out, o, plan, len(in.uploaded))
	if o.DryRun {
		var b bytes.Buffer
		for _, p := range plan.delete {
			b.WriteString(p)
			b.WriteByte('\n')
		}
		if o.Report == "" {
			_, err := out.Write(b.Bytes())
			return err
		}
		return writeFileAtomic(o.Report, b.Bytes(), 0o600)
	}

	if !plan.covered {
		// Nothing was decided: a journal a failed delete left stays for
		// the run that can decide it again.
		return nil
	}
	// The journal first: a crash after it leaves every path still in the
	// uploaded record (so still a candidate), or in the journal (retried).
	var b bytes.Buffer
	for _, p := range plan.delete {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	if len(plan.delete) == 0 {
		if err := os.Remove(o.Pending); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vendorsign %s: %w", verb, err)
		}
	} else {
		if err := writeFileAtomic(o.Pending, b.Bytes(), 0o600); err != nil {
			return err
		}
		gone := make(map[string]bool, len(plan.delete))
		for _, p := range plan.delete {
			gone[p] = true
		}
		var keep bytes.Buffer
		for _, p := range in.uploaded {
			if !gone[p] {
				keep.WriteString(p)
				keep.WriteByte('\n')
			}
		}
		if err := writeFileAtomic(o.Uploaded, keep.Bytes(), 0o600); err != nil {
			return err
		}
	}
	for _, v := range plan.prune {
		p := filepath.Join(o.State, osvShardsPublishedDir, strconv.FormatInt(v, 10)+".json")
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("vendorsign %s: prune %s: %w", verb, p, err)
		}
	}
	return nil
}

// readShardRecords reads every published record; a file that is not one,
// or a record whose name and version disagree, refuses the sweep.
func readShardRecords(state string) ([]sweepRecord, error) {
	verb := osvShardSweepVerb
	dir := filepath.Join(state, osvShardsPublishedDir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vendorsign %s: %w", verb, err)
	}
	var out []sweepRecord
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".") {
			continue // a temp file of writeFileAtomic
		}
		v, ok := strings.CutSuffix(name, ".json")
		n, err := strconv.ParseInt(v, 10, 64)
		if e.IsDir() || !ok || err != nil || n <= 0 {
			return nil, fmt.Errorf("vendorsign %s: %s is not a published record", verb, filepath.Join(dir, name))
		}
		raw, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // osvshards' own state directory
		if err != nil {
			return nil, fmt.Errorf("vendorsign %s: %w", verb, err)
		}
		var rec shardPublishedRecord
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&rec); err != nil {
			return nil, fmt.Errorf("vendorsign %s: %s: %w", verb, name, err)
		}
		issued, err := time.Parse(time.RFC3339, rec.IssuedAt)
		if err != nil || rec.ManifestVersion != n || rec.PreviousVersion < 0 || rec.PreviousVersion >= rec.ManifestVersion {
			return nil, fmt.Errorf("vendorsign %s: %s is not a valid published record", verb, name)
		}
		out = append(out, sweepRecord{version: n, previous: rec.PreviousVersion, issued: issued.UTC(), sha256: rec.ManifestSHA256, objects: rec.Objects})
	}
	return out, nil
}

// readPathList reads one path per line, skipping blank lines; a missing
// file is an error when required, else empty.
func readPathList(path string, required bool) ([]string, error) {
	f, err := os.Open(path) //nolint:gosec // the publisher's own records
	if errors.Is(err, os.ErrNotExist) && !required {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vendorsign %s: %w", osvShardSweepVerb, err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 1<<16)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("vendorsign %s: %s: %w", osvShardSweepVerb, path, err)
	}
	return out, nil
}

// printShardSweep writes the summary: the window and records, what is kept
// and why, and what is deleted per set.
func printShardSweep(out io.Writer, o osvShardSweepOptions, plan sweepPlan, uploaded int) {
	verb := osvShardSweepVerb
	mode := "delete"
	if o.DryRun {
		mode = "dry run"
	}
	if plan.noRecords {
		fmt.Fprintf(out, "%s: %s, window %d days; no published record yet (osvshards writes one with every manifest it signs); nothing is deleted\n", verb, mode, o.Days)
		return
	}
	fmt.Fprintf(out, "%s: %s, window %d days; %d published record(s), %s to %s\n", verb, mode, o.Days, plan.records,
		plan.oldest.Format(time.RFC3339), plan.newest.Format(time.RFC3339))
	if !plan.covered {
		fmt.Fprintf(out, "%s: the records do not cover the window yet; nothing is deleted before %s\n", verb, plan.coveredOn.Format(time.RFC3339))
	}
	reasons := make([]string, 0, len(plan.reasons))
	for r := range plan.reasons {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	fmt.Fprintf(out, "%s: %d uploaded object(s); %d kept", verb, uploaded, plan.kept)
	for _, r := range reasons {
		fmt.Fprintf(out, "; %d %s", plan.reasons[r], r)
	}
	fmt.Fprintln(out)
	perSet := map[string]int{}
	for _, p := range plan.delete {
		s, _, _ := strings.Cut(p, "/")
		perSet[s]++
	}
	sets := make([]string, 0, len(perSet))
	for s := range perSet {
		sets = append(sets, s)
	}
	sort.Strings(sets)
	parts := make([]string, 0, len(sets))
	for _, s := range sets {
		parts = append(parts, fmt.Sprintf("%s %d", s, perSet[s]))
	}
	verbDel := "delete"
	if o.DryRun {
		verbDel = "would delete"
	}
	if len(plan.delete) == 0 {
		fmt.Fprintf(out, "%s: %s nothing\n", verb, verbDel)
	} else {
		fmt.Fprintf(out, "%s: %s %d object(s): %s\n", verb, verbDel, len(plan.delete), strings.Join(parts, ", "))
	}
	if len(plan.prune) > 0 && !o.DryRun {
		fmt.Fprintf(out, "%s: %d record(s) older than manifest %d dropped\n", verb, len(plan.prune), plan.anchor)
	}
}
