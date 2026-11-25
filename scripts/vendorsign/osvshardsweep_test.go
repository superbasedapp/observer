package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// sweepObj is a well-formed shard object path for a short name.
func sweepObj(set, name string) string {
	return osvshardkey.ShardPath(set, content.HashBytes([]byte(name)))
}

func TestPlanShardSweep(t *testing.T) {
	now := time.Date(2026, 12, 31, 3, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	ago := func(d float64) time.Time { return now.Add(-time.Duration(d * float64(day))) }
	A, B, C, P, Q := sweepObj("npm", "a"), sweepObj("npm", "b"), sweepObj("Ubuntu-22.04-LTS", "c"), sweepObj("npm", "p"), sweepObj("Debian-12", "q")
	X, Y, Z, W := sweepObj("npm", "x"), sweepObj("npm", "y"), sweepObj("npm", "z"), sweepObj("npm", "w")
	rec := func(v, prev int64, at time.Time, objs ...string) sweepRecord {
		return sweepRecord{version: v, previous: prev, issued: at, sha256: "sha-" + string(rune('0'+v)), objects: objs}
	}
	cases := []struct {
		name string
		in   sweepInput
		// want is the delete list; wantErr a substring of the refusal.
		want      []string
		wantErr   string
		covered   bool
		prune     []int64
		coveredOn time.Time
	}{
		{
			name: "records younger than the window delete nothing",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(10), A)}, current: []string{A}, uploaded: []string{A, B},
			},
			covered: false, coveredOn: ago(10).Add(30 * day),
		},
		{
			name: "an object named only by the window's anchor is deleted",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A, B), rec(2, 1, ago(20), A)}, current: []string{A}, uploaded: []string{A, B},
			},
			want: []string{B}, covered: true,
		},
		{
			name: "an object still named by a manifest younger than the floor is kept",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), X, Y), rec(2, 1, ago(5), X), rec(3, 2, ago(1), Y)},
				current: []string{Y}, uploaded: []string{X, Y},
			},
			covered: true,
		},
		{
			name: "an object named by a manifest between the floor and the window is kept",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), Z), rec(2, 1, ago(20), Z), rec(3, 2, ago(1), W)},
				current: []string{W}, uploaded: []string{Z, W},
			},
			covered: true,
		},
		{
			name: "an object last named 31 days ago is deleted and older records are pruned",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(45), Z), rec(2, 1, ago(31), Z), rec(3, 2, ago(29), W)},
				current: []string{W}, uploaded: []string{Z, W},
			},
			want: []string{Z}, covered: true, prune: []int64{1},
		},
		{
			name: "a manifest issued exactly at the window's start is the anchor",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(30), A), rec(2, 1, ago(1), B)}, current: []string{B}, uploaded: []string{A, B},
			},
			want: []string{A}, covered: true,
		},
		{
			name: "an object of objects.txt that no record names yet is kept",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(2, 1, ago(1), A)}, current: []string{A, Q}, uploaded: []string{A, Q},
			},
			covered: true,
		},
		{
			name: "the newest manifest's objects are kept when it is older than the window",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(50), A), rec(2, 1, ago(40), B)}, current: []string{C}, uploaded: []string{A, B, C},
			},
			want: []string{A}, covered: true, prune: []int64{1},
		},
		{
			name: "a path a failed delete left pending is deleted again",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(2, 1, ago(1), A)}, current: []string{A}, uploaded: []string{A}, pending: []string{P},
			},
			want: []string{P}, covered: true,
		},
		{
			name: "a pending path a build named again since is kept",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(2, 1, ago(1), A, P)}, current: []string{A, P}, uploaded: []string{A, P}, pending: []string{P},
			},
			covered: true,
		},
		{
			name: "a gap older than the anchor is ignored",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(60), A), rec(3, 2, ago(40), A), rec(4, 3, ago(31), B), rec(5, 4, ago(5), B)},
				current: []string{B}, uploaded: []string{A, B},
			},
			want: []string{A}, covered: true, prune: []int64{1, 3},
		},
		{
			name: "a -manifest-version jump the record chains is no gap",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(9, 1, ago(5), B)}, current: []string{B}, uploaded: []string{A, B},
			},
			want: []string{A}, covered: true,
		},
		{
			name: "a gap inside the window refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(2, 1, ago(20), A), rec(4, 3, ago(10), B)}, current: []string{B}, uploaded: []string{A, B},
			},
			wantErr: "may have no record",
		},
		{
			name: "the last signed manifest with no record refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A)}, signedVersion: 2, signedSHA256: "sha-2", current: []string{A}, uploaded: []string{A, B},
			},
			wantErr: "has no record",
		},
		{
			name: "a record that does not match the signed manifest refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A)}, signedVersion: 1, signedSHA256: "other", current: []string{A}, uploaded: []string{A, B},
			},
			wantErr: "does not match",
		},
		{
			name: "the signed manifest's own record is accepted",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A, B), rec(2, 1, ago(1), A)}, signedVersion: 2, signedSHA256: "sha-2", current: []string{A}, uploaded: []string{A, B},
			},
			want: []string{B}, covered: true,
		},
		{
			name: "a record issued in the future refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(2, 1, now.Add(2*time.Hour), A)}, current: []string{A}, uploaded: []string{A, B},
			},
			wantErr: "after now",
		},
		{
			// v3 inside the window would be left unprotected if v4, issued
			// earlier, were taken as the anchor.
			name: "a later manifest issued earlier refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(2, 1, ago(35), A), rec(3, 2, ago(10), B), rec(4, 3, ago(31), C)},
				current: []string{C}, uploaded: []string{A, B, C},
			},
			wantErr: "before manifest 3",
		},
		{
			// The first run after the sweep is deployed, before osvshards
			// signed a manifest with a record.
			name: "no record at all deletes nothing",
			in:   sweepInput{signedVersion: 7, signedSHA256: "old", current: []string{A}, uploaded: []string{A, B}},
		},
		{
			name: "a malformed uploaded path refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A)}, current: []string{A}, uploaded: []string{A, "content/security.osv_shards/manifest.json"},
			},
			wantErr: "not a shard or index object path",
		},
		{
			name: "a traversal in a pending path refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A)}, current: []string{A}, uploaded: []string{A}, pending: []string{"../obj/" + strings.Repeat("a", 64) + ".json.gz"},
			},
			wantErr: "not a shard or index object path",
		},
		{
			name: "a malformed path in a record refuses",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), "npm/obj/x.json.gz")}, current: []string{A}, uploaded: []string{A},
			},
			wantErr: "not a shard or index object path",
		},
		{
			name: "two records of one version refuse",
			in: sweepInput{
				records: []sweepRecord{rec(1, 0, ago(40), A), rec(1, 0, ago(39), A)}, current: []string{A}, uploaded: []string{A},
			},
			wantErr: "two records",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.now, in.window = now, 30*day
			plan, err := planShardSweep(in)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(plan.delete, tc.want) {
				t.Errorf("delete %v, want %v", plan.delete, tc.want)
			}
			if plan.covered != tc.covered {
				t.Errorf("covered %v, want %v", plan.covered, tc.covered)
			}
			if !reflect.DeepEqual(plan.prune, tc.prune) {
				t.Errorf("prune %v, want %v", plan.prune, tc.prune)
			}
			if !tc.coveredOn.IsZero() && !plan.coveredOn.Equal(tc.coveredOn) {
				t.Errorf("covered on %v, want %v", plan.coveredOn, tc.coveredOn)
			}
			// Whatever is deleted, nothing objects.txt or a record inside the
			// window names is ever among it.
			named := map[string]bool{}
			for _, p := range in.current {
				named[p] = true
			}
			for _, r := range in.records {
				if r.issued.After(now.Add(-30 * day)) {
					for _, p := range r.objects {
						named[p] = true
					}
				}
			}
			for _, p := range plan.delete {
				if named[p] {
					t.Errorf("%s is named by objects.txt or a manifest inside the window, but would be deleted", p)
				}
			}
		})
	}
}

// writeLines writes one path per line.
func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// readLines reads the non-blank lines of path ("" for a missing file).
func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test file
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(raw))
}

// TestOSVShardsSweepEndToEnd builds three publishes with osvshards, records
// every object as uploaded the way publish.sh does, and sweeps: nothing
// before the records cover the window, then exactly the objects only the
// first manifest named.
func TestOSVShardsSweepEndToEnd(t *testing.T) {
	f := newShardFixture(t)
	writeShardInputs(t, f, npmShardRecords())
	root := filepath.Dir(f.objects)
	uploaded := filepath.Join(root, "shards-uploaded.txt")
	pending := filepath.Join(root, "shards-sweep-pending.txt")
	upload := func() {
		have := map[string]bool{}
		for _, p := range readLines(t, uploaded) {
			have[p] = true
		}
		for _, p := range readLines(t, filepath.Join(f.objects, osvShardsObjectsList)) {
			have[p] = true
		}
		var all []string
		for p := range have {
			all = append(all, p)
		}
		sort.Strings(all)
		writeLines(t, uploaded, all)
	}
	day := 24 * time.Hour

	// v1 at T0, the first publish.
	if _, err := buildOSVShards(f.opts(osvT0)); err != nil {
		t.Fatal(err)
	}
	upload()
	v1 := readLines(t, filepath.Join(f.objects, osvShardsObjectsList))

	// Its record names exactly objects.txt and the signed envelope.
	raw := mustRead(t, filepath.Join(f.state, osvShardsPublishedDir, "1.json"))
	var r1 shardPublishedRecord
	if err := json.Unmarshal(raw, &r1); err != nil {
		t.Fatal(err)
	}
	if r1.ManifestVersion != 1 || r1.PreviousVersion != 0 || r1.IssuedAt != osvT0.Format(time.RFC3339) ||
		r1.ManifestSHA256 != content.HashBytes(mustRead(t, filepath.Join(f.kindDir(), "manifest.json"))) ||
		!reflect.DeepEqual(r1.Objects, v1) {
		t.Fatalf("record 1: %+v", r1)
	}

	// An unchanged run writes no record.
	if res, err := buildOSVShards(f.opts(osvT0.Add(time.Hour))); err != nil || !res.Unchanged {
		t.Fatalf("unchanged run: %+v %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(f.state, osvShardsPublishedDir, "2.json")); !os.IsNotExist(err) {
		t.Fatal("an unchanged run wrote a record")
	}

	// v2 at T0+1d: one npm record changes, so one shard and one index file
	// are replaced.
	recs := npmShardRecords()
	recs["GHSA-0001.json"] = strings.Replace(recs["GHSA-0001.json"], "9.9.9", "9.9.10", 1)
	osvWriteEco(t, f.lang, "npm", osvZip(t, recs, osvT0), nil)
	if _, err := buildOSVShards(f.opts(osvT0.Add(day))); err != nil {
		t.Fatal(err)
	}
	upload()
	v2 := readLines(t, filepath.Join(f.objects, osvShardsObjectsList))
	v2set := map[string]bool{}
	for _, p := range v2 {
		v2set[p] = true
	}
	var onlyV1 []string
	for _, p := range v1 {
		if !v2set[p] {
			onlyV1 = append(onlyV1, p)
		}
	}
	if len(onlyV1) != 2 {
		t.Fatalf("v1 names %d objects v2 does not, want a shard and an index file", len(onlyV1))
	}

	sweep := func(now time.Time, days int, dry bool, report string) (string, error) {
		out, err := os.CreateTemp(root, "sweep-out-*")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = out.Close() }()
		err = sweepOSVShards(osvShardSweepOptions{
			State: f.state, Objects: f.objects, Uploaded: uploaded, Pending: pending, Report: report,
			Days: days, DryRun: dry, Now: now,
		}, out)
		return string(mustRead(t, out.Name())), err
	}

	// Two days in, the records do not cover 30 days: nothing changes.
	before := readLines(t, uploaded)
	printed, err := sweep(osvT0.Add(2*day), 30, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(printed, "nothing is deleted before "+osvT0.Add(30*day).Format(time.RFC3339)) {
		t.Errorf("summary does not say when the sweep can start:\n%s", printed)
	}
	if !reflect.DeepEqual(readLines(t, uploaded), before) || readLines(t, pending) != nil {
		t.Fatal("a sweep with no coverage changed the uploaded record or wrote a delete list")
	}

	// A window under the age floor is refused.
	if _, err := sweep(osvT0.Add(40*day), 13, false, ""); err == nil || !strings.Contains(err.Error(), "age floor") {
		t.Fatalf("-days 13: %v", err)
	}

	// v3 at T0+35d: a reissue of v2 (same objects).
	if res, err := buildOSVShards(f.opts(osvT0.Add(35 * day))); err != nil || res.Unchanged || res.ManifestVersion != 3 {
		t.Fatalf("reissue: %+v %v", res, err)
	}
	upload()
	now := osvT0.Add(35 * day)

	// The dry run reports exactly v1's own objects and changes nothing.
	report := filepath.Join(root, "dryrun.txt")
	if printed, err = sweep(now, 30, true, report); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, report); !reflect.DeepEqual(got, onlyV1) {
		t.Fatalf("dry run would delete %v, want %v", got, onlyV1)
	}
	if !strings.Contains(printed, "would delete 2 object(s): npm 2") {
		t.Errorf("dry run summary:\n%s", printed)
	}
	if !reflect.DeepEqual(readLines(t, uploaded), before) || readLines(t, pending) != nil {
		t.Fatal("the dry run changed the uploaded record or wrote a delete list")
	}
	for _, v := range []string{"1", "2", "3"} {
		if _, err := os.Stat(filepath.Join(f.state, osvShardsPublishedDir, v+".json")); err != nil {
			t.Fatalf("the dry run pruned record %s", v)
		}
	}

	// The real sweep: the delete list first, then the uploaded record without
	// it; v2's record is the anchor (the newest issued at or before T0+5d),
	// so v1's is pruned.
	if printed, err = sweep(now, 30, false, ""); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, pending); !reflect.DeepEqual(got, onlyV1) {
		t.Fatalf("delete list %v, want %v", got, onlyV1)
	}
	left := map[string]bool{}
	for _, p := range readLines(t, uploaded) {
		left[p] = true
	}
	for _, p := range onlyV1 {
		if left[p] {
			t.Errorf("%s is still recorded as uploaded", p)
		}
	}
	for _, p := range v2 {
		if !left[p] {
			t.Errorf("%s, which the current manifest names, left the uploaded record", p)
		}
	}
	if !strings.Contains(printed, "delete 2 object(s): npm 2") || !strings.Contains(printed, "1 record(s) older than manifest 2 dropped") {
		t.Errorf("summary:\n%s", printed)
	}
	if _, err := os.Stat(filepath.Join(f.state, osvShardsPublishedDir, "1.json")); !os.IsNotExist(err) {
		t.Error("record 1, older than the anchor, was kept")
	}

	// Later the anchor moves to v3: v2's record is pruned, and the delete
	// list (as if rclone had failed) is decided again and kept.
	if _, err := buildOSVShards(f.opts(osvT0.Add(36 * day))); err != nil {
		t.Fatal(err)
	}
	upload()
	if _, err = sweep(osvT0.Add(65*day), 30, false, ""); err != nil {
		t.Fatal(err)
	}
	if got := readLines(t, pending); !reflect.DeepEqual(got, onlyV1) {
		t.Fatalf("a pending list was not carried: %v", got)
	}
	for v, want := range map[string]bool{"1": false, "2": false, "3": true, "4": true} {
		_, err := os.Stat(filepath.Join(f.state, osvShardsPublishedDir, v+".json"))
		if (err == nil) != want {
			t.Errorf("record %s present %v, want %v", v, err == nil, want)
		}
	}

	// Another kind's state directory is refused.
	other := newShardFixture(t)
	if err := claimFeedState(other.state, "osvexport", content.OSVExport); err != nil {
		t.Fatal(err)
	}
	if err := sweepOSVShards(osvShardSweepOptions{State: other.state, Objects: f.objects, Uploaded: uploaded, Pending: pending, Days: 30, Now: now}, os.Stdout); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("another kind's state: %v", err)
	}
}

func TestOSVShardSweepVerb(t *testing.T) {
	root := t.TempDir()
	stdout, err := os.Create(filepath.Join(root, "stdout"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdout.Close() }()
	if err := run([]string{"osvshardsweep", "-state", root}, stdout); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("missing flags: %v", err)
	}
	args := []string{"osvshardsweep", "-state", root, "-objects", root, "-uploaded", filepath.Join(root, "u"), "-pending", filepath.Join(root, "p")}
	if err := run(append(args, "-report", filepath.Join(root, "r")), stdout); err == nil || !strings.Contains(err.Error(), "-dry-run") {
		t.Fatalf("-report without -dry-run: %v", err)
	}
	if err := run(append(args, "-days", "7"), stdout); err == nil || !strings.Contains(err.Error(), "age floor") {
		t.Fatalf("-days 7: %v", err)
	}
	if err := run(args, stdout); err == nil || !strings.Contains(err.Error(), "not an osvshards state directory") {
		t.Fatalf("an empty state directory: %v", err)
	}
}
