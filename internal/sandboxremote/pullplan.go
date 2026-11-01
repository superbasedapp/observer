package sandboxremote

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// pullplan.go is the checkpoint transcript pull plan (sandbox plan v2
// section 5.7, lane SBX-P7 orchestrator default): at every checkpoint and
// at teardown the host pulls the agent tool's transcript files out of the
// box, no-follow and size-capped, into a per-run quarantine directory, and
// ingests them with session and event ids re-keyed under the run id and
// capture_origin = remote_sandbox. Only the tool's own state directories
// are read (the integration registry's SandboxSpec.StateRW, resolved to box
// paths by the cmd layer); nothing else of the box is pulled.
//
// The in-box database row export with a closed, versioned schema is a
// later item; transcripts carry the conversation and tokens the adapters
// already parse.

// BoxFile is one file the box listed (a find run inside the box: path,
// size, and whether it is a regular file; a symlink is never regular).
type BoxFile struct {
	Path    string
	Size    int64
	Regular bool
}

// PullLimits bound one pull.
type PullLimits struct {
	MaxFiles      int
	MaxFileBytes  int64
	MaxTotalBytes int64
}

// DefaultPullLimits: 2000 files, 64 MiB each, 512 MiB in all.
var DefaultPullLimits = PullLimits{MaxFiles: 2000, MaxFileBytes: 64 << 20, MaxTotalBytes: 512 << 20}

// pullSuffixes are the transcript shapes the adapters read.
var pullSuffixes = []string{".jsonl", ".json", ".md", ".db", ".sqlite"}

// PullItem is one file to copy.
type PullItem struct {
	BoxPath string
	// LocalRel is the slash path under the run's quarantine directory:
	// <root index>/<path below the root>.
	LocalRel string
	Size     int64
}

// The closed pull skip reasons.
const (
	SkipNotRegular = "not_a_regular_file"
	SkipOutside    = "outside_tool_state"
	SkipNotTrans   = "not_a_transcript_shape"
	SkipFileCap    = "over_file_cap"
	SkipTotalCap   = "over_total_cap"
)

// PlanPull chooses what to copy from listed under the box roots (absolute
// box paths of the tool's state directories).
func PlanPull(roots []string, listed []BoxFile, lim PullLimits) ([]PullItem, []Exclusion) {
	if lim == (PullLimits{}) {
		lim = DefaultPullLimits
	}
	var items []PullItem
	var skipped []Exclusion
	sorted := append([]BoxFile(nil), listed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	var total int64
	for _, f := range sorted {
		p := path.Clean(f.Path)
		idx, rel := underRoot(p, roots)
		switch {
		case !f.Regular:
			skipped = append(skipped, Exclusion{f.Path, SkipNotRegular})
		case idx < 0 || !path.IsAbs(f.Path) || strings.Contains(f.Path, "\x00"):
			skipped = append(skipped, Exclusion{f.Path, SkipOutside})
		case !transcriptShape(p):
			skipped = append(skipped, Exclusion{f.Path, SkipNotTrans})
		case f.Size < 0 || f.Size > lim.MaxFileBytes:
			skipped = append(skipped, Exclusion{f.Path, SkipFileCap})
		case len(items) >= lim.MaxFiles || total+f.Size > lim.MaxTotalBytes:
			skipped = append(skipped, Exclusion{f.Path, SkipTotalCap})
		default:
			total += f.Size
			items = append(items, PullItem{BoxPath: p, LocalRel: strconv.Itoa(idx) + "/" + rel, Size: f.Size})
		}
	}
	return items, skipped
}

func underRoot(p string, roots []string) (int, string) {
	for i, r := range roots {
		r = path.Clean(r)
		if strings.HasPrefix(p, r+"/") {
			rel := strings.TrimPrefix(p, r+"/")
			if rel != "" && !strings.HasPrefix(rel, "../") && rel != ".." {
				return i, rel
			}
		}
	}
	return -1, ""
}

func transcriptShape(p string) bool {
	for _, s := range pullSuffixes {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

// RekeyID namespaces a box-reported id under the run, so a box can never
// collide with or upgrade another session's rows (section 5.7). It is
// sandboxvocab.RekeyID, re-exported here.
func RekeyID(runID, id string) string { return sandboxvocab.RekeyID(runID, id) }

// RelayRunHeader names the hosted run a relayed model request came from
// (live run 2 finding N5). The spelling lives in internal/sandboxvocab so
// the proxy reads it without linking this package.
const RelayRunHeader = sandboxvocab.RelayRunHeader

// RelaySessionID is the session a relayed model turn of run runID lands
// on; see sandboxvocab.RelaySessionID.
func RelaySessionID(runID, sid string) string { return sandboxvocab.RelaySessionID(runID, sid) }

// ValidRelayRunID reports whether s is shaped like a run id; see
// sandboxvocab.ValidRelayRunID.
func ValidRelayRunID(s string) bool { return sandboxvocab.ValidRelayRunID(s) }
