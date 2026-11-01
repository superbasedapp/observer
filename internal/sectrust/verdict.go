package sectrust

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// Verdict is the check's answer for one launch.
type Verdict string

// The closed Verdict vocabulary, least to most severe.
const (
	VerdictClean     Verdict = "clean"
	VerdictFlagged   Verdict = "flagged"
	VerdictUntrusted Verdict = "untrusted"
)

// Level is how much one reason weighs. Information is reported but never
// raises the verdict.
type Level int

// The closed Level vocabulary, least to most severe.
const (
	LevelInfo Level = iota
	LevelFlagged
	LevelUntrusted
)

var levelNames = [...]string{"info", "flagged", "untrusted"}

// String names the level.
func (l Level) String() string {
	if l < 0 || int(l) >= len(levelNames) {
		return "unknown"
	}
	return levelNames[l]
}

// MarshalJSON writes the level's name.
func (l Level) MarshalJSON() ([]byte, error) { return json.Marshal(l.String()) }

// verdictFor is the verdict a highest level maps to.
func verdictFor(l Level) Verdict {
	switch l {
	case LevelUntrusted:
		return VerdictUntrusted
	case LevelFlagged:
		return VerdictFlagged
	default:
		return VerdictClean
	}
}

// Reason is one finding of the check.
type Reason struct {
	// Code is a reason code of the closed vocabulary (Codes).
	Code  string `json:"code"`
	Level Level  `json:"level"`
	// File is the file the reason was found in, slash-separated and
	// relative to the repository root.
	File string `json:"file"`
	// Class is the path-table class the file was read as.
	Class agentconfig.TrustClass `json:"class,omitempty"`
	// Key is the key path, variable name or git key inside the file.
	Key string `json:"key,omitempty"`
	// Excerpt is a short, secret-masked view of the value; never set for a
	// dotenv file, whose values can be credentials.
	Excerpt string `json:"excerpt,omitempty"`
	// Indicators word the reason ("downloads with curl"); they never decide
	// the level.
	Indicators []string `json:"indicators,omitempty"`
	// Digest is set on a command the repository makes the agent run: the
	// exact content the developer can accept ("sha256:<hex>").
	Digest string `json:"digest,omitempty"`
	// Files are the repository files the command names whose bytes the
	// digest also covers (slash paths from the repository root).
	Files []string `json:"files,omitempty"`
	// Accepted reports that Digest was accepted, which lowers the reason
	// one level (untrusted to flagged, flagged to information).
	Accepted bool `json:"accepted,omitempty"`
	// Local reports that the reason was found in one of the developer's own
	// files (ownFile: a project-local scope file, .git/config, a dotenv
	// file): every reason there carries a digest unless its code is Fixed.
	Local bool `json:"local,omitempty"`
	// Observer reports that Request.Own recognised the reason as Observer's
	// own entry (a hook, MCP server or plugin Observer registered).
	Observer bool `json:"observer,omitempty"`

	// value is the exact content an offered digest covers when the call
	// site did not set Digest itself; noDigest withholds the digest (a
	// command whose named files overflowed the fold).
	value    string
	noDigest bool
	// ownContent is the command a repository-run reason names (addRun) or a
	// plugin file's bytes (code), for Request.Own.
	ownContent string
	// runs marks a reason that names code a process runs or loads beyond
	// what its digest covers (a variable that loads modules or libraries);
	// a repository-run code always does (runsCode).
	runs bool
}

// Result is the check's answer for one repository and launch directory.
type Result struct {
	Verdict Verdict  `json:"verdict"`
	Reasons []Reason `json:"reasons"`
	// Roots are the directories visited, relative to the repository root
	// ("" is the root), outermost first.
	Roots []string `json:"roots"`
	// FilesRead and BytesRead bound the work done; PathsTried counts table
	// rows tried at every root.
	FilesRead  int   `json:"files_read"`
	BytesRead  int64 `json:"bytes_read"`
	PathsTried int   `json:"paths_tried"`
	// Files are the table files the check read or hashed, with their
	// content digests: the config baseline's snapshot (Diff). Not part of
	// the JSON shape.
	Files []FileState `json:"-"`
	// Truncated reports that a bound (files per glob, entries per
	// directory, roots) cut the read short.
	Truncated bool `json:"truncated,omitempty"`
}

// Digests returns the digests of the reasons that carry one and are not
// accepted yet: what an accept flow offers the developer.
func (r Result) Digests() []string {
	var out []string
	for _, x := range r.Reasons {
		if x.Digest != "" && !x.Accepted {
			out = append(out, x.Digest)
		}
	}
	return out
}

// WithoutObserver returns r with the reasons Request.Own marked as
// Observer's own entries left out and the verdict recomputed over the rest.
// A launch-time check at the home directory sets Own so that Observer's own
// registered hooks, status line, MCP server and plugins in the developer's
// home config are never something the launch decides on (plans decision log
// P-044 finding 1); Own itself only marks, so the leaving out is this call.
func (r Result) WithoutObserver() Result {
	out := r
	out.Reasons = make([]Reason, 0, len(r.Reasons))
	top := LevelInfo
	for _, x := range r.Reasons {
		if x.Observer {
			continue
		}
		out.Reasons = append(out.Reasons, x)
		if x.Level > top {
			top = x.Level
		}
	}
	out.Verdict = verdictFor(top)
	return out
}

// Codes returns the reason codes in r, in order, repeated codes once.
func (r Result) Codes() []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range r.Reasons {
		if !seen[x.Code] {
			seen[x.Code] = true
			out = append(out, x.Code)
		}
	}
	return out
}

// ErrTruncatedAccept refuses an accept of everything over a result a bound
// cut short: its unread entries nobody saw (plans decision log P-004).
var ErrTruncatedAccept = errors.New("the trust check was cut short (a truncated result: some entries were not read), so accepting everything would accept what nobody saw; accept the digests one by one, or reduce what the repository holds")

// Select picks the reasons an accept stores from the check it just ran:
// with all, every reason whose digest is not accepted yet (refused over a
// truncated result); otherwise the reasons carrying the named digests, each
// of which must be one the check reports. Every surface that accepts (the
// CLI, the dashboard) selects through it.
func (r Result) Select(digests []string, all bool) ([]Reason, error) {
	if all && r.Truncated {
		return nil, ErrTruncatedAccept
	}
	var out []Reason
	for _, x := range r.Reasons {
		if x.Digest == "" {
			continue
		}
		if (all && !x.Accepted) || (!all && slices.Contains(digests, x.Digest)) {
			out = append(out, x)
		}
	}
	for _, d := range digests {
		if !slices.ContainsFunc(out, func(x Reason) bool { return x.Digest == d }) {
			return nil, fmt.Errorf("digest %s is not reported by the trust check here", d)
		}
	}
	return out, nil
}
