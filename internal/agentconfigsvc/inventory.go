package agentconfigsvc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// The managed node's AI tool configuration inventory (D-112 "the org sees
// everything on managed nodes", T-427). Inventory reads, it never writes:
// every catalogued setting found in an installed tool's settings files (user,
// system and managed files once, each known project clone's files once) and
// every instruction-family file (instructions, skills, agents, commands,
// rules) with its text. Values and text go through the T-428 rule: a
// personal file's value is kept like any other and a secret is SCRUBBED, never
// dropped and never shipped raw. A file the catalogue marks never-read is not
// opened. Whether the report ships is the push seam's decision (managed
// enrolment, raw content); the caller here only decides when to build it.

// InventoryMaxProjects caps the project clones one inventory reads.
const InventoryMaxProjects = 50

var inventoryProjectRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// inventoryScope is one pass of the inventory: the user level (project "")
// or one project clone.
type inventoryScope struct {
	project string // local root ("" = user level)
	hash    string // project identity hash ("" = user level)
}

// Inventory builds the node's AI tool configuration report. roots maps a
// project identity hash to its local clones (the first clone of each is read,
// at most InventoryMaxProjects projects, in hash order).
func (s *Service) Inventory(ctx context.Context, roots map[string][]string) orgcontract.AgentConfigInventoryReport {
	now := s.o.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	scopes := []inventoryScope{{}}
	hashes := make([]string, 0, len(roots))
	for h, rs := range roots {
		if inventoryProjectRE.MatchString(h) && len(rs) > 0 {
			hashes = append(hashes, h)
		}
	}
	sort.Strings(hashes)
	if len(hashes) > InventoryMaxProjects {
		hashes = hashes[:InventoryMaxProjects]
	}
	for _, h := range hashes {
		scopes = append(scopes, inventoryScope{project: roots[h][0], hash: h})
	}
	var rows []orgcontract.AgentConfigStateRow
	for _, tool := range integration.Tools() {
		if ctx.Err() != nil {
			break
		}
		if !knownTool(tool) || !s.Installed(tool) {
			continue
		}
		for _, sc := range scopes {
			rows = append(rows, s.inventorySettings(tool, sc, now)...)
			rows = append(rows, s.inventoryFiles(ctx, tool, sc, now)...)
		}
	}
	return finishInventory(rows)
}

// inScope reports whether a file row belongs to the pass: project files in a
// project pass, every other file in the user pass.
func inScope(sc inventoryScope, scope agentconfig.Scope) bool {
	project := scope == agentconfig.ScopeProjectShared || scope == agentconfig.ScopeProjectLocal
	return project == (sc.project != "")
}

// inventorySettings lists every catalogued setting that holds a value in one
// of the pass's settings files.
func (s *Service) inventorySettings(tool string, sc inventoryScope, now string) []orgcontract.AgentConfigStateRow {
	var snaps []agentconfig.FileSnapshot
	for _, sn := range s.snapshots(tool, sc.project) {
		if inScope(sc, sn.Row.Scope) && sn.State == agentconfig.FilePresent {
			snaps = append(snaps, sn)
		}
	}
	if len(snaps) == 0 {
		return nil
	}
	view := agentconfig.InspectTool(agentconfig.InspectInput{Tool: tool, Files: snaps, Detect: s.o.Detect, Spans: s.spanEnv(), Project: sc.project})
	var out []orgcontract.AgentConfigStateRow
	for _, sv := range view.Settings {
		for _, v := range sv.Values {
			row := orgcontract.AgentConfigStateRow{
				Tool: tool, Setting: sv.ID, FileID: v.FileID, Scope: string(v.Scope), ProjectHash: sc.hash,
				State: orgcontract.AgentConfigInventoryState, ObservedAt: now,
			}
			var value any = scrub.Redacted
			secret := true
			if !v.SecretPresent {
				value, secret = s.ScrubOrgValue(v.Value)
				secret = secret || v.Masked || sv.Secret
				if sv.Secret {
					value = scrub.Redacted
				}
			}
			b, err := json.Marshal(value)
			if err != nil {
				continue
			}
			row.ObservedValue = string(b)
			row.ObservedHash = agentconfig.ValueHash(value)
			if secret {
				row.Reason = orgcontract.AgentConfigInventorySecret
			}
			if len(row.ObservedValue) > orgcontract.AgentConfigObservedMaxBytes {
				row.ObservedValue, row.Reason = "", orgcontract.AgentConfigInventoryTruncated
			}
			out = append(out, row)
		}
	}
	return out
}

// inventoryFiles lists the pass's existing instruction-family files with
// their scrubbed text.
func (s *Service) inventoryFiles(ctx context.Context, tool string, sc inventoryScope, now string) []orgcontract.AgentConfigStateRow {
	files, err := s.Instructions(ctx, tool, sc.project)
	if err != nil {
		return nil
	}
	base, prefix := sc.project, ""
	if sc.project == "" {
		base, prefix = s.o.Home, "~/"
	}
	var out []orgcontract.AgentConfigStateRow
	for _, f := range files {
		if !f.Exists || !inScope(sc, f.Scope) || base == "" {
			continue
		}
		if row, ok := fileRow(f.FileID); !ok || row.WriteNeeds == agentconfig.PrivNever {
			continue
		}
		var relID string
		if sc.project == "" && f.relocatedID != "" {
			// A file a relocation variable moved keeps the catalogue's
			// home spelling as its id (FU-142): the same logical file,
			// and no local path on the row.
			relID = f.relocatedID
		} else {
			rel, err := filepath.Rel(base, f.Path)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			relID = prefix + filepath.ToSlash(rel)
		}
		if sc.project != "" && projectLinkEscapes(f.Path, sc.project) {
			continue
		}
		b, present, err := s.readFile(f.Path)
		if err != nil || !present {
			continue
		}
		text, secret := s.ScrubOrgText(string(b))
		row := orgcontract.AgentConfigStateRow{
			Tool: tool, Setting: orgcontract.AgentConfigInventoryKindSetting(tool, string(f.Kind)),
			FileID: orgcontract.AgentConfigInventoryFileID(tool, string(f.Kind), relID),
			Scope:  string(f.Scope), ProjectHash: sc.hash, State: orgcontract.AgentConfigInventoryState,
			ObservedHash: agentconfig.ValueHash(text), ObservedAt: now,
		}
		if secret {
			row.Reason = orgcontract.AgentConfigInventorySecret
		}
		row.ObservedValue, row.Reason = encodeInventoryText(text, row.Reason)
		out = append(out, row)
	}
	return out
}

// encodeInventoryText returns the JSON string of text, cut (at a rune
// boundary) so the encoding fits AgentConfigObservedMaxBytes; a cut text
// carries the truncated reason.
func encodeInventoryText(text, reason string) (string, string) {
	b, _ := json.Marshal(text)
	if len(b) <= orgcontract.AgentConfigObservedMaxBytes {
		return string(b), reason
	}
	cut := orgcontract.AgentConfigObservedMaxBytes / 2
	for {
		t := text
		if cut < len(t) {
			t = t[:cut]
			for len(t) > 0 && !utf8.ValidString(t) {
				t = t[:len(t)-1]
			}
		}
		b, _ = json.Marshal(t)
		if len(b) <= orgcontract.AgentConfigObservedMaxBytes || cut <= 0 {
			return string(b), orgcontract.AgentConfigInventoryTruncated
		}
		cut /= 2
	}
}

// finishInventory dedupes, sorts, caps the rows and the value budget, and
// stamps the digest.
func finishInventory(rows []orgcontract.AgentConfigStateRow) orgcontract.AgentConfigInventoryReport {
	rep := orgcontract.AgentConfigInventoryReport{Rows: []orgcontract.AgentConfigStateRow{}}
	seen := map[string]bool{}
	for _, r := range rows {
		k := r.Setting + "\x00" + r.FileID + "\x00" + r.ProjectHash
		if seen[k] {
			continue
		}
		seen[k] = true
		rep.Rows = append(rep.Rows, r)
	}
	sort.Slice(rep.Rows, func(i, j int) bool {
		a, b := rep.Rows[i], rep.Rows[j]
		if a.ProjectHash != b.ProjectHash {
			return a.ProjectHash < b.ProjectHash
		}
		if a.Setting != b.Setting {
			return a.Setting < b.Setting
		}
		return a.FileID < b.FileID
	})
	if len(rep.Rows) > orgcontract.AgentConfigInventoryMaxRows {
		rep.Rows, rep.Truncated = rep.Rows[:orgcontract.AgentConfigInventoryMaxRows], true
	}
	budget := orgcontract.AgentConfigInventoryMaxBytes
	for i := range rep.Rows {
		n := len(rep.Rows[i].ObservedValue)
		if n > budget {
			rep.Rows[i].ObservedValue, rep.Rows[i].Reason = "", orgcontract.AgentConfigInventoryBudget
			continue
		}
		budget -= n
	}
	rep.Digest = orgcontract.DigestAgentConfigState(rep.Rows)
	return rep
}
