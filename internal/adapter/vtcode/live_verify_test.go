package vtcode

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestLiveVerify_RealStore is a manual audit tool, not part of the regular
// suite: it re-parses a REAL VT Code store (never a fixture) and logs what
// came out. Skipped unless VTCODE_LIVE_ROOTS lists (os.PathListSeparator-
// separated) a real global archive dir (`<state>/sessions`) and/or a
// workspace `.vtcode/sessions` dir. Never committed data, never required
// for `go test ./...`.
func TestLiveVerify_RealStore(t *testing.T) {
	env := os.Getenv("VTCODE_LIVE_ROOTS")
	if env == "" {
		t.Skip("set VTCODE_LIVE_ROOTS to a real archive dir and/or workspace .vtcode/sessions dir")
	}
	roots := filepath.SplitList(env)
	if env == "discover" {
		roots = discoverRoots()
		t.Logf("discovered roots: %v", roots)
	}
	a := NewWithOptions(nil, roots...)

	for _, root := range roots {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !a.IsSessionFile(path) {
				return nil
			}
			res, perr := a.ParseSessionFile(context.Background(), path, 0)
			if perr != nil {
				t.Errorf("ParseSessionFile(%s): %v", path, perr)
				return nil
			}
			actions := map[string]int{}
			sessions := map[string]bool{}
			for _, e := range res.ToolEvents {
				actions[e.ActionType]++
				sessions[e.SessionID] = true
			}
			models := map[string]int{}
			var in, cached, out int64
			var genRows int
			for _, tk := range res.TokenEvents {
				models[tk.Model]++
				in += tk.InputTokens
				cached += tk.CacheReadTokens
				out += tk.OutputTokens
				if tk.GenMs > 0 {
					genRows++
				}
			}
			var reasoning, attachments int
			for _, e := range res.ToolEvents {
				if e.PrecedingReasoning != "" {
					reasoning++
				}
				attachments += len(e.UserAttachments)
			}
			keys := make([]string, 0, len(actions))
			for k, v := range actions {
				keys = append(keys, k+"="+strconv.Itoa(v))
			}
			sort.Strings(keys)
			t.Logf("%s\n  sessions=%d tool_events=%d [%s]\n  token_rows=%d net_in=%d cache_read=%d out=%d models=%v warnings=%v\n  gen_ms_rows=%d cache_obs=%d reasoning_rows=%d attachments=%d versions=%v seeds=%v surfaces=%v",
				path, len(sessions), len(res.ToolEvents), strings.Join(keys, " "), len(res.TokenEvents), in, cached, out, models, res.Warnings,
				genRows, len(res.CacheObservations), reasoning, attachments, res.SessionToolVersions, res.SessionProcessSeeds, res.SessionSurfaces)
			second, serr := a.ParseSessionFile(context.Background(), path, res.NewOffset)
			if serr != nil {
				t.Errorf("re-parse(%s): %v", path, serr)
			} else if !isArchiveShape(path) && (len(second.ToolEvents) != 0 || len(second.TokenEvents) != 0) {
				t.Errorf("re-parse from offset %d yielded %d/%d new rows, want 0", res.NewOffset, len(second.ToolEvents), len(second.TokenEvents))
			}
			return nil
		})
	}
}
