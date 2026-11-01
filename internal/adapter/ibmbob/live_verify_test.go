package ibmbob

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/toolaccount"
)

// TestLiveVerify_RealStore is a manual audit tool, not part of the regular
// suite: it parses a REAL Bob home (point IBMBOB_LIVE_HOME at a COPY of a
// `.bob` directory holding db/bob.db and logs/shell) and logs counts only:
// sessions, actions by type, account observations (identities are counted,
// never printed) and the LOC rows the ladder produces for each edit/write.
func TestLiveVerify_RealStore(t *testing.T) {
	home := os.Getenv("IBMBOB_LIVE_HOME")
	if home == "" {
		t.Skip("set IBMBOB_LIVE_HOME to a copy of a .bob directory to run against a real store")
	}
	dbPath := filepath.Join(home, storeDirName, dbFile)
	a := NewWithOptions(nil, []string{filepath.Dir(dbPath)})
	res, err := a.ParseSessionFile(context.Background(), dbPath, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	for _, w := range res.Warnings {
		t.Logf("warning: %s", w)
	}
	sessions := map[string]bool{}
	byType := map[string]int{}
	for _, e := range res.ToolEvents {
		sessions[e.SessionID] = true
		byType[e.ActionType]++
	}
	t.Logf("sessions=%d actions=%d by type=%v", len(sessions), len(res.ToolEvents), sortedCounts(byType))

	keys, accountSessions := map[string]bool{}, map[string]int{}
	roles := map[string]int{}
	for _, o := range res.ToolAccounts {
		n, key, ok := toolaccount.Normalize(o)
		if !ok {
			t.Errorf("observation refused by Normalize (session %s)", o.SessionID)
			continue
		}
		keys[key] = true
		accountSessions[n.SessionID]++
		roles[n.Role+"/"+n.Stage+"/"+n.Scope]++
	}
	t.Logf("account observations=%d distinct accounts=%d sessions with an account=%d of %d roles=%v",
		len(res.ToolAccounts), len(keys), len(accountSessions), len(sessions), sortedCounts(roles))

	for _, e := range res.ToolEvents {
		if e.ActionType != models.ActionEditFile && e.ActionType != models.ActionWriteFile {
			continue
		}
		for _, f := range loc.Extract(loc.Input{RawToolInput: e.RawToolInput, ActionType: e.ActionType, Target: e.Target, BeforeLines: -1}) {
			t.Logf("loc session=%s tool=%s shape=%s lang=%s conf=%s stats=%+v",
				e.SessionID[:8], e.RawToolName, f.Shape, f.Lang, f.Confidence, f.Stats)
		}
	}
}

func sortedCounts(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+itoa(v))
	}
	sort.Strings(out)
	return out
}
