package retention

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestRunAccountEvidenceAge(t *testing.T) {
	path, st := seed(t)
	database := openExisting(t, path)
	for _, tc := range []struct {
		id  string
		age time.Duration
	}{{"old", -200 * 24 * time.Hour}, {"recent", -2 * time.Hour}} {
		err := st.RecordToolAccounts(context.Background(), []models.ToolAccountObservation{{SessionID: tc.id, Tool: models.ToolCursor, BindingKind: "message", BindingID: "m", Role: "assistant", Email: "fixture@example.invalid", Source: "fixture", Scope: "test", Stage: "activity", ObservedAt: fakeNow.Add(tc.age)}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := New(database).Run(context.Background(), Options{MaxAgeDays: 100, DBPath: path}); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.QueryRow(`SELECT count(*) FROM tool_account_observations WHERE session_id='old'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("old orphan retained: %d %v", count, err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM tool_account_observations WHERE session_id='recent'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("pending hook lost: %d %v", count, err)
	}
}
