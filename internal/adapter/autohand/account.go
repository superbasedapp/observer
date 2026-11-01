package autohand

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/models"
)

const (
	// accountSnapshotRel is the vendor's account-skills sync snapshot, a
	// sibling of the sessions directory.
	accountSnapshotRel = ".account-skills/snapshot.json"
	maxSnapshotBytes   = 64 << 10

	// accountSource / accountScope label the observation: the id names the
	// signed-in Autohand DEVICE account, not the person who typed a prompt.
	accountSource = "autohand_account_snapshot"
	accountScope  = models.ToolAccountScopeAccount + ":device"
)

// readAccountID returns the Autohand account id recorded in the data home's
// account snapshot ("" when absent). Only the `accountId` member is decoded:
// the file also holds a token HASH and a config path, which are never read
// into a value this package keeps. The user's e-mail lives only in
// config.json (credential file) and is never a source.
func readAccountID(dataHome string) string {
	path := filepath.Join(dataHome, filepath.FromSlash(accountSnapshotRel))
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxSnapshotBytes {
		return ""
	}
	f, err := os.Open(path) //nolint:gosec // vendor sync snapshot under the data home
	if err != nil {
		return ""
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, maxSnapshotBytes))
	if err != nil {
		return ""
	}
	var s struct {
		AccountID string `json:"accountId"`
	}
	if json.Unmarshal(body, &s) != nil {
		return ""
	}
	id := strings.TrimSpace(s.AccountID)
	if id == "" || len(id) > 128 || strings.ContainsFunc(id, unicode.IsControl) {
		return ""
	}
	return id
}

// accountObservations binds the device account to every event this window
// produced (the join key is the action's SourceEventID, the key the message
// views group on). Account-level: AccountID only, no person fields.
func accountObservations(accountID, sessID string, events []models.ToolEvent) []models.ToolAccountObservation {
	if accountID == "" || sessID == "" {
		return nil
	}
	out := make([]models.ToolAccountObservation, 0, len(events))
	for _, ev := range events {
		if ev.SourceEventID == "" {
			continue
		}
		role := "assistant"
		if ev.ActionType == models.ActionUserPrompt {
			role = "user"
		}
		out = append(out, models.ToolAccountObservation{
			SessionID:   sessID,
			Tool:        models.ToolAutohand,
			BindingKind: "message",
			BindingID:   ev.SourceEventID,
			Role:        role,
			AccountID:   accountID,
			Source:      accountSource,
			Scope:       accountScope,
			Stage:       "activity",
			ObservedAt:  ev.Timestamp,
		})
	}
	return out
}
