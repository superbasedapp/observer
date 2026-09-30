package sessionend

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Role is what an action type does to a session's end time.
type Role int

const (
	// RoleNone leaves the end time alone (every tool call, token row,
	// error row, and turn-evidence row a host writes after its end hook).
	RoleNone Role = iota
	// RoleClose ends the session at the action's timestamp.
	RoleClose
	// RoleReopen makes a session live again when it is later than the
	// latest close.
	RoleReopen
)

// roles is the lifecycle table. Adding a lifecycle action is adding a row.
var roles = map[string]Role{
	models.ActionSessionEnd:   RoleClose,
	models.ActionSessionStart: RoleReopen,
	models.ActionUserPrompt:   RoleReopen,
}

// RoleOf returns the lifecycle role of an action type.
func RoleOf(actionType string) Role {
	return roles[actionType]
}

// ActionTypes returns the action types carrying role r, in a stable order,
// for a loader's `action_type IN (...)` filter.
func ActionTypes(r Role) []string {
	var out []string
	for _, t := range []string{models.ActionSessionEnd, models.ActionSessionStart, models.ActionUserPrompt} {
		if roles[t] == r {
			out = append(out, t)
		}
	}
	return out
}

// Facts are a session's latest close and latest reopen timestamps as
// stored (RFC3339, "" when the session has none).
type Facts struct {
	LastClose  string
	LastReopen string
}

// rule is one row of the ordered decision table: the first match wins.
type rule struct {
	match func(close, reopen time.Time, hasClose, hasReopen bool) bool
	// endedAt returns the end time to store; ok=false means "leave the
	// stored value alone".
	endedAt func(f Facts) (value string, ok bool)
}

var rules = []rule{
	// No close recorded: nothing to decide (never clear a value some other
	// writer set).
	{
		match:   func(_, _ time.Time, hasClose, _ bool) bool { return !hasClose },
		endedAt: func(Facts) (string, bool) { return "", false },
	},
	// A human turn or a session start after the latest close: live again.
	{
		match:   func(c, r time.Time, _, hasReopen bool) bool { return hasReopen && r.After(c) },
		endedAt: func(Facts) (string, bool) { return "", true },
	},
	// Otherwise the latest close is the end.
	{
		match:   func(_, _ time.Time, _, _ bool) bool { return true },
		endedAt: func(f Facts) (string, bool) { return f.LastClose, true },
	},
}

// EndedAt decides the session's end time from its facts. ok=false means
// leave the stored ended_at unchanged; ok=true with value "" means the
// session is live (clear it). An unparseable close is treated as absent.
func EndedAt(f Facts) (value string, ok bool) {
	c, errC := time.Parse(time.RFC3339Nano, f.LastClose)
	r, errR := time.Parse(time.RFC3339Nano, f.LastReopen)
	hasClose, hasReopen := f.LastClose != "" && errC == nil, f.LastReopen != "" && errR == nil
	for _, row := range rules {
		if row.match(c, r, hasClose, hasReopen) {
			return row.endedAt(f)
		}
	}
	return "", false
}
