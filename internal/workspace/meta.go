package workspace

import (
	"encoding/json"
	"time"
)

// Meta is the shape of the per-workspace meta.json record (plan §4: "no
// DB change — B7 reads the same files"). The caller writes MarshalMeta's
// output to <ManagedRoot>/<ID>/meta.json once Plan's Steps have
// succeeded; this package owns only the shape and the pure marshal, not
// the file write.
type Meta struct {
	Source    Source    `json:"source"`
	Origin    string    `json:"origin"` // ProjectRoot (live/clone-local/worktree) or RemoteURL (clone-remote)
	Branch    string    `json:"branch,omitempty"`
	RunID     string    `json:"run_id"`
	CreatedAt time.Time `json:"created_at"`
	// Kept, for a worktree run the end of the run kept, says why (shown by
	// `observer workspaces ls`); empty otherwise.
	Kept string `json:"kept,omitempty"`
}

// MarshalMeta renders m as indented JSON. It is pure — the caller
// performs the actual file write (and any retention sweep / `observer
// workspaces ls|rm` reads it back the same way).
func MarshalMeta(m Meta) ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}
