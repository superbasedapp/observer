package integration

import (
	"bytes"
	"encoding/json"
	"errors"
)

// SandboxConfigHome declares where a tool keeps its own config and first-run
// state, and how a sandboxed run gets a writable copy of it when the user's
// config folder does not exist (Windows 11 Pro rerun 2026-10-25, D3: in the
// Windows box the home is read-only, so a tool with no config folder could
// not create one, and Claude Code's first-run screens call provider hosts the
// box blocks). A sandbox driver reads it from the tool's row; it never
// branches on the tool's name.
type SandboxConfigHome struct {
	// Env is the variable that moves the tool's config folder
	// (CLAUDE_CONFIG_DIR).
	Env string
	// Dir is the HOME-relative config folder the tool uses when Env is
	// unset. When it exists it is granted read-write through StateRW and no
	// run-local folder is made.
	Dir string
	// StateFile is the HOME-relative first-run state file the tool reads
	// when Env is unset.
	StateFile string
	// RelocatedStateFile is the state file's name inside the folder Env
	// names.
	RelocatedStateFile string
	// OnboardedKey is the state file's top-level key that is JSON true once
	// the tool's first-run screens are done.
	OnboardedKey string
	// SeedKeys are the only top-level state keys copied into a run-local
	// folder: non-secret first-run state, never an account, a token or a
	// key. Only scalar values are copied.
	SeedKeys []string
	// Grounding names the evidence the fields were read from.
	Grounding string
}

// ErrSeedNotObject is returned by Seed for a state file that is not a JSON
// object.
var ErrSeedNotObject = errors.New("integration: the tool's state file is not a JSON object")

// Onboarded reports whether a state file's content marks the tool's first
// run as done (OnboardedKey is JSON true).
func (c SandboxConfigHome) Onboarded(state []byte) bool {
	if c.OnboardedKey == "" {
		return false
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(state, &doc); err != nil {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(doc[c.OnboardedKey]), []byte("true"))
}

// Seed is the run-local state file's content: a JSON object holding only
// the SeedKeys present in state with a scalar value (a string, a number, a
// boolean). Every other key, and any object, array or null value, is left
// out, so an account, a token or a key in the user's state file never
// reaches the run's copy.
func (c SandboxConfigHome) Seed(state []byte) ([]byte, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(state, &doc); err != nil || doc == nil {
		return nil, ErrSeedNotObject
	}
	out := map[string]json.RawMessage{}
	for _, k := range c.SeedKeys {
		v, ok := doc[k]
		if !ok || !ScalarJSON(v) {
			continue
		}
		out[k] = v
	}
	return json.Marshal(out)
}

// ScalarJSON reports whether v is one JSON string, number or boolean.
func ScalarJSON(v json.RawMessage) bool {
	var x any
	if err := json.Unmarshal(v, &x); err != nil {
		return false
	}
	switch x.(type) {
	case string, float64, bool:
		return true
	}
	return false
}
