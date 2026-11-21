package integration

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
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
	// KeyApproval, when set, is where the tool records the user's answer to
	// its "use this API key?" question for a key in its environment, so a
	// hosted box's run sentinel can be approved up front (FX4 fix round 1,
	// F-P6B-2a). Nil: the tool asks nothing, or the place is not grounded.
	KeyApproval *SandboxKeyApproval
	// Grounding names the evidence the fields were read from.
	Grounding string
}

// SandboxKeyApproval is a tool's record of approved environment API keys:
// the state file's top-level Key holds an object whose "approved" and
// "rejected" arrays list each answered key by its last Suffix characters.
type SandboxKeyApproval struct {
	// Env is the key variable the question is about.
	Env string
	// Key is the state file's top-level key holding the answers.
	Key string
	// Suffix is how many trailing characters of a key the tool records.
	Suffix int
	// Grounding names the evidence.
	Grounding string
}

// ErrKeyApprovalNotObject is returned by ApproveKey for a state file, or an
// answers value, that is not a JSON object.
var ErrKeyApprovalNotObject = errors.New("integration: the tool's state file or its key answers are not a JSON object")

// ApproveKey returns state with value's last Suffix characters in the
// approved list (once) and out of the rejected list; every other key and
// value of state is kept as it is. An empty state is an empty object. The
// caller passes only a value that is not a secret (a hosted run's
// sentinel, never a real key): the suffix is written in the clear.
func (a SandboxKeyApproval) ApproveKey(state []byte, value string) ([]byte, error) {
	if a.Key == "" || a.Suffix <= 0 || value == "" {
		return nil, errors.New("integration: no key approval to write")
	}
	doc := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(state)) > 0 {
		if err := json.Unmarshal(state, &doc); err != nil || doc == nil {
			return nil, ErrKeyApprovalNotObject
		}
	}
	answers := map[string]json.RawMessage{}
	if raw, ok := doc[a.Key]; ok {
		if err := json.Unmarshal(raw, &answers); err != nil || answers == nil {
			return nil, ErrKeyApprovalNotObject
		}
	}
	suffix := value
	if len(suffix) > a.Suffix {
		suffix = suffix[len(suffix)-a.Suffix:]
	}
	list := func(name string) []string {
		var out []string
		_ = json.Unmarshal(answers[name], &out)
		return out
	}
	approved := list("approved")
	if !slices.Contains(approved, suffix) {
		approved = append(approved, suffix)
	}
	rejected := slices.DeleteFunc(list("rejected"), func(s string) bool { return s == suffix })
	if rejected == nil {
		rejected = []string{}
	}
	var err error
	if answers["approved"], err = json.Marshal(approved); err != nil {
		return nil, err
	}
	if answers["rejected"], err = json.Marshal(rejected); err != nil {
		return nil, err
	}
	if doc[a.Key], err = json.Marshal(answers); err != nil {
		return nil, err
	}
	return json.Marshal(doc)
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

// RemoteSeed is the first-run state for a box on another machine (a hosted
// box): Seed of this machine's state when it is a JSON object (nil or an
// unreadable state seeds nothing of it), with OnboardedKey set true
// whatever this machine's state says. The box's first-run screens are the
// box's, not this machine's: they call the provider directly, which the box
// cannot reach, so a tool that was installed here but never started
// interactively (no OnboardedKey) must not leave the box at them (FX4 item
// 4, live finding F-L3P4-8). Only non-secret keys are written, as Seed. A
// row with no OnboardedKey seeds nothing (nil, false).
func (c SandboxConfigHome) RemoteSeed(state []byte) ([]byte, bool) {
	if c.OnboardedKey == "" {
		return nil, false
	}
	out := map[string]json.RawMessage{}
	if b, err := c.Seed(state); err == nil {
		_ = json.Unmarshal(b, &out)
	}
	out[c.OnboardedKey] = json.RawMessage("true")
	b, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	return b, true
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

// Approved reports whether state already approves value (its last Suffix
// characters are in the approved list and not in the rejected list).
func (a SandboxKeyApproval) Approved(state []byte, value string) bool {
	if a.Key == "" || a.Suffix <= 0 || value == "" {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(state, &doc) != nil {
		return false
	}
	var answers struct {
		Approved []string `json:"approved"`
		Rejected []string `json:"rejected"`
	}
	if json.Unmarshal(doc[a.Key], &answers) != nil {
		return false
	}
	suffix := value
	if len(suffix) > a.Suffix {
		suffix = suffix[len(suffix)-a.Suffix:]
	}
	return slices.Contains(answers.Approved, suffix) && !slices.Contains(answers.Rejected, suffix)
}
