package models

import "encoding/json"

// ArenaSessionIDPrefix identifies the synthetic per-candidate session ids
// used to attribute proxy turns for headless harnesses that do not expose a
// native conversation id (notably Aider). The proxy accepts a pid-bridge
// fallback carrying this prefix even on an explicit /up/<provider> lane; all
// ordinary coding-agent session ids remain barred from that Plane-A fallback.
const ArenaSessionIDPrefix = "sbo-arena:"

// arena.go — shared types for the Agent Arena (plan:
// docs/plans/agent-arena-terminal-multi-harness-2026-08-22.md). One
// ArenaRun is an operator-initiated multi-harness prompt run against a
// project; each ArenaCandidate is one harness's isolated attempt inside
// its own git worktree.

// ArenaRun lifecycle. pending → running → judging → complete; any stage
// may collapse to failed.
const (
	ArenaRunStatusPending  = "pending"
	ArenaRunStatusRunning  = "running"
	ArenaRunStatusJudging  = "judging"
	ArenaRunStatusComplete = "complete"
	ArenaRunStatusFailed   = "failed"
)

// ArenaCandidate lifecycle. pending → running → done|failed|timeout →
// judged → kept|discarded.
const (
	ArenaCandidateStatusPending   = "pending"
	ArenaCandidateStatusRunning   = "running"
	ArenaCandidateStatusDone      = "done"
	ArenaCandidateStatusFailed    = "failed"
	ArenaCandidateStatusTimeout   = "timeout"
	ArenaCandidateStatusJudged    = "judged"
	ArenaCandidateStatusKept      = "kept"
	ArenaCandidateStatusDiscarded = "discarded"
)

// ArenaRun is one judged comparison of N candidate harnesses against the
// same prompt and base commit.
type ArenaRun struct {
	ID          string
	ProjectRoot string
	BaseBranch  string
	BaseSHA     string
	Prompt      string
	JudgeTool   string
	JudgeModel  string
	Status      string
	CreatedAt   string // RFC3339 UTC, store-managed
	UpdatedAt   string
}

// ArenaCandidate is a single harness's attempt: its worktree/branch, the
// captured outcome metrics, judge scores, and the keep/discard decision.
type ArenaCandidate struct {
	ID                 string
	RunID              string
	Tool               string
	Model              string
	Seq                int
	Status             string
	BranchName         string
	WorktreePath       string
	PatchPath          string
	ExitCode           int
	WallMS             int64
	TimedOut           bool
	FinalAnswerExcerpt string
	DiffFiles          int
	DiffAdded          int
	DiffRemoved        int
	InputTokens        int64
	OutputTokens       int64
	CostUSD            float64
	SessionIDs         []string
	Scores             *JudgeScores
	Verdict            string
	KeptCommitSHA      string
	Error              string
	UpdatedAt          string
	// PermissionLane is the permission lane the candidate's drive ran in
	// ("bypass", "edit" or "read_only", OSH-R-005); empty when not
	// recorded (migration 210).
	PermissionLane string
}

// JudgeScores is the fixed global rubric every judge harness must return.
// All numeric scores are 0–10 with higher = better EXCEPT Risk, where
// higher = riskier. Overall is the judge's weighted verdict of its own;
// the UI never re-derives it from the components.
type JudgeScores struct {
	Correctness      int    `json:"correctness"`
	Completeness     int    `json:"completeness"`
	CodeQuality      int    `json:"code_quality"`
	Performance      int    `json:"performance"`
	Risk             int    `json:"risk"`
	Overall          int    `json:"overall"`
	VerdictRationale string `json:"verdict_rationale"`
}

// MarshalScores renders scores as the DB JSON column value (” when nil).
func MarshalScores(s *JudgeScores) (string, error) {
	if s == nil {
		return "", nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// UnmarshalScores parses a DB scores column (” → nil).
func UnmarshalScores(raw string) (*JudgeScores, error) {
	if raw == "" {
		return nil, nil
	}
	var s JudgeScores
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, err
	}
	return &s, nil
}
