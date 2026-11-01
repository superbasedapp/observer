package dimcode

import (
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// DimCode persists its own runtime bookkeeping as role=user messages whose
// `metadata._dimTranscript` object says what the row really is: a recovery
// notice after a provider retry was exhausted, the terminal status of a
// failed or aborted run, a background-task / sub-agent completion
// notification, a steer bundle, hidden tool context, ... None of those were
// typed by the person. The vendor's own isRootUserMessage rule is "no
// _dimTranscript, or kind user_input", so this adapter follows the same
// line: only those rows (plus the user-owned steer kinds) become
// user_prompt; every other kind is routed through harnessRules to the action
// type it actually is, or dropped.

// transcriptMeta is the subset of `metadata._dimTranscript` this adapter
// reads. All fields are optional; an unknown kind is tolerated.
type transcriptMeta struct {
	Visibility     string `json:"visibility"`
	Kind           string `json:"kind"`
	Source         string `json:"source"`
	Owner          string `json:"owner"`
	Status         string `json:"status"`
	Reason         string `json:"reason"`
	RecoveryReason string `json:"recoveryReason"`
	ErrorClass     string `json:"errorClass"`
	Attempt        int    `json:"attempt"`
	Error          struct {
		Name       string `json:"name"`
		Message    string `json:"message"`
		Code       string `json:"code"`
		ErrorClass string `json:"errorClass"`
	} `json:"error"`
	Notice struct {
		Params struct {
			Status    string `json:"status"`
			ToolName  string `json:"toolName"`
			AgentName string `json:"agentName"`
		} `json:"params"`
	} `json:"notice"`
}

// harnessMeta decodes the _dimTranscript object off a message's metadata
// column, nil when the row carries none (an ordinary message).
func harnessMeta(metadata string) *transcriptMeta {
	if strings.TrimSpace(metadata) == "" {
		return nil
	}
	var wrap struct {
		T *transcriptMeta `json:"_dimTranscript"`
	}
	if err := json.Unmarshal([]byte(metadata), &wrap); err != nil {
		return nil
	}
	return wrap.T
}

// Vendor vocabulary the rules match on.
const (
	kindUserInput        = "user_input"
	kindUserSteer        = "user_steer"
	kindUserInterrupt    = "user_interrupt"
	kindRunTerminal      = "run_terminal"
	kindProviderRetry    = "provider_retry"
	kindRuntimeContinue  = "runtime_continuation"
	kindToolContext      = "tool_context"
	codeRunAborted       = "SESSION_RUN_ABORTED"
	reasonProviderError  = "provider_error"
	reasonUserInterrupt  = "user_interrupt"
	statusCancelled      = "cancelled"
	ownerUser            = "user"
	rawNameHarnessPrefix = "dimcode."
)

// harnessDisposition is what a non-prompt harness row becomes.
type harnessDisposition struct {
	// Action is the normalized action type; "" drops the row (hidden
	// bookkeeping that carries nothing an analyst can use).
	Action string
	// Failed marks a row that records something going wrong (Success=false,
	// ErrorMessage carried).
	Failed bool
	// Interrupt stamps ActionMetadata.IsInterrupt.
	Interrupt bool
}

// harnessRule is one row of the ordered classification table.
type harnessRule struct {
	name  string
	match func(*transcriptMeta) bool
	disp  harnessDisposition
}

// harnessRules is walked top-down; the first matching row wins (CLAUDE.md
// #5: decision logic is a table, one test case per row — see
// TestHarnessRules). The last row is the catch-all, so an unknown future
// kind can never become a user prompt.
var harnessRules = []harnessRule{
	{
		"hidden tool context", func(t *transcriptMeta) bool { return t.Kind == kindToolContext },
		harnessDisposition{},
	},
	{
		"user interrupt", func(t *transcriptMeta) bool { return t.Kind == kindUserInterrupt },
		harnessDisposition{Action: models.ActionTurnAborted, Failed: true, Interrupt: true},
	},
	{"run ended by an abort / cancel", func(t *transcriptMeta) bool {
		return t.Kind == kindRunTerminal &&
			(t.Error.Code == codeRunAborted || t.Status == statusCancelled || t.Reason == reasonUserInterrupt)
	}, harnessDisposition{Action: models.ActionTurnAborted, Failed: true}},
	{"run ended by a provider error", func(t *transcriptMeta) bool {
		return t.Kind == kindRunTerminal && t.Reason == reasonProviderError
	}, harnessDisposition{Action: models.ActionAPIError, Failed: true}},
	{
		"run ended otherwise (tool / hook / storage error, turn cap)", func(t *transcriptMeta) bool { return t.Kind == kindRunTerminal },
		harnessDisposition{Action: models.ActionTurnAborted, Failed: true},
	},
	{
		"provider retry notice", func(t *transcriptMeta) bool { return t.Kind == kindProviderRetry },
		harnessDisposition{Action: models.ActionAPIError, Failed: true},
	},
	{"recovery after an exhausted provider retry", func(t *transcriptMeta) bool {
		return t.Kind == kindRuntimeContinue && strings.Contains(t.RecoveryReason, "provider")
	}, harnessDisposition{Action: models.ActionAPIError, Failed: true}},
	{
		"every other runtime-injected message", func(*transcriptMeta) bool { return true },
		harnessDisposition{Action: models.ActionPromptContext},
	},
}

// userAuthored reports whether a role=user row was typed by the person: no
// _dimTranscript marker, the plain user_input kind, or a user-owned steer.
func userAuthored(t *transcriptMeta) bool {
	if t == nil {
		return true
	}
	switch t.Kind {
	case kindUserInput, kindUserSteer:
		return true
	case kindUserInterrupt:
		return false
	}
	return t.Owner == ownerUser
}

// classifyHarness walks harnessRules for a non-user-authored row.
func classifyHarness(t *transcriptMeta) harnessDisposition {
	for _, r := range harnessRules {
		if r.match(t) {
			return r.disp
		}
	}
	return harnessDisposition{Action: models.ActionPromptContext}
}

// harnessTarget renders the short, content-free label of a harness row.
func harnessTarget(t *transcriptMeta, d harnessDisposition) string {
	switch d.Action {
	case models.ActionAPIError, models.ActionTurnAborted:
		if t.Error.Code != "" {
			return t.Error.Code
		}
		return firstNonEmpty(t.RecoveryReason, t.Reason, t.Status, t.Kind)
	}
	label := t.Kind
	if t.Notice.Params.Status != "" {
		label += " — " + t.Notice.Params.Status
	}
	if t.Notice.Params.ToolName != "" {
		label += " (" + t.Notice.Params.ToolName + ")"
	}
	return label
}

// harnessError renders the human-readable cause: the first line of the
// vendor's error message (its multi-line body carries provider response
// text and request ids, which are not kept) plus the error code.
func harnessError(t *transcriptMeta) string {
	msg := strings.TrimSpace(strings.SplitN(t.Error.Message, "\n", 2)[0])
	if msg == "" {
		msg = firstNonEmpty(t.RecoveryReason, t.Reason, t.Kind)
	}
	if t.Error.Code != "" && !strings.Contains(msg, t.Error.Code) {
		msg += " (" + t.Error.Code + ")"
	}
	return msg
}

// harnessEvent builds the event for a role=user message that is not a
// person's prompt. ok is false for a dropped row.
func (a *Adapter) harnessEvent(c *sessionCtx, m messageRow, t *transcriptMeta) (models.ToolEvent, bool) {
	d := classifyHarness(t)
	if d.Action == "" {
		return models.ToolEvent{}, false
	}
	ev := models.ToolEvent{
		SourceFile:    c.sourceFile,
		SourceEventID: "harness:" + m.ID,
		SessionID:     c.sessionID,
		ProjectRoot:   c.projectRoot,
		GitRemote:     c.gitRemote,
		Timestamp:     parseTime(m.CreatedAt),
		Model:         c.modelFor(runIDOf(m)),
		Tool:          models.ToolDimCode,
		ActionType:    d.Action,
		Target:        truncate(a.scrub(harnessTarget(t, d)), 200),
		Success:       !d.Failed,
		RawToolName:   rawNameHarnessPrefix + t.Kind,
		MessageID:     m.ID,
		Metadata:      c.metadata(),
	}
	if d.Failed {
		ev.ErrorMessage = truncate(a.scrub(harnessError(t)), 500)
	}
	if d.Interrupt {
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		ev.Metadata.IsInterrupt = true
	}
	return ev, true
}
