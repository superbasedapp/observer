package oteldirect

import "github.com/marmutapp/superbased-observer/internal/orgcontract"

// posture.go is the content posture of an OTel-direct batch. Full content
// (a managed member: CLAUDE.md "enterprise / org-managed nodes ship full
// content") keeps every column. Metadata only (provisional default 3: a
// member of an individual-tenancy org) keeps what a metadata-only node
// ships: every raw content column is hashed into its *_hash counterpart and
// cleared, and a raw column with no hash counterpart is cleared. The columns
// are exactly internal/shiptoken's raw-content table (posture.go
// contentRules) for the admitted families; TestPostureClearsEveryRawColumn
// fails if that table grows a column this one misses.

// contentField is one raw content column of a row type T: where its raw
// value lives and, when it has one, its hash counterpart.
type contentField[T any] struct {
	raw  func(*T) *string
	hash func(*T) *string // nil: no counterpart, the raw value is just cleared
}

var sessionContent = []contentField[orgcontract.SessionRow]{
	{func(r *orgcontract.SessionRow) *string { return &r.ProjectRoot }, func(r *orgcontract.SessionRow) *string { return &r.ProjectRootHash }},
	{func(r *orgcontract.SessionRow) *string { return &r.GitRemote }, func(r *orgcontract.SessionRow) *string { return &r.GitRemoteHash }},
	{func(r *orgcontract.SessionRow) *string { return &r.GitUpstreamRemote }, func(r *orgcontract.SessionRow) *string { return &r.GitUpstreamRemoteHash }},
	{func(r *orgcontract.SessionRow) *string { return &r.Workspace }, func(r *orgcontract.SessionRow) *string { return &r.WorkspaceHash }},
	{func(r *orgcontract.SessionRow) *string { return &r.GitBranch }, nil},
}

var actionContent = []contentField[orgcontract.ActionRow]{
	{func(r *orgcontract.ActionRow) *string { return &r.Target }, func(r *orgcontract.ActionRow) *string { return &r.TargetHash }},
	{func(r *orgcontract.ActionRow) *string { return &r.SourceFile }, func(r *orgcontract.ActionRow) *string { return &r.SourceFileHash }},
	{func(r *orgcontract.ActionRow) *string { return &r.RawToolInput }, nil},
	{func(r *orgcontract.ActionRow) *string { return &r.RawToolOutput }, nil},
	{func(r *orgcontract.ActionRow) *string { return &r.PrecedingReasoning }, nil},
	{func(r *orgcontract.ActionRow) *string { return &r.ErrorMessage }, nil},
}

var apiTurnContent = []contentField[orgcontract.APITurnRow]{
	{func(r *orgcontract.APITurnRow) *string { return &r.ProjectRoot }, func(r *orgcontract.APITurnRow) *string { return &r.ProjectRootHash }},
}

var otelContentContent = []contentField[orgcontract.OTelContentRow]{
	{func(r *orgcontract.OTelContentRow) *string { return &r.Content }, func(r *orgcontract.OTelContentRow) *string { return &r.ContentHash }},
}

// strip applies the metadata-only rule to one row: a raw value fills an
// EMPTY hash counterpart (an existing hash is kept, as the ingest's
// hashOrComputed keeps a shipped hash), then the raw value is cleared.
func strip[T any](row *T, fields []contentField[T]) {
	for _, f := range fields {
		raw := f.raw(row)
		if *raw == "" {
			continue
		}
		if f.hash != nil {
			if h := f.hash(row); *h == "" {
				*h = hashRaw(*raw)
			}
		}
		*raw = ""
	}
}

// ApplyPosture applies the member's content posture to env in place:
// fullContent keeps everything; otherwise every raw content column is
// hashed into its counterpart (the org ingest's hashOrComputed hash) and
// cleared.
func ApplyPosture(env *orgcontract.PushEnvelope, fullContent bool) {
	if env == nil || fullContent {
		return
	}
	for i := range env.Sessions {
		strip(&env.Sessions[i], sessionContent)
	}
	for i := range env.Actions {
		strip(&env.Actions[i], actionContent)
	}
	for i := range env.APITurns {
		strip(&env.APITurns[i], apiTurnContent)
	}
	for i := range env.OTelContent {
		strip(&env.OTelContent[i], otelContentContent)
	}
}
