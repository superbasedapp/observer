package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/spendverdict"
)

// cloudlocal_facts.go holds the evidence-fact loaders the `observer cloud` CLI
// maps into cloudevidence inputs: read-only, node-local, part of the
// cloud-intelligence store seam (cloudlocal.go describes the whole seam).

// CloudActionFact is one raw, node-local action fact the CLI maps into a
// cloudevidence.ActionInput. Target is the real local target (a path for file
// actions, the COMMAND STRING for run_command); the pure layer turns it into a
// closed-vocabulary label and never lets it leave the machine.
type CloudActionFact struct {
	// Ref is the action's ORIGINAL 0-based position in the whole session, so a
	// sampled envelope's ref gaps honestly show that sampling happened.
	Ref         string
	Kind        string
	Success     bool
	Target      string
	RawToolName string
	Timestamp   time.Time
}

// CloudKindCount is one whole-session action-kind count.
type CloudKindCount struct {
	Kind  string
	Count int
}

// CloudSessionMetrics is the deterministic numeric substrate of a session:
// summed token usage plus the session row's own recorded scores. All of it is
// already-aggregated counts — no content.
type CloudSessionMetrics struct {
	// TokensIn / TokensOut / CacheReadTokens / CacheCreationTokens /
	// ReasoningTokens sum the session's counted rows - api_turns and
	// token_usage deduplicated by the one session rule (loadCloudTokenMetrics),
	// the session header's figures. Input is NET (the cached portion lives in
	// CacheReadTokens); a twinned proxy row's output is its transcript twin's
	// visible output, its reasoning the twin's.
	TokensIn            int
	TokensOut           int
	CacheReadTokens     int
	CacheCreationTokens int
	ReasoningTokens     int
	// CostUSD sums the counted rows' own recorded cost. It is 0 for the many
	// adapters that record no per-turn cost; the caller decides whether to
	// fall back to a priced estimate.
	CostUSD float64
	// RecordedRows is how many counted rows the sums covered (0 => the
	// session carried no billable usage at all).
	RecordedRows int
	// QualityScore / RedundancyRatio / ErrorRate come from the sessions row and
	// are 0 when it never recorded them (the common case).
	QualityScore    float64
	RedundancyRatio float64
	ErrorRate       float64
	// Turns is the PER-ROW token substrate, in time order: one entry per
	// counted row with that row's OWN model, timestamp and token bundle.
	//
	// It exists because a session's cost cannot be computed from the sums above.
	// Pricing is per model AND date-effective, and several models price input in
	// LONG-CONTEXT BANDS — so pricing a whole session's summed tokens as if they
	// were one turn invents surcharges the session never incurred and collapses
	// two models (or two sides of a price change) onto one rate. The caller
	// prices each turn and sums the money; the engine's own contract says
	// "aggregate AFTER pricing, not before".
	//
	// It carries every counted row, proxy and transcript alike.
	Turns []CloudTokenTurn
	// ProxyTurns is always empty: Turns carries the proxy rows the one
	// session rule counts. It is kept so a caller of the older
	// token_usage-else-api_turns split still compiles (it priced ProxyTurns
	// only when Turns was empty).
	ProxyTurns []CloudTokenTurn
}

// CloudTokenTurn is one billable turn: the model it ran on, when it ran, and
// its token bundle. It carries no content.
type CloudTokenTurn struct {
	// Model is the row's own recorded model (may be empty on rows that never
	// captured one — the caller decides what to do with an unpriceable turn).
	Model string
	// Timestamp is the row's own time, so it is priced at the rate in force
	// then.
	Timestamp time.Time
	// Input is NET input tokens (adapters emit net; cached lives in CacheRead).
	Input int
	// Output is output tokens.
	Output int
	// CacheRead / CacheCreation / Reasoning complete the bundle.
	CacheRead     int
	CacheCreation int
	Reasoning     int
	// CacheCreation1h is the subset of CacheCreation that landed in the 1h tier,
	// which prices differently. WebSearchRequests is the count of server-side
	// web_search invocations, billed as a FLAT per-request fee on top of tokens.
	// Fast marks a turn served in the provider's low-latency tier, which bills
	// every per-token dimension at a multiple of the standard rate.
	//
	// All three exist here because the bundle handed to the cost engine has to be
	// COMPLETE (A6). Dropping them did not merely lose precision: a fast-mode
	// Opus turn priced at half its real cost, and a session that ran a web search
	// lost the fee entirely. A bundle that is missing a priced dimension is not
	// an approximation of the cost — it is a different number.
	CacheCreation1h   int
	WebSearchRequests int
	Fast              bool
	// RecordedCostUSD is the row's own estimated_cost_usd (0 on the many
	// adapters that record none). It is a PER-ROW fact: whether a row is priced
	// from its recording or from the engine is decided per row, because a session
	// routinely mixes rows of both kinds.
	RecordedCostUSD float64
}

// CloudSessionFacts is the raw session substrate the CLI maps into a
// cloudevidence.SessionInput. It carries local values (tool/model/paths); the
// pure builder turns them into the privacy-preserving envelope. Authority is
// read separately via SessionAuthority so the eligibility gate stays the pure
// contract's single source of truth.
type CloudSessionFacts struct {
	Tool      string
	Model     string
	ProjectID int64
	StartedAt time.Time
	EndedAt   time.Time
	// TotalActions is the sessions row's own counter, which many adapters never
	// populate. ActionCount below is the COUNTED truth.
	TotalActions int
	// ActionCount / FailedActions are counted over the actions table, so an
	// error rate is honest even when the sessions row is empty.
	ActionCount   int
	FailedActions int
	// FirstActionAt / LastActionAt bound the observed activity. They are the
	// duration fallback when the sessions row has no ended_at (very common:
	// a session is only stamped ended when the adapter saw an end event).
	FirstActionAt time.Time
	LastActionAt  time.Time
	// ActivityMix is the WHOLE-SESSION kind histogram, independent of how many
	// action rows Actions carries.
	ActivityMix []CloudKindCount
	// Metrics is the deterministic numeric substrate.
	Metrics CloudSessionMetrics
	// Actions is a STRIDED SAMPLE across the session's WHOLE ordered action
	// population — at most maxActions rows, always including the first and the
	// last. Each row's Ref is its ORIGINAL index, so a gap in the refs shows the
	// sampling honestly. ActionCount above is the population it was drawn from,
	// which is what makes the envelope's omission count true.
	Actions []CloudActionFact
	// OutcomeActions is the KIND-BOUNDED population the milestone and outcome
	// derivations run over: every run_command / edit_file / write_file /
	// tool_failure / task_complete / session_end row in the session, plus the
	// earliest failed row of any kind, all of it in time order.
	//
	// It is deliberately NOT the sample above. Milestones and outcomes are
	// existence-and-count facts ("did a test suite run, did the last build
	// pass, when was the first edit"), and computing them from a 256-row sample
	// of a 30,000-action session answers a different question — it reports what
	// the SAMPLE happened to contain. Bounding by KIND rather than by row count
	// keeps the read cheap while keeping the answer exact.
	OutcomeActions []CloudActionFact
}

// cloudOutcomeKinds is the closed kind list OutcomeActions covers: exactly the
// kinds the pure layer's milestone and outcome rules can fire on.
var cloudOutcomeKinds = []string{
	"run_command", "edit_file", "write_file", "tool_failure", "task_complete", "session_end",
}

// cloudOutcomeTargetBytes bounds how much of one command row's target is read.
//
// It MATCHES the pure classifier's own scan bound (cloudevidence's
// maxCommandScanBytes), and that is the whole point (A5). At 512 bytes the
// window was SHORTER than the classifier's, so a command whose program sat past
// byte 512 — `KEY=<600-byte value> go test ./...`, a real shape when a secret or
// a long PATH is exported inline — arrived here already decapitated and
// classified as nothing at all. A window narrower than the classifier's silently
// changes classifications; a matching one cannot.
const cloudOutcomeTargetBytes = 4096

// Bounds on the outcome population. It is high enough that no real session
// reaches it (a session with 50k shell commands is pathological, not a workflow)
// and exists only so a corrupt or synthetic row explosion cannot make one CLI
// command allocate without limit.
//
// WHY HEAD **AND** TAIL (the N3 fix). The bound used to keep the EARLIEST rows
// only, on the reasoning that milestones are first-occurrence facts. But the two
// derivations disagree about which end matters: DeriveMilestones wants the head
// (first_edit, first_test), while DeriveOutcomes reports the LAST build's result
// and `session_end` / `first_task_complete` are by construction at the very end.
// A head-only truncation therefore did not merely under-report — it could assert
// the WRONG build outcome (an early failed build standing in for a later passing
// one) and silently drop the session's terminal milestones. Splitting the same
// budget into an early window plus a late window answers both derivations, and
// the rows that fall out are the MIDDLE ones, which neither derivation reads
// except as counts. When the split IS hit, test counts under-report (honest) and
// the build outcome is the true last one.
const (
	cloudMaxOutcomeRows  = 50000
	cloudOutcomeTailRows = 10000
	cloudOutcomeHeadRows = cloudMaxOutcomeRows - cloudOutcomeTailRows
)

// cloudReader is the read surface every cloud-evidence loader needs. Both
// *sql.DB and *sql.Conn satisfy it, so each loader runs either standalone or —
// as LoadCloudEvidenceFacts does — inside ONE pinned-connection read snapshot.
type cloudReader interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// LoadCloudEvidenceFacts loads a session row, its whole-session aggregates, a
// STRIDED action sample across the whole session, the kind-bounded outcome
// population, and the per-turn token substrate — everything a cloud evidence
// envelope is built from. maxActions caps the sample (defaulting to
// cloudDefaultActionSample); the pure builder bounds again and summarizes
// overflow as a count against the true population. ok=false means the session
// does not exist. NODE-LOCAL.
// WHY ONE READ SNAPSHOT (the N4 fix). The five reads used to run independently
// against the pool, so a session being written WHILE the envelope was built saw
// an inconsistent world: the aggregate query counted N actions and the sample
// query then selected against a table that already held N+1, dropping the last
// action from the sample and making ActionsOmitted disagree with the mix. Two
// rebuilds of the "same" session then differed, which the two-digest protocol
// reads as tampering — the user is told the evidence changed and asked to
// reconfirm, for no reason but a concurrent insert.
//
// The snapshot is a pinned connection running BEGIN DEFERRED, deliberately NOT
// s.db.BeginTx: the agent DSN carries _txlock=immediate, so BeginTx would take
// the database's WRITE lock for the duration of a purely read-only build and
// contend with the daemon's own ingest. A deferred transaction on one pinned
// connection gives the same repeatable-read snapshot (WAL readers do not block
// writers) at no cost to the writer.
func (s *Store) LoadCloudEvidenceFacts(ctx context.Context, sessionID string, maxActions int) (CloudSessionFacts, bool, error) {
	b, ok, err := s.LoadCloudEvidenceBundle(ctx, sessionID, CloudEvidenceRequest{MaxActions: maxActions})
	return b.Facts, ok, err
}

// CloudEvidenceRequest says what one envelope build needs read, so it can ALL be
// read inside a single snapshot.
//
// WHY THE SINKS (A5 / A8). Two of the facts an envelope asserts are
// WHOLE-SESSION claims over populations that can be enormous: "the session ran N
// tests and its last build passed", and "these were its failure classes". Both
// used to be computed over a bounded window of rows and then presented as facts
// about the session — so a build at row 45,000 of 60,000 could be invisible, and
// the dominant failure class could sit in the omitted middle. A sink lets the
// store scan the WHOLE population row by row and hand each row to a pure
// classifier, so the claim covers everything while memory stays constant: no
// slice of the population is ever built.
type CloudEvidenceRequest struct {
	// EvidenceSettings applies explicit content read limits; nil keeps legacy selection.
	EvidenceSettings *CloudEvidenceSettings
	// MaxActions caps the strided action sample (0 ⇒ cloudDefaultActionSample).
	MaxActions int
	// IncludeTexts reads the excerpt substrate. It is set ONLY on the
	// bounded-context-enrichment path; a structural build leaves it false and
	// the text SQL never runs.
	IncludeTexts bool
	// IncludeFirstPrompt reads ONLY the user-prompt rows (Texts.UserPrompts),
	// never the final assistant message or the failure population. It is the
	// "Title only" level's read: a structural build whose receipt binds the
	// first_user_prompt_excerpt class needs the first real prompt and nothing
	// else, so nothing else is read. Ignored when IncludeTexts is set (which
	// reads a superset).
	IncludeFirstPrompt bool
	// Commands, when non-nil, receives EVERY run_command row of the session in
	// time order (target, success) — the outcome population.
	Commands func(target string, success bool)
	// Failures, when non-nil, receives EVERY recorded failure message of the
	// session in time order — the error-class population. It is CONTENT, so it
	// is set only alongside IncludeTexts.
	Failures func(message string)
	// PromptHeads, when non-nil, receives the OPENING (cloudPromptHeadBytes) of
	// EVERY user_prompt row of the session, sub-agent rows included, in time
	// order (T-966). The caller only matches it against the harness-message
	// table to correct the activity mix; it never leaves the process, the same
	// posture as the Commands stream.
	PromptHeads func(head string)
}

// cloudPromptHeadBytes bounds how much of a user_prompt row PromptHeads reads:
// the harness table matches the opening element name only.
const cloudPromptHeadBytes = 64

// CloudEvidenceBundle is everything one envelope build reads, from ONE snapshot.
type CloudEvidenceBundle struct {
	Facts CloudSessionFacts
	// Texts is populated only when the request asked for it.
	Texts CloudSessionTexts
}

// cloudEvidenceMidReadHook is a TEST SEAM fired inside the snapshot, after the
// structural facts are read and before the text substrate is. It is nil in
// production and exists so a test can commit a write from a second connection at
// exactly the moment the old code was vulnerable, and prove the snapshot holds.
var cloudEvidenceMidReadHook func()

// LoadCloudEvidenceBundle reads a session's whole evidence substrate — structural
// facts, the streamed outcome and failure populations, and (on request) the text
// substrate — inside ONE pinned-connection read snapshot. NODE-LOCAL.
//
// WHY ONE READ SNAPSHOT (the N4 fix, completed by A7). The reads used to run
// independently against the pool, so a session being written WHILE the envelope
// was built saw an inconsistent world: the aggregate query counted N actions and
// the sample query then selected against a table that already held N+1, dropping
// the last action from the sample and making ActionsOmitted disagree with the
// mix. Two rebuilds of the "same" session then differed, which the two-digest
// protocol reads as tampering — the user is told the evidence changed and asked
// to reconfirm, for no reason but a concurrent insert.
//
// The TEXT substrate was left outside that snapshot, which is the same bug with
// a worse surface: a prompt landing between the facts read and the text read
// changed the excerpts — the part of the envelope a consent receipt is most
// specifically about — while the digest it was bound to stayed the one the user
// previewed. Both halves now read from the same pinned connection.
//
// The snapshot is a pinned connection running BEGIN DEFERRED, deliberately NOT
// s.db.BeginTx: the agent DSN carries _txlock=immediate, so BeginTx would take
// the database's WRITE lock for the duration of a purely read-only build and
// contend with the daemon's own ingest. A deferred transaction on one pinned
// connection gives the same repeatable-read snapshot (WAL readers do not block
// writers) at no cost to the writer.
func (s *Store) LoadCloudEvidenceBundle(ctx context.Context, sessionID string, req CloudEvidenceRequest) (CloudEvidenceBundle, bool, error) {
	if req.EvidenceSettings != nil {
		if err := req.EvidenceSettings.Validate(); err != nil {
			return CloudEvidenceBundle{}, false, err
		}
	}
	maxActions := req.MaxActions
	if maxActions <= 0 {
		maxActions = cloudDefaultActionSample
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return CloudEvidenceBundle{}, false, fmt.Errorf("store.LoadCloudEvidenceBundle: conn: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN DEFERRED`); err != nil {
		return CloudEvidenceBundle{}, false, fmt.Errorf("store.LoadCloudEvidenceBundle: begin: %w", err)
	}
	// Read-only: the snapshot always ends in ROLLBACK, never a commit.
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), `ROLLBACK`) }()

	var out CloudEvidenceBundle
	facts, ok, err := loadCloudSessionRow(ctx, conn, sessionID)
	if err != nil || !ok {
		return CloudEvidenceBundle{}, ok, err
	}
	if err := loadCloudActionAggregates(ctx, conn, sessionID, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if err := loadCloudTokenMetrics(ctx, conn, sessionID, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if err := loadCloudActionScan(ctx, conn, sessionID, maxActions, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if err := loadCloudOutcomeActions(ctx, conn, sessionID, &facts); err != nil {
		return CloudEvidenceBundle{}, false, err
	}
	if req.Commands != nil {
		if err := streamCloudRunCommands(ctx, conn, sessionID, req.Commands); err != nil {
			return CloudEvidenceBundle{}, false, err
		}
	}
	if req.PromptHeads != nil {
		if err := streamCloudPromptHeads(ctx, conn, sessionID, req.PromptHeads); err != nil {
			return CloudEvidenceBundle{}, false, err
		}
	}
	out.Facts = facts

	if hook := cloudEvidenceMidReadHook; hook != nil {
		hook()
	}

	switch {
	case req.EvidenceSettings != nil && (req.IncludeTexts || req.IncludeFirstPrompt):
		settings := *req.EvidenceSettings
		if !req.IncludeTexts {
			settings = CloudEvidenceSettingsForLevel(settings, CloudEnrichTitles)
		}
		texts, terr := loadCloudSelectedTexts(ctx, conn, sessionID, settings, req.Failures)
		if terr != nil {
			return CloudEvidenceBundle{}, false, terr
		}
		out.Texts = texts
	case req.IncludeTexts:
		texts, terr := loadCloudSessionTexts(ctx, conn, sessionID, req.Failures)
		if terr != nil {
			return CloudEvidenceBundle{}, false, terr
		}
		out.Texts = texts
	case req.IncludeFirstPrompt:
		prompts, perr := loadCloudPromptRows(ctx, conn, sessionID)
		if perr != nil {
			return CloudEvidenceBundle{}, false, perr
		}
		out.Texts = CloudSessionTexts{UserPrompts: prompts}
	}
	return out, true, nil
}

// streamCloudRunCommands hands EVERY run_command row of the session to sink, in
// time order, one at a time — the outcome population (A5).
//
// It is a stream and not a load because the population is unbounded in principle
// (a long session runs tens of thousands of commands) and the caller needs only
// counters from it. Targets are read at cloudOutcomeTargetBytes, which is the
// same bound the shell classifier itself scans, so truncation can never change a
// classification.
//
// Sub-agent rows are INCLUDED here, deliberately: a test a sub-agent ran is a
// test this session ran, and an outcome count carries no content. That is the
// opposite of the excerpt reads, which exclude them because they carry text.
func streamCloudRunCommands(ctx context.Context, db cloudReader, sessionID string, sink func(target string, success bool)) error {
	rows, err := db.QueryContext(ctx, `
		SELECT substr(COALESCE(target, ''), 1, ?), COALESCE(success, 1)
		  FROM actions
		 WHERE session_id = ? AND COALESCE(action_type, '') = 'run_command'
		 ORDER BY timestamp ASC, id ASC`, cloudOutcomeTargetBytes, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceBundle: outcome stream: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			target  string
			success int
		)
		if err := rows.Scan(&target, &success); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceBundle: scan outcome row: %w", err)
		}
		sink(target, success != 0)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceBundle: outcome stream: %w", err)
	}
	return nil
}

// streamCloudPromptHeads hands the opening of EVERY user_prompt row of the
// session to sink, in time order (T-966). Like the outcome stream it includes
// sub-agent rows (the activity mix counts the whole session) and reads a
// bounded head only, because the consumer matches the leading element name.
func streamCloudPromptHeads(ctx context.Context, db cloudReader, sessionID string, sink func(head string)) error {
	rows, err := db.QueryContext(ctx, `
		SELECT substr(ltrim(COALESCE(target, '')), 1, ?)
		  FROM actions
		 WHERE session_id = ? AND COALESCE(action_type, '') = 'user_prompt'
		 ORDER BY timestamp ASC, id ASC`, cloudPromptHeadBytes, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceBundle: prompt heads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var head string
		if err := rows.Scan(&head); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceBundle: scan prompt head: %w", err)
		}
		sink(head)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceBundle: prompt heads: %w", err)
	}
	return nil
}

// loadCloudSessionRow reads the sessions row itself.
func loadCloudSessionRow(ctx context.Context, db cloudReader, sessionID string) (CloudSessionFacts, bool, error) {
	var (
		facts       CloudSessionFacts
		model       sql.NullString
		startedAt   sql.NullString
		endedAt     sql.NullString
		total       sql.NullInt64
		quality     sql.NullFloat64
		redundancy  sql.NullFloat64
		sessionErrR sql.NullFloat64
	)
	err := db.QueryRowContext(ctx,
		`SELECT tool, COALESCE(model, ''), project_id, COALESCE(started_at, ''),
		        COALESCE(ended_at, ''), COALESCE(total_actions, 0),
		        quality_score, redundancy_ratio, error_rate
		   FROM sessions WHERE id = ?`, sessionID).
		Scan(&facts.Tool, &model, &facts.ProjectID, &startedAt, &endedAt, &total,
			&quality, &redundancy, &sessionErrR)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudSessionFacts{}, false, nil
	}
	if err != nil {
		return CloudSessionFacts{}, false, fmt.Errorf("store.LoadCloudEvidenceFacts: session row: %w", err)
	}
	facts.Model = model.String
	facts.StartedAt = cloudParseTime(startedAt.String)
	facts.EndedAt = cloudParseTime(endedAt.String)
	facts.TotalActions = int(total.Int64)
	facts.Metrics.QualityScore = quality.Float64
	facts.Metrics.RedundancyRatio = redundancy.Float64
	facts.Metrics.ErrorRate = sessionErrR.Float64
	return facts, true, nil
}

// loadCloudActionAggregates counts the WHOLE session: totals, failures, the
// observed time bounds, and the per-kind mix. These are exact regardless of the
// action-scan bound.
func loadCloudActionAggregates(ctx context.Context, db cloudReader, sessionID string, facts *CloudSessionFacts) error {
	var (
		count, failed int
		minTS, maxTS  sql.NullString
	)
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*),
		        COALESCE(SUM(CASE WHEN COALESCE(success, 1) = 0 THEN 1 ELSE 0 END), 0),
		        MIN(timestamp), MAX(timestamp)
		   FROM actions WHERE session_id = ?`, sessionID).
		Scan(&count, &failed, &minTS, &maxTS); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: action aggregates: %w", err)
	}
	facts.ActionCount = count
	facts.FailedActions = failed
	facts.FirstActionAt = cloudParseTime(minTS.String)
	facts.LastActionAt = cloudParseTime(maxTS.String)

	rows, err := db.QueryContext(ctx,
		`SELECT COALESCE(action_type, ''), COUNT(*)
		   FROM actions WHERE session_id = ?
		  GROUP BY 1 ORDER BY 1 ASC`, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: activity mix: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kc CloudKindCount
		if err := rows.Scan(&kc.Kind, &kc.Count); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceFacts: scan activity mix: %w", err)
		}
		facts.ActivityMix = append(facts.ActivityMix, kc)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: activity mix: %w", err)
	}
	return nil
}

// loadCloudTokenMetrics reads the session's token usage and recorded cost
// from BOTH substrates that can carry it - token_usage (the watcher/JSONL
// path) and api_turns (the proxy path) - deduplicated by the ONE session
// rule, sessionmsg.Derive (over spendverdict.LoadSession's rows, the loader
// every node reader of a session uses). A proxied session writes both an
// api_turns row and its token_usage twin; the rule counts that turn once (the
// proxy row, carrying its twin's visible output and reasoning), keeps a turn
// only one side captured, pairs output-only shadow rows, and reconciles a
// session-cumulative running total - so the sums, the per-row substrate and
// the recorded cost here are the session header's figures.
//
// It replaced a substrate CHOICE (lane R2-ONERULE): token_usage when it had
// rows, api_turns only when it was the whole story, and the recorded cost as
// MAX of the two sums. That dropped every proxied turn the transcript missed
// (and vice versa) and counted Copilot-family shadow rows twice.
//
// Turns carries every counted row, proxy and transcript alike, in time
// order; ProxyTurns is always empty now (kept so a reader of the older split
// still compiles - it only ever priced it when Turns was empty).
func loadCloudTokenMetrics(ctx context.Context, db cloudReader, sessionID string, facts *CloudSessionFacts) error {
	rows, err := spendverdict.LoadSession(ctx, db, sessionID)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: token rows: %w", err)
	}
	v := rows.Verdicts()
	type stamped struct {
		ts   string
		turn CloudTokenTurn
	}
	var counted []stamped
	for i, p := range rows.Proxies {
		if !v.ProxyCounted[i] {
			continue
		}
		counted = append(counted, stamped{p.Timestamp, CloudTokenTurn{
			Model: p.Model, Timestamp: cloudParseTime(p.Timestamp),
			Input: int(p.Input), Output: int(v.ProxyOutput[i]), CacheRead: int(p.CacheRead),
			CacheCreation: int(p.CacheCreation), Reasoning: int(v.ProxyReasoning[i]),
			CacheCreation1h: int(p.CacheCreation1h), WebSearchRequests: int(p.WebSearchRequests),
			Fast:            p.Fast || v.ProxyInheritedFast[i],
			RecordedCostUSD: proxyRecordedCost(p.CostUSD, p.Fast, v.ProxyInheritedFast[i]),
		}})
	}
	for i, t := range rows.Tokens {
		if !v.TokenCounted[i] {
			continue
		}
		counted = append(counted, stamped{t.Timestamp, CloudTokenTurn{
			Model: t.Model, Timestamp: cloudParseTime(t.Timestamp),
			Input: int(t.Input), Output: int(t.Output), CacheRead: int(t.CacheRead),
			CacheCreation: int(t.CacheCreation), Reasoning: int(t.Reasoning),
			CacheCreation1h: int(t.CacheCreation1h), WebSearchRequests: int(t.WebSearchRequests),
			Fast: t.Fast, RecordedCostUSD: t.CostUSD,
		}})
	}
	// Time order with a deterministic tie-break (the two-digest protocol
	// needs an unchanged session to rebuild identical bytes).
	sort.SliceStable(counted, func(i, j int) bool { return counted[i].ts < counted[j].ts })
	m := &facts.Metrics
	m.Turns = nil
	for _, c := range counted {
		t := c.turn
		m.TokensIn += t.Input
		m.TokensOut += t.Output
		m.CacheReadTokens += t.CacheRead
		m.CacheCreationTokens += t.CacheCreation
		m.ReasoningTokens += t.Reasoning
		if t.RecordedCostUSD > 0 {
			m.CostUSD += t.RecordedCostUSD
		}
		m.Turns = append(m.Turns, t)
	}
	m.RecordedRows = len(counted)
	return nil
}

// proxyRecordedCost is a counted proxy row's recorded cost: its own, unless
// its fast transcript twin lifted it to the fast tier, in which case the
// recorded figure (priced at the standard wire tier) no longer stands and
// the caller prices the row (the cost engine's rule).
func proxyRecordedCost(cost float64, fast, inheritedFast bool) float64 {
	if inheritedFast && !fast {
		return 0
	}
	return cost
}

// cloudDefaultActionSample is the sample size used when a caller passes 0. It
// matches the envelope's own MaxActions; the store cannot import the contract
// (that would invert the dependency), so the CLI passes the real bound and this
// is only the fallback.
const cloudDefaultActionSample = 256

// loadCloudActionScan selects a STRIDED SAMPLE across the session's whole
// ordered action population, never a prefix.
//
// WHY A WINDOW FUNCTION AND NOT `LIMIT n` (the F6 fix). The previous read took
// the first 20,000 rows and let the pure builder sample within them, so a
// 30,000-action session shipped a sample of its FIRST 20,000 — the tail, where
// the work usually lands, could not be selected at all, and the omission count
// was computed against the truncated set rather than the real one. Counting
// first, computing the stride in Go, and filtering on ROW_NUMBER() keeps the
// selection population-wide while still returning only ~maxActions rows to Go.
//
// Ref stays the row's ORIGINAL index in the full order, so ref gaps show the
// sampling honestly, and facts.ActionCount (counted in SQL over every row) is
// the population the caller reports omissions against.
func loadCloudActionScan(ctx context.Context, db cloudReader, sessionID string, maxActions int, facts *CloudSessionFacts) error {
	total := facts.ActionCount
	if total == 0 {
		return nil
	}
	stride := 1
	if total > maxActions {
		// ceil(total / maxActions): the smallest stride whose sample fits. The
		// stride is the ONLY thing the Go-side count is used for — the "always
		// include the last row" predicate compares against the statement's own
		// COUNT(*) OVER (), so a population that grew between the two reads can
		// no longer drop the session's last action from the sample (N4).
		stride = (total + maxActions - 1) / maxActions
	}
	rows, err := db.QueryContext(ctx, `
		WITH ordered AS (
		  SELECT COALESCE(action_type, '') AS kind,
		         COALESCE(success, 1)      AS ok,
		         COALESCE(target, '')      AS target,
		         COALESCE(raw_tool_name, '') AS tool_name,
		         timestamp                 AS ts,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn,
		         COUNT(*)     OVER ()                               AS total
		    FROM actions WHERE session_id = ?
		)
		SELECT kind, ok, target, tool_name, ts, rn
		  FROM ordered
		 WHERE (rn - 1) % ? = 0 OR rn = total
		 ORDER BY rn ASC`, sessionID, stride)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: action sample: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			kind, target, toolName, ts string
			success                    int
			rn                         int64
		)
		if err := rows.Scan(&kind, &success, &target, &toolName, &ts, &rn); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceFacts: scan action: %w", err)
		}
		facts.Actions = append(facts.Actions, CloudActionFact{
			Ref:         "a" + strconv.FormatInt(rn-1, 10),
			Kind:        kind,
			Success:     success != 0,
			Target:      target,
			RawToolName: toolName,
			Timestamp:   cloudParseTime(ts),
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: action sample: %w", err)
	}
	return nil
}

// loadCloudOutcomeActions reads the KIND-BOUNDED outcome population: every row
// whose kind can fire a milestone or an outcome rule, plus any failed row (the
// first_error rule matches a failure of ANY kind). Targets are read truncated —
// command classification only inspects the leading tokens — so the population is
// bounded in memory per row as well as in row count.
//
// The bound is a HEAD WINDOW PLUS A TAIL WINDOW (see cloudMaxOutcomeRows), not a
// prefix: milestones are answered by the head, the last build outcome and the
// terminal milestones by the tail. `COUNT(*) OVER ()` computes the population
// size inside the same statement, so the window edges can never be computed
// against a different read than the one they filter.
func loadCloudOutcomeActions(ctx context.Context, db cloudReader, sessionID string, facts *CloudSessionFacts) error {
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(cloudOutcomeKinds)), ",")
	args := make([]any, 0, len(cloudOutcomeKinds)+4)
	args = append(args, cloudOutcomeTargetBytes, sessionID)
	for _, k := range cloudOutcomeKinds {
		args = append(args, k)
	}
	args = append(args, cloudOutcomeHeadRows, cloudOutcomeTailRows)
	rows, err := db.QueryContext(ctx, `
		WITH ordered AS (
		  SELECT COALESCE(action_type, '')      AS kind,
		         COALESCE(success, 1)           AS ok,
		         substr(COALESCE(target, ''), 1, ?) AS target,
		         COALESCE(raw_tool_name, '')    AS tool_name,
		         timestamp                      AS ts,
		         ROW_NUMBER() OVER (ORDER BY timestamp ASC, id ASC) AS rn,
		         COUNT(*)     OVER ()                               AS total
		    FROM actions
		   WHERE session_id = ?
		     AND (COALESCE(action_type, '') IN (`+placeholders+`) OR COALESCE(success, 1) = 0)
		)
		SELECT kind, ok, target, tool_name, ts
		  FROM ordered
		 WHERE rn <= ? OR rn > total - ?
		 ORDER BY rn ASC`, args...)
	if err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: outcome population: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			kind, target, toolName, ts string
			success                    int
		)
		if err := rows.Scan(&kind, &success, &target, &toolName, &ts); err != nil {
			return fmt.Errorf("store.LoadCloudEvidenceFacts: scan outcome row: %w", err)
		}
		facts.OutcomeActions = append(facts.OutcomeActions, CloudActionFact{
			Kind:        kind,
			Success:     success != 0,
			Target:      target,
			RawToolName: toolName,
			Timestamp:   cloudParseTime(ts),
		})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("store.LoadCloudEvidenceFacts: outcome population: %w", err)
	}
	return nil
}
