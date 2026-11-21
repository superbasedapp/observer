package cloudagents

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// UsageFigure is one native usage figure a vendor reported for a task
// (ACUs, credits, premium requests, vendor USD). It lands in the node-local
// cloud_usage_ledger in its own unit, never summed across units (CA-D11).
type UsageFigure struct {
	Unit             string
	Value            float64
	ValueType        string // models.UsageValue*
	Source           string // models.UsageSource*
	MonetaryStatus   string // models.UsageMonetary*
	IncludesChildren *bool
	IntervalStart    time.Time
	IntervalEnd      time.Time
	ReportedAt       time.Time
	Model            string
	// RecordID is the vendor's own id of the measured record (Cursor: a
	// run's usageUuid), "" when it reports none. When set, the ledger row's
	// source_record_id is derived from it alone, so a re-read of the same
	// record lands once whatever time it is read at.
	RecordID string
	// Run is the vendor run the figure covers (scope_run), "" for a
	// session-level figure.
	Run string
	// Revisable names a figure the vendor may revise (Cursor: the part of
	// an agent's cost no run reports, which moves whenever a run starts or
	// ends). The ledger keeps ONE live row per (connector, session, key,
	// monetary status): a changed value lands as a new revision that
	// supersedes the previous row (ResolveRevisions), never frozen by the
	// insert-once record id. "" for a figure that is final once reported.
	Revisable string
}

// TokenFigure is a real token total a vendor reported for a task. It lands
// in token_usage with its source tier (CA-D11).
type TokenFigure struct {
	Kind          TokenSourceKind
	Model         string
	Input         int64
	Output        int64
	CacheRead     int64
	CacheCreation int64
	// CacheCreation1h is the part of CacheCreation written to the 1-hour
	// cache tier, 0 when the vendor gives no split.
	CacheCreation1h int64
	Reasoning       int64
	ReportedAt      time.Time
}

// LedgerEntry is one cloud_usage_ledger row as this package computes it;
// the service copies it onto the store's row type (no store type leaks
// into this pure package).
type LedgerEntry struct {
	Connector         string
	SourceRecordID    string
	MeasurementSource string
	ValueType         string
	Unit              string
	Value             float64
	MonetaryStatus    string
	ScopeRun          string
	ScopeSession      string
	ScopeAccount      string
	ScopeModel        string
	IntervalStart     time.Time
	IntervalEnd       time.Time
	IncludesChildren  *bool
	ReportedAt        time.Time
	// Revisable marks an entry whose SourceRecordID is still the revision
	// base; ResolveRevisions turns it into a numbered revision.
	Revisable bool
	// SupersedesID is the ledger row this entry replaces (0 = none).
	SupersedesID int64
}

// SourceFilePrefix starts the source_file of every row a connector writes
// (SourceFile); no capture adapter writes a source_file with this prefix.
const SourceFilePrefix = "cloud-agents/"

// SourceFile is the stable actions.source_file / token_usage.source_file of
// rows a connector writes (the dedup key with SourceEventID; not a path).
func SourceFile(connector string) string { return SourceFilePrefix + connector }

// VocabularyForSource returns the tool id whose native tool names a stored
// action row is classified under, given the row's tool and source_file:
// the vocabulary of the connector that wrote the row (Connector.Vocabulary,
// so Cline Cloud's rows read under cline-cli), else the row's own tool. A
// reader that resolves a stored raw_tool_name through the taxonomy (the
// dashboard's surface breakdown) calls this so it classifies the row
// exactly as MapActivity did at capture. A connector row that follows the
// session's harness (HarnessTools) keeps the landing tool, which is what
// ForTask gave MapActivity.
func VocabularyForSource(tool, sourceFile string) string {
	id, ok := strings.CutPrefix(sourceFile, SourceFilePrefix)
	if !ok {
		return tool
	}
	for _, c := range Connectors {
		if c.ID == id && c.ToolVocabulary != "" {
			return c.ToolVocabulary
		}
	}
	return tool
}

// StartTime is when a task's session began, as well as the vendor says:
// its creation time, else its first known update.
func (t Task) StartTime() time.Time {
	if !t.CreatedAt.IsZero() {
		return t.CreatedAt
	}
	return t.UpdatedAt
}

// EndTime is when a terminal task ended (zero for a live one).
func (t Task) EndTime() time.Time {
	if !t.Lifecycle.Terminal() {
		return time.Time{}
	}
	if !t.CompletedAt.IsZero() {
		return t.CompletedAt
	}
	return t.UpdatedAt
}

// MapEvents maps a task to the lifecycle actions Ingest lands: one
// session_start, and a session_end once the task is terminal. sessionID is
// the row ResolveSessionID chose; projectRoot the root the project resolves
// to. A task with no time at all yields nothing (Ingest needs a timestamp,
// and inventing one would be fabrication).
func MapEvents(c Connector, t Task, sessionID, projectRoot string) []models.ToolEvent {
	start := t.StartTime()
	if start.IsZero() || sessionID == "" || projectRoot == "" {
		return nil
	}
	base := models.ToolEvent{
		SourceFile: SourceFile(c.ID), SessionID: sessionID, ProjectRoot: projectRoot,
		Tool: c.Tool, RawToolName: "cloud_task",
	}
	ev := base
	ev.SourceEventID = c.ID + ":" + t.ID + ":start"
	ev.Timestamp = start
	ev.ActionType = models.ActionSessionStart
	ev.Target = "cloud"
	ev.Success = true
	out := []models.ToolEvent{ev}
	if end := t.EndTime(); !end.IsZero() {
		if end.Before(start) {
			end = start
		}
		e := base
		// The end time is part of the id: a task that gets another turn and
		// ends again lands a second end marker; ended_at follows the latest.
		e.SourceEventID = c.ID + ":" + t.ID + ":end:" + strconv.FormatInt(end.UnixNano(), 10)
		e.Timestamp = end
		e.ActionType = models.ActionSessionEnd
		e.Target = string(t.Lifecycle)
		e.Success = t.Lifecycle == LifecycleSucceeded
		e.RawToolName = "cloud_task:" + t.VendorStatus
		out = append(out, e)
	}
	return out
}

// tokenSourceColumn maps a token source kind to token_usage.source and
// reliability.
var tokenSourceColumn = map[TokenSourceKind][2]string{
	TokenFromSandboxTranscript: {models.TokenSourceJSONL, models.ReliabilityAccurate},
	TokenFromProviderRunTotal:  {models.TokenSourceSessionSummary, models.ReliabilityAccurate},
	TokenFromOTelProvisional:   {models.TokenSourceOTel, models.ReliabilityApproximate},
	TokenFromOrgDailyReport:    {models.TokenSourceEstimated, models.ReliabilityApproximate},
}

// MapTokens maps a task's reported token total to one token event, or nil
// when the vendor reported none (absent, never zero).
func MapTokens(c Connector, t Task, sessionID, projectRoot string) []models.TokenEvent {
	f := t.Tokens
	if f == nil || sessionID == "" || projectRoot == "" {
		return nil
	}
	col, ok := tokenSourceColumn[f.Kind]
	if !ok {
		return nil
	}
	at := f.ReportedAt
	if at.IsZero() {
		at = t.UpdatedAt
	}
	if at.IsZero() {
		return nil
	}
	return []models.TokenEvent{{
		SourceFile: SourceFile(c.ID), SourceEventID: c.ID + ":" + t.ID + ":tokens:" + string(f.Kind),
		SessionID: sessionID, ProjectRoot: projectRoot, Timestamp: at, Tool: c.Tool, Model: f.Model,
		InputTokens: f.Input, OutputTokens: f.Output, CacheReadTokens: f.CacheRead,
		CacheCreationTokens: f.CacheCreation, CacheCreation1hTokens: f.CacheCreation1h, ReasoningTokens: f.Reasoning,
		Source: col[0], Reliability: col[1],
	}}
}

// MapLedger maps a task's native usage figures to ledger entries. A figure
// with an unknown vocabulary value is dropped rather than coerced.
func MapLedger(c Connector, t Task, sessionID, accountID string) []LedgerEntry {
	var out []LedgerEntry
	for _, f := range t.Usage {
		if !models.KnownUsageSource(f.Source) || !models.KnownUsageValueType(f.ValueType) ||
			!models.KnownUsageMonetaryStatus(f.MonetaryStatus) || f.Unit == "" {
			continue
		}
		at := f.ReportedAt
		if at.IsZero() {
			at = t.UpdatedAt
		}
		if at.IsZero() {
			continue
		}
		id := c.ID + ":" + t.ID + ":" + f.Unit + ":" + strconv.FormatInt(at.UnixNano(), 10)
		if f.RecordID != "" {
			// One vendor record may carry several measurements in one unit
			// (Cursor: the list-price and the charged amount), so the
			// monetary status tells them apart under the unique
			// (connector, source_record_id) index.
			id = f.RecordID + ":" + f.MonetaryStatus
		}
		if f.Revisable != "" {
			// The revision base; ResolveRevisions numbers it.
			id = t.ID + ":" + f.Revisable + ":" + f.MonetaryStatus
		}
		out = append(out, LedgerEntry{
			Connector: c.ID, SourceRecordID: id, ScopeRun: f.Run,
			MeasurementSource: f.Source, ValueType: f.ValueType, Unit: f.Unit, Value: f.Value,
			MonetaryStatus: f.MonetaryStatus, ScopeSession: sessionID, ScopeAccount: accountID,
			ScopeModel: f.Model, IntervalStart: f.IntervalStart, IntervalEnd: f.IntervalEnd,
			IncludesChildren: f.IncludesChildren, ReportedAt: at, Revisable: f.Revisable != "",
		})
	}
	return out
}

// PriorLedgerRow is a ledger row already stored for the session, as
// ResolveRevisions needs it (the service copies it from the store).
type PriorLedgerRow struct {
	ID             int64
	SourceRecordID string
	Value          float64
}

// revisionSep separates a revision base from its number.
const revisionSep = "#r"

// revisionTolerance is the smallest value change that makes a new revision
// (below it the value is the same figure, float noise).
const revisionTolerance = 1e-9

// ResolveRevisions turns each revisable entry into a numbered revision
// (base#r<n>) that supersedes the newest stored revision of the same base,
// or drops it when its value has not changed. The readers drop a superseded
// row (cloudlane), so exactly one revision per base is ever counted, and a
// value that returns to an earlier one still lands as a NEW revision (an
// earlier id would be ignored by the insert-once index while staying
// superseded). A first revision of zero lands nothing: there is nothing to
// represent. Entries that are not revisable pass through unchanged.
func ResolveRevisions(entries []LedgerEntry, prior []PriorLedgerRow) []LedgerEntry {
	out := make([]LedgerEntry, 0, len(entries))
	for _, e := range entries {
		if !e.Revisable {
			out = append(out, e)
			continue
		}
		base := e.SourceRecordID
		var latest *PriorLedgerRow
		n := 0
		for i := range prior {
			rest, ok := strings.CutPrefix(prior[i].SourceRecordID, base+revisionSep)
			if !ok {
				continue
			}
			k, err := strconv.Atoi(rest)
			if err != nil || k <= n {
				continue
			}
			n, latest = k, &prior[i]
		}
		switch {
		case latest != nil && math.Abs(latest.Value-e.Value) < revisionTolerance:
			continue // unchanged: the live revision stands
		case latest == nil && math.Abs(e.Value) < revisionTolerance:
			continue // nothing to represent
		}
		e.SourceRecordID = base + revisionSep + strconv.Itoa(n+1)
		if latest != nil {
			e.SupersedesID = latest.ID
		}
		e.Revisable = false
		out = append(out, e)
	}
	return out
}

// Surface returns the surface stamp of a pulled session: the connector's
// host token only (CA-D15), or nil when the row declares none. The kind is
// left empty on purpose (unknown, never guessed).
func Surface(c Connector, sessionID string) []models.SessionSurface {
	if c.SurfaceHost == "" || sessionID == "" {
		return nil
	}
	return []models.SessionSurface{{SessionID: sessionID, SurfaceHost: c.SurfaceHost}}
}

// Execution is the cloud-execution stamp of a pulled session: it ran in the
// vendor's cloud (CA-D1), with the vendor's second reference when one exists,
// unless a table row resolved another location from a vendor field (Qoder's
// self-hosted environment: customer_worker) or the location still waits for
// the read that reports it.
func Execution(sessionID string, t Task) models.SessionExecution {
	loc := models.ExecutionVendorCloud
	switch {
	case t.ExecutionPending:
		loc = "" // waits for the read that says where it ran
	case t.ExecutionLocation != "":
		loc = t.ExecutionLocation
	case t.EnvironmentKind != "":
		loc = "" // a reported kind no EnvironmentKinds row names: unknown
	}
	return models.SessionExecution{SessionID: sessionID, ExecutionLocation: loc, VendorSessionRef: t.VendorRef}
}

// DeliveryLink is one pull request or branch a vendor said a cloud session
// produced (lane CA-C5). The service hands it to the store as a
// cloud_session_links row; internal/projectroi.CreditCloud turns it into
// commit credit.
type DeliveryLink struct {
	// Remote is the repository, "host/owner/repo".
	Remote string
	// PRNumber is the stated PR number (0 = none); Branch the stated branch
	// ("" = none).
	PRNumber int64
	Branch   string
}

// DeliveryLinks maps a task to its delivery links, one table row per vendor
// pointer, nothing guessed:
//
//	stated PR  - the task's PR number (Copilot pullRequestNumber, Devin
//	             pull_requests[0].pr_url), on the PR URL's repository, else
//	             the task's repository;
//	run branch - each Cursor run's git.branches[0] {repoUrl, branch}.
//
// A pointer with no repository is dropped (a PR number means nothing
// without one). The Codex Cloud list (CX01) carries no PR or branch, so a
// Codex task yields none.
func DeliveryLinks(t Task) []DeliveryLink {
	var out []DeliveryLink
	seen := map[DeliveryLink]bool{}
	add := func(l DeliveryLink) {
		if l.Remote == "" || (l.PRNumber <= 0 && l.Branch == "") || seen[l] {
			return
		}
		seen[l] = true
		out = append(out, l)
	}
	if t.PullRequestNumber > 0 {
		remote, n := PullRequestFromURL(t.PullRequestURL)
		if remote == "" {
			remote = t.RepoRemote
		}
		if n == 0 || n == t.PullRequestNumber {
			add(DeliveryLink{Remote: remote, PRNumber: t.PullRequestNumber})
		}
	}
	for _, r := range t.Runs {
		if r.Branch != "" {
			add(DeliveryLink{Remote: r.Remote, Branch: r.Branch})
		}
	}
	return out
}
