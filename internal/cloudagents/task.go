package cloudagents

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Task is one cloud session or task as a connector discovered it, already
// normalized. Content-bearing vendor fields (titles, summaries, prompt-
// derived names) are deliberately NOT carried: this lane captures where and
// when work ran, not what it said.
type Task struct {
	// Connector is the connector id.
	Connector string
	// ID is the vendor's native session or task id; it becomes sessions.id
	// (CA-D2).
	ID string
	// VendorRef is a second native reference for cross-rail joins (CA-D2),
	// "" when the vendor exposes none.
	VendorRef string
	// VendorStatus is the vendor's status string, lowercased and bounded.
	VendorStatus string
	// Lifecycle is VendorStatus through the connector's table.
	Lifecycle Lifecycle
	// CreatedAt is when the task started; zero when the vendor does not say.
	CreatedAt time.Time
	// UpdatedAt is the vendor's last-update time; zero when absent.
	UpdatedAt time.Time
	// CompletedAt is when the task ended; zero when not ended or not stated.
	CompletedAt time.Time
	// RepoRemote is the repository the task ran against, as a remote
	// ("github.com/owner/repo"); "" when the vendor does not say.
	RepoRemote string
	// EnvironmentID / EnvironmentLabel are the vendor environment (Codex).
	EnvironmentID    string
	EnvironmentLabel string
	// User is the vendor login that started the task ("" when absent).
	// On a member-scoped connector (Devin user_id, OpenHands
	// created_by_user_id, Warp creator.uid of a "user" creator) it is the
	// vendor user id the ownership decision compares with the account's
	// chosen user.
	User string
	// ServiceUser is the vendor service user that started the task (Devin
	// service_user_id: an automation or an organization API key; Warp
	// creator.uid of a "service_account" creator: the team's service
	// account an Agent key acts as), "" when none. A task started by a
	// service user names no person and is never landed on a member-scoped
	// account (OwnerSkipServiceUser).
	ServiceUser string
	// PullRequestNumber / PullRequestURL link the task's PR when stated.
	PullRequestNumber int64
	PullRequestURL    string
	// Attempts is Codex's attempt_total (best-of-N), 0 when absent. It is
	// NOT a subagent count.
	Attempts int
	// Usage is native usage the vendor reported for the task (none for the
	// two CLI connectors; lane CA-B2's API connectors fill it).
	Usage []UsageFigure
	// Tokens is a real token total the vendor reported, nil when absent.
	Tokens *TokenFigure
	// ParentID is the vendor's parent session id ("" when none or not
	// stated). Recorded for lineage; not landed in this lane.
	ParentID string
	// ForkedFromID is the session this one continues when the vendor
	// states it (Cline: a local task handed off to the cloud,
	// metadata.handoff.sourceSessionId). It lands as a user fork
	// (forked_from_id, thread_source "user"), not as a subagent.
	ForkedFromID string
	// Runs are the executions of a durable agent (Cursor), oldest first,
	// filled by the runs detail call; nil when not read.
	Runs []Run
	// DetailPending is true when the row declares detail calls that this
	// pass did not make for the task (budget), so a later pass re-reads it.
	DetailPending bool
	// Harness is the vendor harness the task ran under (Warp: claude, codex,
	// oz), "" when the connector has none. A row that declares HarnessTools
	// lands the task under that harness's tool (ForTask).
	Harness string
	// EnvironmentKind is the environment type the vendor reported (Qoder
	// config.type, bounded), "" when not read.
	EnvironmentKind string
	// ExecutionLocation is the execution_location resolved from a vendor
	// field (Warp: customer_worker for a self-hosted worker_host; Qoder: an
	// EnvironmentKinds row); "" leaves the connector default (vendor_cloud,
	// CA-D1).
	ExecutionLocation string
	// ExecutionPending is true while the location waits for a detail read
	// (Qoder: the environment); Execution then stamps no location, so a
	// fill-only stamp is never written before the vendor said where it ran.
	ExecutionPending bool
}

// Run is one execution of a durable cloud agent (Cursor runs).
type Run struct {
	ID        string
	Status    string
	Lifecycle Lifecycle
	CreatedAt time.Time
	UpdatedAt time.Time
	// Remote / Branch are the run's first git.branches entry ({repoUrl,
	// branch}) as "host/owner/repo" and the branch name; "" when the run
	// reported none. Delivery credit (DeliveryLinks) reads them.
	Remote string
	Branch string
}

// Page is one parsed discovery page.
type Page struct {
	Tasks []Task
	// Cursor continues the listing ("" = no further page).
	Cursor string
}

// Identity is what the connect probe learned about the vendor login.
type Identity struct {
	// AccountID is the vendor's immutable account id.
	AccountID string
	// Display is a display name (a login), never used as the key.
	Display string
}

// LocalLoginAccount is the account id of a connector whose CLI exposes no
// account id without reading its credential file: the account is "the
// vendor CLI's signed-in login on this machine". Switching that login to a
// different vendor account is not visible to Observer (hand-back open
// question).
const LocalLoginAccount = "local-cli-login"

// maxToken bounds short vendor tokens kept on a Task.
const maxToken = 64

func boundToken(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) > maxToken {
		s = s[:maxToken]
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return "other"
		}
	}
	return s
}

// flexTime decodes an RFC 3339 string, a unix-seconds number, or null.
type flexTime struct{ t time.Time }

func (f *flexTime) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		if s == "" {
			return nil
		}
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			return err
		}
		f.t = t.UTC()
		return nil
	}
	n, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return err
	}
	if n > 0 {
		sec := int64(n)
		f.t = time.Unix(sec, int64((n-float64(sec))*1e9)).UTC()
	}
	return nil
}

func wrongShape(msg string) error { return &Error{Class: ErrWrongShape, Msg: msg} }

// --- codex cloud list --json -------------------------------------------------

// codexTask is the documented `codex cloud list --json` task (reference
// chapter 03, CX01): id, url, title, status, updated_at, environment_id,
// environment_label, summary, is_review, attempt_total. title and summary are
// decoded as raw values and dropped (content). created_at is read when a
// build emits it.
type codexTask struct {
	ID               string          `json:"id"`
	URL              string          `json:"url"`
	Title            json.RawMessage `json:"title"`
	Status           string          `json:"status"`
	CreatedAt        flexTime        `json:"created_at"`
	UpdatedAt        flexTime        `json:"updated_at"`
	EnvironmentID    *string         `json:"environment_id"`
	EnvironmentLabel *string         `json:"environment_label"`
	Summary          json.RawMessage `json:"summary"`
	IsReview         bool            `json:"is_review"`
	AttemptTotal     *int            `json:"attempt_total"`
}

type codexList struct {
	Tasks  *[]codexTask `json:"tasks"`
	Cursor *string      `json:"cursor"`
}

// ParseCodexList parses one page of `codex cloud list --json`.
func ParseCodexList(b []byte) (Page, error) {
	var l codexList
	if err := json.Unmarshal(b, &l); err != nil {
		return Page{}, wrongShape("codex cloud list output is not the documented JSON")
	}
	if l.Tasks == nil {
		return Page{}, wrongShape("codex cloud list output has no tasks array")
	}
	c, _ := ConnectorByID(ConnectorCodexCloud)
	var p Page
	for _, t := range *l.Tasks {
		if !ValidSessionID(t.ID) {
			continue
		}
		task := Task{
			Connector: ConnectorCodexCloud, ID: t.ID,
			VendorStatus: boundToken(t.Status), Lifecycle: c.LifecycleOf(t.Status),
			CreatedAt: t.CreatedAt.t, UpdatedAt: t.UpdatedAt.t,
		}
		if t.EnvironmentID != nil {
			task.EnvironmentID = boundField(*t.EnvironmentID)
		}
		if t.EnvironmentLabel != nil {
			task.EnvironmentLabel = boundField(*t.EnvironmentLabel)
		}
		if t.AttemptTotal != nil && *t.AttemptTotal > 0 {
			task.Attempts = *t.AttemptTotal
		}
		if task.Lifecycle.Terminal() {
			// The list carries no completion time; the last update of a
			// finished task is when it finished.
			task.CompletedAt = task.UpdatedAt
		}
		p.Tasks = append(p.Tasks, task)
	}
	if l.Cursor != nil && *l.Cursor != "" {
		if !ValidCursor(*l.Cursor) {
			return Page{}, wrongShape("codex cloud list returned an unusable cursor")
		}
		p.Cursor = *l.Cursor
	}
	return p, nil
}

// boundField trims and bounds a free-form identifier field.
func boundField(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}

// --- gh agent-task list|view --json -----------------------------------------

// ghSession is gh 2.89.0's capi.Session.ExportData shape: repository is the
// PR repository's nameWithOwner ("owner/repo") or null, user is the login or
// null, times are RFC 3339 or null. name and pullRequestTitle are content
// and are not decoded.
type ghSession struct {
	ID                string   `json:"id"`
	State             string   `json:"state"`
	Repository        *string  `json:"repository"`
	User              *string  `json:"user"`
	CreatedAt         flexTime `json:"createdAt"`
	UpdatedAt         flexTime `json:"updatedAt"`
	CompletedAt       flexTime `json:"completedAt"`
	PullRequestNumber *int64   `json:"pullRequestNumber"`
	PullRequestURL    *string  `json:"pullRequestUrl"`
	PullRequestState  *string  `json:"pullRequestState"`
}

func (s ghSession) task(c Connector) (Task, bool) {
	if !ValidSessionID(s.ID) {
		return Task{}, false
	}
	t := Task{
		Connector: c.ID, ID: s.ID,
		VendorStatus: boundToken(s.State), Lifecycle: c.LifecycleOf(s.State),
		CreatedAt: s.CreatedAt.t, UpdatedAt: s.UpdatedAt.t, CompletedAt: s.CompletedAt.t,
	}
	if s.Repository != nil && ValidRepoSlug(*s.Repository) {
		t.RepoRemote = "github.com/" + *s.Repository
	}
	if s.User != nil {
		t.User = boundField(*s.User)
	}
	if s.PullRequestNumber != nil && *s.PullRequestNumber > 0 {
		t.PullRequestNumber = *s.PullRequestNumber
	}
	if s.PullRequestURL != nil && strings.HasPrefix(*s.PullRequestURL, "https://github.com/") {
		t.PullRequestURL = boundField(*s.PullRequestURL)
	}
	return t, true
}

// ParseCopilotList parses `gh agent-task list --json <fields>` (a JSON
// array, possibly empty).
func ParseCopilotList(b []byte) (Page, error) {
	var list []ghSession
	if err := json.Unmarshal(b, &list); err != nil {
		return Page{}, wrongShape("gh agent-task list output is not the expected JSON array")
	}
	c, _ := ConnectorByID(ConnectorCopilotAgent)
	var p Page
	for _, s := range list {
		if t, ok := s.task(c); ok {
			p.Tasks = append(p.Tasks, t)
		}
	}
	return p, nil
}

// ParseCopilotView parses `gh agent-task view <id> --json <fields>` (one
// object).
func ParseCopilotView(b []byte) (Task, error) {
	var s ghSession
	if err := json.Unmarshal(b, &s); err != nil {
		return Task{}, wrongShape("gh agent-task view output is not the expected JSON object")
	}
	c, _ := ConnectorByID(ConnectorCopilotAgent)
	t, ok := s.task(c)
	if !ok {
		return Task{}, wrongShape("gh agent-task view returned no usable id")
	}
	return t, nil
}

// ParseGHUser parses `gh api user`: only the immutable numeric id and the
// login are read.
func ParseGHUser(b []byte) (Identity, error) {
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.Unmarshal(b, &u); err != nil || u.ID <= 0 {
		return Identity{}, wrongShape("gh api user returned no account id")
	}
	return Identity{AccountID: strconv.FormatInt(u.ID, 10), Display: boundField(u.Login)}, nil
}

// ParsePage dispatches a list response to the connector's parser.
func ParsePage(connector string, b []byte) (Page, error) {
	switch connector {
	case ConnectorCodexCloud:
		return ParseCodexList(b)
	case ConnectorCopilotAgent:
		return ParseCopilotList(b)
	}
	return Page{}, errInvalid("unknown connector")
}

// ParseIdentity dispatches an identity probe response.
func ParseIdentity(connector string, b []byte) (Identity, error) {
	switch connector {
	case ConnectorCodexCloud:
		if _, err := ParseCodexList(b); err != nil {
			return Identity{}, err
		}
		return Identity{AccountID: LocalLoginAccount}, nil
	case ConnectorCopilotAgent:
		return ParseGHUser(b)
	}
	return Identity{}, errInvalid("unknown connector")
}

// ValidRepoSlug reports whether s is a plain GitHub "owner/repo".
func ValidRepoSlug(s string) bool {
	owner, repo, ok := strings.Cut(s, "/")
	if !ok || owner == "" || repo == "" || len(s) > 200 || strings.Contains(repo, "/") {
		return false
	}
	ok = true
	check := func(part string) {
		if strings.HasPrefix(part, ".") || strings.HasPrefix(part, "-") {
			ok = false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				ok = false
			}
		}
	}
	check(owner)
	check(repo)
	return ok
}
