package feed

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Kind is the closed vocabulary of notification kinds, one per rule.
type Kind string

// The kinds, in rule order.
const (
	KindOrgBudget       Kind = "org_budget"       // an org budget window crossed a threshold (budget-status.json)
	KindMonthlyBudget   Kind = "monthly_budget"   // the node's own monthly budget at 80% / over 100%
	KindGrantActive     Kind = "grant_active"     // an access grant is in force (a request was approved)
	KindGrantExpiring   Kind = "grant_expiring"   // an access grant expires within ExpiringWithin
	KindGrantInactive   Kind = "grant_inactive"   // a cached grant is no longer honoured (expired, used up, unverified)
	KindRequestUnsent   Kind = "request_unsent"   // a queued access request failed to reach the org
	KindGuardBlocked    Kind = "guard_blocked"    // the guard denied or asked about a tool call
	KindPromptHeld      Kind = "prompt_held"      // a prompt is held until the developer resends it
	KindCacheExpiring   Kind = "cache_expiring"   // a warm prompt cache is about to expire
	KindUpdate          Kind = "update"           // an update needs the developer (available, blocked, failed, refused)
	KindUpdateApplied   Kind = "update_applied"   // this node updated itself
	KindOrgAnnouncement Kind = "org_announcement" // a message from the org (or the release rail)
	KindOrgPolicy       Kind = "org_policy"       // the org changed a policy this machine applies
	KindIngestStall     Kind = "ingest_stall"     // session files are not being ingested
	KindOrgMessage      Kind = "org_message"      // an admin wrote to the developer, or a reply did not reach the org
)

// Severity is the display tier.
type Severity string

// The tiers, most urgent first.
const (
	SeverityCritical Severity = "critical"
	SeverityWarn     Severity = "warn"
	SeverityInfo     Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarn:
		return 1
	default:
		return 2
	}
}

// Notification is one row of the bell.
type Notification struct {
	// ID is stable across polls for the same underlying event, so read and
	// dismiss state sticks; a new event (a new day's denials, a new grant, a
	// higher budget rung) gets a new id and notifies again.
	ID       string    `json:"id"`
	Kind     Kind      `json:"kind"`
	Severity Severity  `json:"severity"`
	Title    string    `json:"title"`
	Body     string    `json:"body,omitempty"`
	Section  string    `json:"section,omitempty"`
	Link     string    `json:"link,omitempty"`
	At       time.Time `json:"at"`
	// USD is a money figure the dashboard formats under the developer cost
	// display (never rendered into Title / Body).
	USD  *float64 `json:"usd,omitempty"`
	Read bool     `json:"read"`
}

// Tunables.
const (
	// ExpiringWithin is how close to expiry a grant notifies.
	ExpiringWithin = 24 * time.Hour
	// RecentWithin bounds how long an applied update or a policy change stays
	// in the feed.
	RecentWithin = 7 * 24 * time.Hour
	// StallAfter is how long a session file must lag before it notifies.
	StallAfter = 15 * time.Minute
)

// BudgetNotice is one org budget threshold crossing (budgetwarnfile.Notice).
type BudgetNotice struct {
	ID        string
	Window    string
	Subject   string
	Threshold float64
	Ratio     float64
	Level     string // "warning" | "exceeded" (budgetwarn levels)
	Message   string // already rendered in the developer cost display
	CrossedAt time.Time
}

// MonthlyBudget is one scope of the node's own monthly budget (/api/budget).
type MonthlyBudget struct {
	Month     string // YYYY-MM
	Root      string // "" = the global budget
	Pct       float64
	Threshold string // "" | "warn80" | "over100"
}

// Grant is one cached org access grant with its honour state now.
type Grant struct {
	ID        int64
	Type      string
	Target    string
	RuleID    string
	RequestID int64
	StartsAt  time.Time
	ExpiresAt time.Time // zero = perpetual
	Honoured  bool
	Reason    string // why not honoured
}

// QueuedRequest is one access request waiting in the outbox.
type QueuedRequest struct {
	ID          int64
	CreatedAt   time.Time
	Attempts    int64
	LastError   string
	LastAttempt time.Time
}

// GuardBlock is the store's per-(rule, decision, day) aggregate of enforced
// denials and asks.
type GuardBlock struct {
	RuleID   string
	Decision string // "deny" | "ask"
	Day      string // YYYY-MM-DD (UTC) of the events
	Count    int
	Last     time.Time
}

// HeldPrompt is a prompt the prompt guard held until an identical resend.
type HeldPrompt struct {
	Fingerprint string
	SessionID   string
	Detectors   string
	WarnedAt    time.Time
	ExpiresAt   time.Time
}

// CacheWarning is one critical cache-expiry warning (cachewarm severity
// "critical").
type CacheWarning struct {
	SessionID       string
	Model           string
	ExpiresAt       time.Time
	SecondsToExpiry int64
	ValueAtRiskUSD  float64
	Estimated       bool
}

// UpdateFacts is the node's update posture (/api/update/status).
type UpdateFacts struct {
	Enabled       bool
	State         string
	TargetVersion string
	SelfApply     bool
	Advice        string
	RefusalMin    string
	RefusalMsg    string
}

// UpdateEvent is one update_events row.
type UpdateEvent struct {
	ID        int64
	At        time.Time
	ToVersion string
	State     string
}

// Announcement is one live announcement (release or org rail).
type Announcement struct {
	ID       string
	Severity string // announce.Severity: info | notice | critical
	Title    string
	Body     string
	Source   string // release | org
}

// PolicyChange is one org policy family whose accepted version moved.
type PolicyChange struct {
	Family    string
	Version   int64
	UpdatedAt time.Time
}

// IngestFacts is the watcher's lag picture.
type IngestFacts struct {
	BehindFiles         int
	BehindBytes         int64
	OldestBehindSeconds int64
}

// OrgMessageThread is one conversation with the org's admins that holds an
// unread or unacknowledged admin message (internal/store, node-local).
type OrgMessageThread struct {
	ThreadID string
	Subject  string
	// Kind is the thread's message kind: note | coaching | alert.
	Kind string
	// NewestID / NewestAuthor / NewestAt describe the newest admin message.
	NewestID     int64
	NewestAuthor string
	NewestAt     time.Time
	Unread       int
	NeedsAck     int
}

// OrgMessageUnsent is one reply or new conversation the org refused, or
// that has not reached it after retries.
type OrgMessageUnsent struct {
	ID        string
	ThreadID  string
	Subject   string // a new conversation's subject ("" for a reply)
	Failed    bool   // refused on its merits (not retried until the developer acts)
	Attempts  int
	LastError string
	At        time.Time
}

// Input is every fact Build reads. Zero values mean "nothing to say".
type Input struct {
	Now time.Time
	// Hidden is the set of dashboard sections the organization hid on this
	// machine: nav section ids ("security", "cost") and Settings subsections
	// as "settings#<id>" ("settings#health"). nil = nothing hidden.
	Hidden map[string]bool

	OrgBudget      []BudgetNotice
	MonthlyBudgets []MonthlyBudget
	Grants         []Grant
	Queued         []QueuedRequest
	GuardBlocks    []GuardBlock
	HeldPrompts    []HeldPrompt
	CacheCritical  []CacheWarning
	Update         *UpdateFacts
	UpdateEvents   []UpdateEvent
	Announcements  []Announcement
	PolicyChanges  []PolicyChange
	Ingest         *IngestFacts
	// OrgMessages are the conversations with unread admin messages;
	// OrgMessagesUnsent the developer's posts that did not reach the org.
	OrgMessages       []OrgMessageThread
	OrgMessagesUnsent []OrgMessageUnsent
	// OrgMessagesAlertsOnly is the developer's [messages].alerts_only: the
	// bell (a push surface) then shows alert conversations only. The
	// Messages page itself always lists everything.
	OrgMessagesAlertsOnly bool
}

// Rule is one row of the table: its kind, the section that owns it ("" =
// never hidden: the surface behind it is cross-cutting, like its banner) and
// the builder.
type Rule struct {
	Kind    Kind
	Section string
	Build   func(in Input) []Notification
}

// Rules is THE table (CLAUDE.md #5), walked top-down by Build.
var Rules = []Rule{
	{KindOrgBudget, "", buildOrgBudget},
	{KindMonthlyBudget, "cost", buildMonthlyBudget},
	{KindGrantActive, "requests", buildGrantActive},
	{KindGrantExpiring, "requests", buildGrantExpiring},
	{KindGrantInactive, "requests", buildGrantInactive},
	{KindRequestUnsent, "requests", buildRequestUnsent},
	{KindGuardBlocked, "security", buildGuardBlocked},
	{KindPromptHeld, "security", buildPromptHeld},
	{KindCacheExpiring, "cache", buildCacheExpiring},
	{KindUpdate, "settings", buildUpdate},
	{KindUpdateApplied, "settings", buildUpdateApplied},
	{KindOrgAnnouncement, "", buildAnnouncements},
	{KindOrgPolicy, "", buildPolicyChanges},
	{KindIngestStall, "", buildIngestStall},
	{KindOrgMessage, "messages", buildOrgMessages},
}

// Build returns the notifications for in, most urgent first (severity, then
// newest), with every hidden section's rules skipped and every link into a
// hidden page dropped.
func Build(in Input) []Notification {
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}
	out := []Notification{}
	for _, r := range Rules {
		if r.Section != "" && hidden(in.Hidden, r.Section) {
			continue
		}
		for _, n := range r.Build(in) {
			n.Kind = r.Kind
			if n.Section == "" {
				n.Section = r.Section
			}
			if n.Link != "" && !linkVisible(in.Hidden, n.Link) {
				n.Link = ""
			}
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.rank() != out[j].Severity.rank() {
			return out[i].Severity.rank() < out[j].Severity.rank()
		}
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// hidden reports whether section (a nav id or "settings#<id>") is hidden; a
// Settings subsection is hidden with its page too.
func hidden(h map[string]bool, section string) bool {
	if len(h) == 0 {
		return false
	}
	if h[section] {
		return true
	}
	page, _, _ := strings.Cut(section, "#")
	return h[page]
}

// linkVisible maps a dashboard link to its section ("/settings?section=health"
// -> "settings#health", "/requests?new=x" -> "requests") and checks it.
func linkVisible(h map[string]bool, link string) bool {
	path, query, _ := strings.Cut(link, "?")
	page := strings.TrimPrefix(path, "/")
	if i := strings.IndexByte(page, '/'); i >= 0 {
		page = page[:i]
	}
	if page == "" {
		page = "overview"
	}
	section := page
	if page == "settings" {
		for _, kv := range strings.Split(query, "&") {
			if v, ok := strings.CutPrefix(kv, "section="); ok && v != "" {
				section = "settings#" + v
			}
		}
	}
	return !hidden(h, section)
}

func pct(f float64) string { return fmt.Sprintf("%d%%", int(f*100+0.5)) }

func buildOrgBudget(in Input) []Notification {
	out := []Notification{}
	for _, b := range in.OrgBudget {
		sev := SeverityWarn
		if b.Level == "exceeded" || b.Threshold >= 1 {
			sev = SeverityCritical
		}
		title := "Org budget at " + pct(b.Ratio)
		if b.Threshold >= 1 {
			title = "Org budget reached"
		}
		out = append(out, Notification{
			ID: "org_budget:" + b.ID, Severity: sev, Title: title, Body: b.Message,
			Link: "/requests?new=budget", At: b.CrossedAt,
		})
	}
	return out
}

func buildMonthlyBudget(in Input) []Notification {
	out := []Notification{}
	for _, m := range in.MonthlyBudgets {
		if m.Threshold != "warn80" && m.Threshold != "over100" {
			continue
		}
		scope := "Monthly budget"
		key := "global"
		if m.Root != "" {
			scope = "Monthly budget for " + lastSegment(m.Root)
			key = m.Root
		}
		sev, title := SeverityWarn, fmt.Sprintf("%s at %d%%", scope, int(m.Pct+0.5))
		if m.Threshold == "over100" {
			sev, title = SeverityCritical, scope+" exceeded"
		}
		out = append(out, Notification{
			ID: "monthly_budget:" + m.Month + ":" + key + ":" + m.Threshold, Severity: sev, Title: title,
			Body: "Advisory only: budgets never block traffic.", Link: "/cost", At: in.Now,
		})
	}
	return out
}

func grantLabel(g Grant) string {
	what := strings.ReplaceAll(g.Type, "_", " ")
	switch {
	case g.RuleID != "":
		what += " for " + g.RuleID
	case g.Target != "":
		what += " for " + g.Target
	}
	return what
}

func buildGrantActive(in Input) []Notification {
	out := []Notification{}
	for _, g := range in.Grants {
		if !g.Honoured {
			continue
		}
		title := "Access granted: " + grantLabel(g)
		if g.RequestID > 0 {
			title = fmt.Sprintf("Request #%d approved: %s", g.RequestID, grantLabel(g))
		}
		body := "No expiry."
		if !g.ExpiresAt.IsZero() {
			body = "Expires " + g.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + "."
		}
		at := g.StartsAt
		if at.IsZero() {
			at = in.Now
		}
		out = append(out, Notification{
			ID: fmt.Sprintf("grant:%d", g.ID), Severity: SeverityInfo, Title: title, Body: body,
			Link: "/requests", At: at,
		})
	}
	return out
}

func buildGrantExpiring(in Input) []Notification {
	out := []Notification{}
	for _, g := range in.Grants {
		if !g.Honoured || g.ExpiresAt.IsZero() {
			continue
		}
		left := g.ExpiresAt.Sub(in.Now)
		if left <= 0 || left > ExpiringWithin {
			continue
		}
		out = append(out, Notification{
			ID: fmt.Sprintf("grant_expiring:%d", g.ID), Severity: SeverityWarn,
			Title: "Access expires soon: " + grantLabel(g),
			Body:  "Expires " + g.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + ". Ask again from Requests if you still need it.",
			Link:  "/requests", At: in.Now,
		})
	}
	return out
}

func buildGrantInactive(in Input) []Notification {
	out := []Notification{}
	for _, g := range in.Grants {
		if g.Honoured {
			continue
		}
		reason := strings.ReplaceAll(g.Reason, "_", " ")
		if reason == "" {
			reason = "not in force"
		}
		out = append(out, Notification{
			ID: fmt.Sprintf("grant_inactive:%d:%s", g.ID, g.Reason), Severity: SeverityWarn,
			Title: "Access no longer applies: " + grantLabel(g),
			Body:  "Reason: " + reason + ".", Link: "/requests", At: in.Now,
		})
	}
	return out
}

func buildRequestUnsent(in Input) []Notification {
	out := []Notification{}
	for _, q := range in.Queued {
		if q.LastError == "" {
			continue
		}
		at := q.LastAttempt
		if at.IsZero() {
			at = q.CreatedAt
		}
		out = append(out, Notification{
			ID: fmt.Sprintf("request_unsent:%d", q.ID), Severity: SeverityWarn,
			Title: "An access request has not reached your org",
			Body:  fmt.Sprintf("%d attempt(s); it is retried automatically. Last error: %s", q.Attempts, truncate(q.LastError, 160)),
			Link:  "/requests", At: at,
		})
	}
	return out
}

func buildGuardBlocked(in Input) []Notification {
	out := []Notification{}
	for _, b := range in.GuardBlocks {
		if b.Count <= 0 {
			continue
		}
		verb, sev := "blocked", SeverityWarn
		if b.Decision == "ask" {
			verb, sev = "asked about", SeverityInfo
		}
		calls := "tool call"
		if b.Count != 1 {
			calls = "tool calls"
		}
		out = append(out, Notification{
			ID: "guard:" + b.RuleID + ":" + b.Decision + ":" + b.Day, Severity: sev,
			Title: fmt.Sprintf("Guard %s %d %s (%s)", verb, b.Count, calls, b.RuleID),
			Body:  "Review the events on the Security page; ask your org for an exception from Requests if the rule is in your way.",
			Link:  "/security", At: b.Last,
		})
	}
	return out
}

func buildPromptHeld(in Input) []Notification {
	out := []Notification{}
	for _, p := range in.HeldPrompts {
		if !p.ExpiresAt.IsZero() && !in.Now.Before(p.ExpiresAt) {
			continue
		}
		out = append(out, Notification{
			ID: "prompt_held:" + p.Fingerprint, Severity: SeverityWarn,
			Title: "A prompt is waiting for your confirmation",
			Body:  "The prompt guard held a prompt (" + p.Detectors + "). Send the same prompt again to confirm it, or edit it.",
			Link:  "/security", At: p.WarnedAt,
		})
	}
	return out
}

func buildCacheExpiring(in Input) []Notification {
	out := []Notification{}
	for _, c := range in.CacheCritical {
		if c.SecondsToExpiry < 0 {
			continue
		}
		usd := c.ValueAtRiskUSD
		approx := ""
		if c.Estimated {
			approx = "about "
		}
		out = append(out, Notification{
			ID:       fmt.Sprintf("cache:%s:%s:%d", c.SessionID, c.Model, c.ExpiresAt.Unix()),
			Severity: SeverityWarn,
			Title:    "Prompt cache expires in " + approx + humanSeconds(c.SecondsToExpiry),
			Body:     c.Model + " cache for session " + shortID(c.SessionID) + ". The next turn after expiry pays to rebuild it.",
			Link:     "/cache", At: in.Now, USD: &usd,
		})
	}
	return out
}

func buildUpdate(in Input) []Notification {
	u := in.Update
	if u == nil || !u.Enabled {
		return nil
	}
	if u.RefusalMin != "" || u.RefusalMsg != "" {
		body := u.RefusalMsg
		if u.RefusalMin != "" {
			body = "Your org requires observer " + u.RefusalMin + " or newer and is refusing this node's data until it is updated."
		}
		return []Notification{{
			ID: "update_refused:" + u.RefusalMin, Severity: SeverityCritical,
			Title: "Not sharing with your org", Body: body, Link: "/settings?section=health", At: in.Now,
		}}
	}
	target := u.TargetVersion
	switch {
	case u.State == "blocked" && !u.SelfApply:
		return []Notification{{
			ID: "update:blocked:" + target, Severity: SeverityWarn, Title: "Update needs you",
			Body: strings.TrimSpace("Your org published " + orDefault(target, "an update") + ". " + u.Advice),
			Link: "/settings?section=health", At: in.Now,
		}}
	case u.State == "failed" || u.State == "rolled_back":
		title := "Update failed"
		if u.State == "rolled_back" {
			title = "Update rolled back"
		}
		return []Notification{{
			ID: "update:" + u.State + ":" + target, Severity: SeverityWarn, Title: title,
			Body: "This node is still running its previous version.", Link: "/settings?section=health", At: in.Now,
		}}
	case u.State == "available":
		return []Notification{{
			ID: "update:available:" + target, Severity: SeverityInfo, Title: "Update available: " + orDefault(target, "a new version"),
			Link: "/settings?section=health", At: in.Now,
		}}
	}
	return nil
}

func buildUpdateApplied(in Input) []Notification {
	out := []Notification{}
	for _, e := range in.UpdateEvents {
		if e.State != "applied" || in.Now.Sub(e.At) > RecentWithin {
			continue
		}
		out = append(out, Notification{
			ID: fmt.Sprintf("update_applied:%d", e.ID), Severity: SeverityInfo,
			Title: "Updated to " + orDefault(e.ToVersion, "a new version"), Link: "/settings?section=health", At: e.At,
		})
	}
	return out
}

func buildAnnouncements(in Input) []Notification {
	out := []Notification{}
	for _, a := range in.Announcements {
		sev := SeverityInfo
		switch a.Severity {
		case "critical":
			sev = SeverityCritical
		case "notice":
			sev = SeverityWarn
		}
		title := a.Title
		if a.Source == "org" {
			title = "From your org: " + a.Title
		}
		out = append(out, Notification{
			ID: "announce:" + a.ID, Severity: sev, Title: title, Body: truncate(a.Body, 280), At: in.Now,
		})
	}
	return out
}

func buildPolicyChanges(in Input) []Notification {
	out := []Notification{}
	for _, p := range in.PolicyChanges {
		if p.UpdatedAt.IsZero() || in.Now.Sub(p.UpdatedAt) > RecentWithin {
			continue
		}
		out = append(out, Notification{
			ID: fmt.Sprintf("policy:%s:%d", p.Family, p.Version), Severity: SeverityInfo,
			Title: "Your org updated the " + policyLabel(p.Family) + " policy",
			Body:  fmt.Sprintf("Version %d is now applied on this machine.", p.Version),
			Link:  "/settings?section=enrolment", At: p.UpdatedAt,
		})
	}
	return out
}

func buildIngestStall(in Input) []Notification {
	g := in.Ingest
	if g == nil || g.BehindFiles == 0 || time.Duration(g.OldestBehindSeconds)*time.Second < StallAfter {
		return nil
	}
	files := "file is"
	if g.BehindFiles != 1 {
		files = "files are"
	}
	return []Notification{{
		ID: "ingest_stall:" + in.Now.UTC().Format("2006-01-02"), Severity: SeverityWarn,
		Title: fmt.Sprintf("%d session %s behind", g.BehindFiles, files),
		Body:  "Capture is lagging by " + humanSeconds(g.OldestBehindSeconds) + "; recent activity may be missing from the dashboard.",
		Link:  "/settings?section=health", At: in.Now,
	}}
}

// orgMessageSeverity maps a message kind onto the bell tier: an alert is
// critical, a message waiting for an acknowledgement is a warning, the rest
// is information. An unknown kind (a newer org) reads as a note.
func orgMessageSeverity(kind string, needsAck bool) Severity {
	switch {
	case kind == "alert":
		return SeverityCritical
	case needsAck:
		return SeverityWarn
	default:
		return SeverityInfo
	}
}

// orgMessageLink is the deep link into one conversation.
func orgMessageLink(threadID string) string { return "/messages?thread=" + threadID }

func buildOrgMessages(in Input) []Notification {
	out := []Notification{}
	for _, m := range in.OrgMessages {
		if in.OrgMessagesAlertsOnly && m.Kind != "alert" {
			continue
		}
		author := orDefault(m.NewestAuthor, "Your admin")
		title := author + " (admin): " + orDefault(m.Subject, "a message")
		var parts []string
		if m.Unread > 1 {
			parts = append(parts, fmt.Sprintf("%d unread messages.", m.Unread))
		}
		if m.NeedsAck > 0 {
			parts = append(parts, "Your admin asked you to acknowledge this.")
		}
		at := m.NewestAt
		if at.IsZero() {
			at = in.Now
		}
		// The id carries the newest message, so a new message in the same
		// conversation notifies again while an already-read one stays read.
		out = append(out, Notification{
			ID: fmt.Sprintf("org_message:%s:%d", m.ThreadID, m.NewestID), Severity: orgMessageSeverity(m.Kind, m.NeedsAck > 0),
			Title: truncate(title, 140), Body: strings.Join(parts, " "), Link: orgMessageLink(m.ThreadID), At: at,
		})
	}
	for _, u := range in.OrgMessagesUnsent {
		if u.LastError == "" {
			continue
		}
		title := "Your reply has not reached your admins"
		if u.ThreadID == "" {
			title = "Your message has not reached your admins"
		}
		body := truncate(u.LastError, 160) + "."
		if u.Failed {
			body += " Retry or discard it from Messages."
		} else {
			body += fmt.Sprintf(" %d attempt(s); it is retried automatically.", u.Attempts)
		}
		link := "/messages"
		if u.ThreadID != "" {
			link = orgMessageLink(u.ThreadID)
		}
		out = append(out, Notification{
			ID: "org_message_unsent:" + u.ID, Severity: SeverityWarn, Title: title, Body: body, Link: link, At: u.At,
		})
	}
	return out
}

// State is the persisted read / dismiss state of one notification id.
type State struct {
	Read      bool `json:"read,omitempty"`
	Dismissed bool `json:"dismissed,omitempty"`
}

// ApplyState drops dismissed notifications and marks read ones; it returns
// the visible list and its unread count.
func ApplyState(list []Notification, states map[string]State) ([]Notification, int) {
	out := make([]Notification, 0, len(list))
	unread := 0
	for _, n := range list {
		st := states[n.ID]
		if st.Dismissed {
			continue
		}
		n.Read = st.Read
		if !n.Read {
			unread++
		}
		out = append(out, n)
	}
	return out, unread
}

// policyLabels names the org policy families a developer recognises
// (internal/policystate's closed family vocabulary).
var policyLabels = map[string]string{
	"guard.coding":             "guard",
	"routing":                  "routing",
	"routing.optimization":     "routing",
	"node.governance":          "dashboard visibility",
	"node.features":            "feature",
	"tools.mcp_access":         "MCP access",
	"admission.input":          "admission",
	"egress.routing_guardrail": "egress guardrail",
	"gateway.providers":        "gateway provider",
}

func policyLabel(family string) string {
	if l, ok := policyLabels[family]; ok {
		return l
	}
	return family
}

func lastSegment(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "..."
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func humanSeconds(sec int64) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", sec)
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
