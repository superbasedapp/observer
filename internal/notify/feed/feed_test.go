package feed_test

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/notify/feed"
)

var now = time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

// TestEveryKindHasARule pins the table: one rule per kind, no duplicates.
func TestEveryKindHasARule(t *testing.T) {
	seen := map[feed.Kind]bool{}
	for _, r := range feed.Rules {
		if seen[r.Kind] {
			t.Fatalf("kind %q has two rules", r.Kind)
		}
		seen[r.Kind] = true
	}
	if len(seen) != 15 {
		t.Fatalf("rules cover %d kinds, want 15", len(seen))
	}
}

// TestBuildPerKind is the aggregation table: one case per event kind, each
// asserting the id, severity, a title fragment and the link.
func TestBuildPerKind(t *testing.T) {
	cases := []struct {
		name     string
		in       feed.Input
		wantID   string
		wantSev  feed.Severity
		wantText string
		wantLink string
		wantNone bool
	}{
		{
			name:   "org budget threshold",
			in:     feed.Input{OrgBudget: []feed.BudgetNotice{{ID: "w1|2026-10|0.8", Threshold: 0.8, Ratio: 0.82, Level: "warning", Message: "82% of your monthly cap", CrossedAt: now}}},
			wantID: "org_budget:w1|2026-10|0.8", wantSev: feed.SeverityWarn, wantText: "Org budget at 82%", wantLink: "/requests?new=budget",
		},
		{
			name:   "org budget cap reached is critical",
			in:     feed.Input{OrgBudget: []feed.BudgetNotice{{ID: "w1|2026-10|1", Threshold: 1, Ratio: 1.02, CrossedAt: now}}},
			wantID: "org_budget:w1|2026-10|1", wantSev: feed.SeverityCritical, wantText: "Org budget reached",
		},
		{
			name:   "monthly budget at 80%",
			in:     feed.Input{MonthlyBudgets: []feed.MonthlyBudget{{Month: "2026-10", Pct: 84, Threshold: "warn80"}}},
			wantID: "monthly_budget:2026-10:global:warn80", wantSev: feed.SeverityWarn, wantText: "Monthly budget at 84%", wantLink: "/cost",
		},
		{
			name:     "monthly budget under 80% is silent",
			in:       feed.Input{MonthlyBudgets: []feed.MonthlyBudget{{Month: "2026-10", Pct: 40}}},
			wantNone: true,
		},
		{
			name:   "grant from an approved request",
			in:     feed.Input{Grants: []feed.Grant{{ID: 7, Type: "guard_exemption", RuleID: "R-101", RequestID: 3, Honoured: true, StartsAt: now.Add(-time.Hour)}}},
			wantID: "grant:7", wantSev: feed.SeverityInfo, wantText: "Request #3 approved: guard exemption for R-101", wantLink: "/requests",
		},
		{
			name: "grant expiring within a day",
			in:   feed.Input{Grants: []feed.Grant{{ID: 8, Type: "model_access", Target: "claude-opus-4-7", Honoured: true, ExpiresAt: now.Add(3 * time.Hour)}}},
			// The expiring row sorts first (warn above info).
			wantID: "grant_expiring:8", wantSev: feed.SeverityWarn, wantText: "Access expires soon: model access for claude-opus-4-7",
		},
		{
			name:   "grant no longer honoured",
			in:     feed.Input{Grants: []feed.Grant{{ID: 9, Type: "budget_increase", Honoured: false, Reason: "expired"}}},
			wantID: "grant_inactive:9:expired", wantSev: feed.SeverityWarn, wantText: "Access no longer applies",
		},
		{
			name:   "queued request that failed to send",
			in:     feed.Input{Queued: []feed.QueuedRequest{{ID: 4, Attempts: 2, LastError: "dial tcp: refused", LastAttempt: now}}},
			wantID: "request_unsent:4", wantSev: feed.SeverityWarn, wantText: "has not reached your org",
		},
		{
			name:     "queued request without an error is silent",
			in:       feed.Input{Queued: []feed.QueuedRequest{{ID: 5}}},
			wantNone: true,
		},
		{
			name:   "guard denials",
			in:     feed.Input{GuardBlocks: []feed.GuardBlock{{RuleID: "R-101", Decision: "deny", Day: "2026-10-06", Count: 3, Last: now}}},
			wantID: "guard:R-101:deny:2026-10-06", wantSev: feed.SeverityWarn, wantText: "Guard blocked 3 tool calls (R-101)", wantLink: "/security",
		},
		{
			name:   "prompt held for confirmation",
			in:     feed.Input{HeldPrompts: []feed.HeldPrompt{{Fingerprint: "abc", Detectors: "aws_key", WarnedAt: now, ExpiresAt: now.Add(time.Hour)}}},
			wantID: "prompt_held:abc", wantSev: feed.SeverityWarn, wantText: "waiting for your confirmation",
		},
		{
			name:     "an expired held prompt is silent",
			in:       feed.Input{HeldPrompts: []feed.HeldPrompt{{Fingerprint: "old", WarnedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}}},
			wantNone: true,
		},
		{
			name:   "critical cache expiry",
			in:     feed.Input{CacheCritical: []feed.CacheWarning{{SessionID: "sess-123456789", Model: "claude-opus-4-7", ExpiresAt: now.Add(90 * time.Second), SecondsToExpiry: 90, ValueAtRiskUSD: 0.42}}},
			wantID: "cache:sess-123456789:claude-opus-4-7:" + itoa(now.Add(90*time.Second).Unix()), wantSev: feed.SeverityWarn, wantText: "Prompt cache expires in 1m", wantLink: "/cache",
		},
		{
			name:   "org refuses an old node",
			in:     feed.Input{Update: &feed.UpdateFacts{Enabled: true, RefusalMin: "1.35.0"}},
			wantID: "update_refused:1.35.0", wantSev: feed.SeverityCritical, wantText: "Not sharing with your org", wantLink: "/settings?section=health",
		},
		{
			name:   "update available",
			in:     feed.Input{Update: &feed.UpdateFacts{Enabled: true, State: "available", TargetVersion: "1.35.0"}},
			wantID: "update:available:1.35.0", wantSev: feed.SeverityInfo, wantText: "Update available: 1.35.0",
		},
		{
			name:     "update management off is silent",
			in:       feed.Input{Update: &feed.UpdateFacts{Enabled: false, State: "available"}},
			wantNone: true,
		},
		{
			name:   "update applied this week",
			in:     feed.Input{UpdateEvents: []feed.UpdateEvent{{ID: 11, At: now.Add(-time.Hour), ToVersion: "1.34.1", State: "applied"}}},
			wantID: "update_applied:11", wantSev: feed.SeverityInfo, wantText: "Updated to 1.34.1",
		},
		{
			name:   "org announcement",
			in:     feed.Input{Announcements: []feed.Announcement{{ID: "a1", Severity: "notice", Title: "Maintenance tonight", Source: "org"}}},
			wantID: "announce:a1", wantSev: feed.SeverityWarn, wantText: "From your org: Maintenance tonight",
		},
		{
			name:   "org policy change",
			in:     feed.Input{PolicyChanges: []feed.PolicyChange{{Family: "guard.coding", Version: 4, UpdatedAt: now.Add(-time.Hour)}}},
			wantID: "policy:guard.coding:4", wantSev: feed.SeverityInfo, wantText: "Your org updated the guard policy", wantLink: "/settings?section=enrolment",
		},
		{
			name:     "an old policy change is silent",
			in:       feed.Input{PolicyChanges: []feed.PolicyChange{{Family: "guard.coding", Version: 3, UpdatedAt: now.Add(-30 * 24 * time.Hour)}}},
			wantNone: true,
		},
		{
			name:   "ingest stall",
			in:     feed.Input{Ingest: &feed.IngestFacts{BehindFiles: 2, BehindBytes: 4096, OldestBehindSeconds: 3600}},
			wantID: "ingest_stall:2026-10-06", wantSev: feed.SeverityWarn, wantText: "2 session files are behind",
		},
		{
			name:     "a short lag is not a stall",
			in:       feed.Input{Ingest: &feed.IngestFacts{BehindFiles: 1, OldestBehindSeconds: 30}},
			wantNone: true,
		},
		{
			name: "a coaching message from an admin",
			in: feed.Input{OrgMessages: []feed.OrgMessageThread{{
				ThreadID: "th-1", Subject: "Model choice", Kind: "coaching", NewestID: 12, NewestAuthor: "Asha Kim", NewestAt: now, Unread: 1,
			}}},
			wantID: "org_message:th-1:12", wantSev: feed.SeverityInfo, wantText: "Asha Kim (admin): Model choice", wantLink: "/messages?thread=th-1",
		},
		{
			name: "an alert is critical",
			in: feed.Input{OrgMessages: []feed.OrgMessageThread{{
				ThreadID: "th-2", Subject: "Stop the migration", Kind: "alert", NewestID: 13, NewestAuthor: "Asha Kim", NewestAt: now, Unread: 1, NeedsAck: 1,
			}}},
			wantID: "org_message:th-2:13", wantSev: feed.SeverityCritical, wantText: "Asha Kim (admin): Stop the migration", wantLink: "/messages?thread=th-2",
		},
		{
			name: "a note waiting for an acknowledgement is a warning",
			in: feed.Input{OrgMessages: []feed.OrgMessageThread{{
				ThreadID: "th-3", Subject: "Policy change", Kind: "note", NewestID: 14, NewestAuthor: "Ravi Rao", NewestAt: now, NeedsAck: 1,
			}}},
			wantID: "org_message:th-3:14", wantSev: feed.SeverityWarn, wantText: "Ravi Rao (admin): Policy change",
		},
		{
			name: "alerts only mutes a note in the bell",
			in: feed.Input{OrgMessagesAlertsOnly: true, OrgMessages: []feed.OrgMessageThread{{
				ThreadID: "th-4", Subject: "FYI", Kind: "note", NewestID: 15, NewestAuthor: "Asha Kim", NewestAt: now, Unread: 1,
			}}},
			wantNone: true,
		},
		{
			name: "alerts only keeps an alert",
			in: feed.Input{OrgMessagesAlertsOnly: true, OrgMessages: []feed.OrgMessageThread{{
				ThreadID: "th-5", Subject: "Urgent", Kind: "alert", NewestID: 16, NewestAuthor: "Asha Kim", NewestAt: now, Unread: 1,
			}}},
			wantID: "org_message:th-5:16", wantSev: feed.SeverityCritical, wantText: "Urgent",
		},
		{
			name:   "a refused reply",
			in:     feed.Input{OrgMessagesUnsent: []feed.OrgMessageUnsent{{ID: "c-1", ThreadID: "th-1", Failed: true, LastError: "this conversation was closed by your admin", At: now}}},
			wantID: "org_message_unsent:c-1", wantSev: feed.SeverityWarn, wantText: "Your reply has not reached your admins", wantLink: "/messages?thread=th-1",
		},
		{
			name:   "a new conversation still queued",
			in:     feed.Input{OrgMessagesUnsent: []feed.OrgMessageUnsent{{ID: "c-2", Subject: "Budget", Attempts: 3, LastError: "your organization could not be reached", At: now}}},
			wantID: "org_message_unsent:c-2", wantSev: feed.SeverityWarn, wantText: "Your message has not reached your admins", wantLink: "/messages",
		},
		{
			name:     "a queued post that has not been tried is silent",
			in:       feed.Input{OrgMessagesUnsent: []feed.OrgMessageUnsent{{ID: "c-3", ThreadID: "th-1"}}},
			wantNone: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Now = now
			got := feed.Build(tc.in)
			if tc.wantNone {
				if len(got) != 0 {
					t.Fatalf("got %+v, want nothing", got)
				}
				return
			}
			if len(got) == 0 {
				t.Fatal("no notification")
			}
			n := got[0]
			if n.ID != tc.wantID || n.Severity != tc.wantSev || !strings.Contains(n.Title, tc.wantText) {
				t.Fatalf("got %s %s %q, want %s %s containing %q", n.ID, n.Severity, n.Title, tc.wantID, tc.wantSev, tc.wantText)
			}
			if tc.wantLink != "" && n.Link != tc.wantLink {
				t.Fatalf("link %q, want %q", n.Link, tc.wantLink)
			}
			if strings.Contains(n.Title+n.Body, "$") {
				t.Fatalf("money rendered into text: %q / %q", n.Title, n.Body)
			}
		})
	}
}

// TestHiddenSectionYieldsNothing: a section the org hid produces no
// notification, a Settings subsection hides its rules' links, and a hidden
// page's links are dropped from notifications other sections own.
func TestHiddenSectionYieldsNothing(t *testing.T) {
	in := feed.Input{
		Now:         now,
		GuardBlocks: []feed.GuardBlock{{RuleID: "R-1", Decision: "deny", Day: "2026-10-06", Count: 1, Last: now}},
		Grants:      []feed.Grant{{ID: 1, Type: "x", Honoured: true}},
		OrgBudget:   []feed.BudgetNotice{{ID: "b", Threshold: 0.8, Ratio: 0.8, CrossedAt: now}},
		Update:      &feed.UpdateFacts{Enabled: true, State: "available", TargetVersion: "2"},
		Ingest:      &feed.IngestFacts{BehindFiles: 1, OldestBehindSeconds: 3600},
	}
	all := ids(feed.Build(in))
	for _, want := range []string{"guard:R-1:deny:2026-10-06", "grant:1", "org_budget:b", "update:available:2", "ingest_stall:2026-10-06"} {
		if !all[want] {
			t.Fatalf("baseline missing %s: %v", want, all)
		}
	}
	in.Hidden = map[string]bool{"security": true, "requests": true, "settings#health": true}
	got := feed.Build(in)
	have := ids(got)
	if have["guard:R-1:deny:2026-10-06"] || have["grant:1"] {
		t.Fatalf("hidden sections still notify: %v", have)
	}
	// The org budget notice is cross-cutting (like its banner) and stays,
	// but its link into the hidden Requests page is dropped; the ingest
	// stall's link into the hidden Settings > Health subsection likewise.
	for _, n := range got {
		if n.ID == "org_budget:b" && n.Link != "" {
			t.Fatalf("link into a hidden page kept: %q", n.Link)
		}
		if n.ID == "ingest_stall:2026-10-06" && n.Link != "" {
			t.Fatalf("link into a hidden settings section kept: %q", n.Link)
		}
	}
	// Hiding the whole Settings page removes the update rules entirely.
	in.Hidden = map[string]bool{"settings": true}
	if ids(feed.Build(in))["update:available:2"] {
		t.Fatal("update notification survives a hidden Settings page")
	}
}

func TestOrderAndState(t *testing.T) {
	in := feed.Input{
		Now:           now,
		Announcements: []feed.Announcement{{ID: "i", Severity: "info", Title: "info"}},
		Update:        &feed.UpdateFacts{Enabled: true, RefusalMin: "9"},
		GuardBlocks:   []feed.GuardBlock{{RuleID: "R", Decision: "deny", Day: "d", Count: 1, Last: now}},
	}
	got := feed.Build(in)
	if got[0].Severity != feed.SeverityCritical || got[len(got)-1].Severity != feed.SeverityInfo {
		t.Fatalf("not most-urgent-first: %+v", got)
	}
	visible, unread := feed.ApplyState(got, map[string]feed.State{
		"announce:i":       {Dismissed: true},
		"guard:R:deny:d":   {Read: true},
		"update_refused:9": {},
	})
	if len(visible) != 2 || unread != 1 {
		t.Fatalf("visible %d unread %d, want 2 and 1", len(visible), unread)
	}
	for _, n := range visible {
		if n.ID == "guard:R:deny:d" && !n.Read {
			t.Fatal("read state not applied")
		}
	}
}

func ids(list []feed.Notification) map[string]bool {
	out := map[string]bool{}
	for _, n := range list {
		out[n.ID] = true
	}
	return out
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
