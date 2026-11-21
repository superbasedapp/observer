package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
)

// TestCloudAgentsCLI_DevinUserLines: a Devin account with no user chosen says
// nothing was pulled and names the command that picks one (no dead end); a
// chosen one prints the user and the removal still owed; skipped sessions are
// counted, never described; the picker prints numbered, sanitized choices and
// the command to record one.
func TestCloudAgentsCLI_DevinUserLines(t *testing.T) {
	const me = "user-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		name    string
		print   func(*bytes.Buffer)
		want    []string
		mustNot []string
	}{
		{
			name: "sync with no user chosen",
			print: func(b *bytes.Buffer) {
				printSyncResult(b, cloudagentssvc.SyncResult{AccountID: 4, Connector: cloudagents.ConnectorDevin, UserState: cloudagents.VendorUserNotChosen})
			},
			want:    []string{"no user chosen, nothing pulled", "observer cloud-agents choose-user 4"},
			mustNot: []string{"task(s) in"},
		},
		{
			name: "sync skips and purge",
			print: func(b *bytes.Buffer) {
				printSyncResult(b, cloudagentssvc.SyncResult{
					AccountID: 4, Connector: cloudagents.ConnectorDevin, UserState: cloudagents.VendorUserChosen,
					Tasks: 1, Pages: 1, SkippedOtherMember: 3, SkippedServiceUser: 1, PurgedOtherMember: 2,
				})
			},
			want: []string{"4 session(s) not yours skipped (3 another member's, 1 a service user's, 0 naming no user)", "2 session(s) pulled earlier"},
		},
		{
			name: "status, not chosen",
			print: func(b *bytes.Buffer) {
				printVendorUser(b, cloudagentssvc.AccountView{ID: 4, UserState: cloudagents.VendorUserNotChosen}, "Devin user")
			},
			want: []string{"not chosen: nothing is pulled", "choose-user 4"},
		},
		{
			name: "status, chosen with removal owed",
			print: func(b *bytes.Buffer) {
				printVendorUser(b, cloudagentssvc.AccountView{ID: 4, UserState: cloudagents.VendorUserChosen, VendorUser: me, PurgePending: true}, "Devin user")
			},
			want: []string{me, "next pass removes"},
		},
		{
			name: "status, another connector",
			print: func(b *bytes.Buffer) {
				printVendorUser(b, cloudagentssvc.AccountView{ID: 1}, "")
			},
			mustNot: []string{"user"},
		},
		{
			name: "picker",
			print: func(b *bytes.Buffer) {
				printUserCandidates(b, cloudagentssvc.UserCandidates{
					AccountID: 4, Connector: cloudagents.ConnectorDevin, UserLabel: "Devin user", Chosen: me,
					Candidates:          []cloudagents.VendorUserCandidate{{UserID: me, Username: "me\x1b[31m", Sessions: 2}, {UserID: "user-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Sessions: 1}},
					ServiceUserSessions: 1,
				})
			},
			want:    []string{"1) " + me, "me?[31m, 2 session(s)  (chosen)", "2) user-bbbb", "name not read", "1 session(s) started by a service user", "choose-user 4 <number>"},
			mustNot: []string{"\x1b"},
		},
		{
			// CA-T8: the same picker for a Warp and an OpenHands account.
			name: "warp picker",
			print: func(b *bytes.Buffer) {
				printUserCandidates(b, cloudagentssvc.UserCandidates{
					AccountID: 7, Connector: cloudagents.ConnectorWarpCloud, UserLabel: "Warp user",
					Candidates:          []cloudagents.VendorUserCandidate{{UserID: "synthUserUid0001", Username: "Synthetic User", Sessions: 3}},
					ServiceUserSessions: 2, NoUserSessions: 1, More: true,
				})
			},
			want: []string{
				"Warp users with sessions this key can see (account 7)", "1) synthUserUid0001  Synthetic User, 3 session(s)",
				"2 session(s) started by a service user or service account: never pulled", "1 session(s) naming no person", "first page only", "choose-user 7 <number>",
			},
			mustNot: []string{"organization"},
		},
		{
			name: "openhands picker, nobody named",
			print: func(b *bytes.Buffer) {
				printUserCandidates(b, cloudagentssvc.UserCandidates{AccountID: 8, Connector: cloudagents.ConnectorOpenHandsCloud, UserLabel: "OpenHands user", NoUserSessions: 2})
			},
			want:    []string{"account 8 (openhands-cloud): no session on the first page names a person", "2 session(s) naming no person"},
			mustNot: []string{"Devin", "choose-user 8 <number>"},
		},
		{
			name: "warp purge of ledger-only runs",
			print: func(b *bytes.Buffer) {
				printSyncResult(b, cloudagentssvc.SyncResult{
					AccountID: 7, Connector: cloudagents.ConnectorWarpCloud, UserState: cloudagents.VendorUserChosen,
					Pages: 1, SkippedOtherMember: 2, PurgedOtherMember: 1, PurgedLedgerOnly: 2,
				})
			},
			want: []string{"1 session(s) pulled earlier", "2 ledger row(s) of runs another member or a service account started"},
		},
		{
			name: "openhands sync with no user chosen",
			print: func(b *bytes.Buffer) {
				printSyncResult(b, cloudagentssvc.SyncResult{AccountID: 8, Connector: cloudagents.ConnectorOpenHandsCloud, UserState: cloudagents.VendorUserNotChosen})
			},
			want:    []string{"no user chosen, nothing pulled", "other people's sessions", "choose-user 8"},
			mustNot: []string{"organization"},
		},
	}
	for _, tc := range cases {
		var b bytes.Buffer
		tc.print(&b)
		out := b.String()
		for _, w := range tc.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: missing %q in %q", tc.name, w, out)
			}
		}
		for _, w := range tc.mustNot {
			if strings.Contains(out, w) {
				t.Errorf("%s: unexpected %q in %q", tc.name, w, out)
			}
		}
	}
	if !isListNumber("2") || isListNumber(me) {
		t.Error("isListNumber")
	}
	p := userChoices(cloudagentssvc.UserCandidates{UserLabel: "Devin user", Candidates: []cloudagents.VendorUserCandidate{{UserID: me, Sessions: 1}}})
	if len(p.Choices) != 1 || p.Choices[0].Value != me {
		t.Fatalf("choices = %+v", p)
	}
}
