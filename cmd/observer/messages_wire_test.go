package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
)

func TestDesktopMessageNotices(t *testing.T) {
	note := orgclient.OrgMessageNotice{ThreadID: "t1", MessageID: 1, Subject: "Model choice", AuthorName: "Asha Kim", Kind: "coaching"}
	alert := orgclient.OrgMessageNotice{ThreadID: "t2", MessageID: 2, Subject: "Stop the migration", AuthorName: "Asha Kim", Kind: "alert"}
	on := config.DefaultMessagesConfig()
	on.Desktop = true
	alertsOnly := on
	alertsOnly.AlertsOnly = true
	many := []orgclient.OrgMessageNotice{note, note, note, note, note}
	cases := []struct {
		name      string
		in        []orgclient.OrgMessageNotice
		cfg       config.MessagesConfig
		wantN     int
		wantTitle string
		wantBody  string
	}{
		{"desktop off by default", []orgclient.OrgMessageNotice{note}, config.DefaultMessagesConfig(), 0, "", ""},
		{"sender and subject only", []orgclient.OrgMessageNotice{note}, on, 1, "Message from Asha Kim (admin)", "Model choice"},
		{"an alert says so", []orgclient.OrgMessageNotice{alert}, on, 1, "Alert from Asha Kim (admin)", "Stop the migration"},
		{"alerts only drops a note", []orgclient.OrgMessageNotice{note, alert}, alertsOnly, 1, "Alert from Asha Kim (admin)", ""},
		{"a burst is folded", many, on, 3, "", ""},
		{"no sender or subject", []orgclient.OrgMessageNotice{{Kind: "note"}}, on, 1, "Message from your admin", "New message"},
	}
	for _, tc := range cases {
		got := desktopMessageNotices(tc.in, tc.cfg)
		if len(got) != tc.wantN {
			t.Fatalf("%s: %d notices, want %d (%+v)", tc.name, len(got), tc.wantN, got)
		}
		if tc.wantTitle != "" && got[0].title != tc.wantTitle {
			t.Fatalf("%s: title %q, want %q", tc.name, got[0].title, tc.wantTitle)
		}
		if tc.wantBody != "" && got[0].body != tc.wantBody {
			t.Fatalf("%s: body %q, want %q", tc.name, got[0].body, tc.wantBody)
		}
	}
	burst := desktopMessageNotices(many, on)
	if burst[2].body != "3 more messages are waiting in Observer." {
		t.Fatalf("fold = %+v", burst[2])
	}
}

func TestStatuslineMessagesUnread(t *testing.T) {
	def := config.DefaultMessagesConfig()
	off := def
	off.Statusline = false
	alerts := def
	alerts.AlertsOnly = true
	cases := []struct {
		name        string
		all, alerts int
		cfg         config.MessagesConfig
		want        int
	}{
		{"default shows every unread message", 3, 1, def, 3},
		{"statusline off hides the segment", 3, 1, off, 0},
		{"alerts only counts alerts", 3, 1, alerts, 1},
		{"nothing unread", 0, 0, def, 0},
	}
	for _, tc := range cases {
		if got := statuslineMessagesUnread(tc.all, tc.alerts, tc.cfg); got != tc.want {
			t.Fatalf("%s: %d, want %d", tc.name, got, tc.want)
		}
	}
}
