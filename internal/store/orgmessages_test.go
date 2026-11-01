package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

var msgNow = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func msgPage(after, next int64, threads []orgcontract.OrgMessageThreadRow, msgs ...orgcontract.OrgMessageRow) OrgMessagePage {
	return OrgMessagePage{
		OrgID: "org-1", Subject: "scim-42", ExpectCursor: after, KeyFingerprint: "fp", Now: msgNow,
		Body: orgcontract.OrgMessageBody{
			Version: 3, After: after, NextAfter: next, Threads: threads, Messages: msgs,
			Policy: orgcontract.OrgMessageNodePolicy{DevThreadsAllowed: true, Topics: []string{"budget", "other"}, RetentionDays: 365},
		},
	}
}

func adminMsg(id int64, thread string, ack bool) orgcontract.OrgMessageRow {
	return orgcontract.OrgMessageRow{
		ID: id, ThreadID: thread, AuthorKind: orgcontract.OrgMessageAuthorAdmin, AuthorName: "Asha Kim",
		Body: "Please try a smaller model for routine edits.", RequireAck: ack, CreatedAt: "2026-10-15T11:00:00Z",
		Attachments: []orgcontract.OrgMessageAttachment{{Type: "model", Ref: "claude-opus-5", Label: "Opus 5"}},
	}
}

func thread(id, kind, status string) orgcontract.OrgMessageThreadRow {
	return orgcontract.OrgMessageThreadRow{ID: id, Subject: "Model choice", Kind: kind, StartedBy: "admin", Status: status, UpdatedAt: "2026-10-15T11:00:00Z"}
}

func TestSaveOrgMessagePage(t *testing.T) {
	cases := []struct {
		name         string
		pages        []OrgMessagePage
		wantErr      error
		wantCursor   int64
		wantInserted []int
		wantMessages int
	}{
		{
			name:         "first page stores threads, messages and cursor",
			pages:        []OrgMessagePage{msgPage(0, 2, []orgcontract.OrgMessageThreadRow{thread("t1", "coaching", "open")}, adminMsg(1, "t1", false), adminMsg(2, "t1", true))},
			wantCursor:   2,
			wantInserted: []int{2},
			wantMessages: 2,
		},
		{
			name: "a re-delivered page inserts nothing twice",
			pages: []OrgMessagePage{
				msgPage(0, 1, []orgcontract.OrgMessageThreadRow{thread("t1", "note", "open")}, adminMsg(1, "t1", false)),
				msgPage(1, 1, []orgcontract.OrgMessageThreadRow{thread("t1", "note", "open")}, adminMsg(1, "t1", false)),
			},
			wantCursor:   1,
			wantInserted: []int{1, 0},
			wantMessages: 1,
		},
		{
			name: "a page for a stale cursor is refused",
			pages: []OrgMessagePage{
				msgPage(0, 5, nil, adminMsg(5, "t1", false)),
				msgPage(0, 6, nil, adminMsg(6, "t1", false)),
			},
			wantErr:      ErrOrgMessageCursorMoved,
			wantCursor:   5,
			wantMessages: 1,
		},
		{
			name:         "a message without its thread header still lands",
			pages:        []OrgMessagePage{msgPage(0, 9, nil, adminMsg(9, "t9", false))},
			wantCursor:   9,
			wantInserted: []int{1},
			wantMessages: 1,
		},
		{
			name:         "next_after below the held cursor never moves it back",
			pages:        []OrgMessagePage{msgPage(0, 0, nil, adminMsg(4, "t1", false))},
			wantCursor:   4,
			wantInserted: []int{1},
			wantMessages: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			ctx := context.Background()
			var err error
			for i, p := range tc.pages {
				var res OrgMessagePageResult
				res, err = s.SaveOrgMessagePage(ctx, p)
				if err != nil {
					break
				}
				if i < len(tc.wantInserted) && len(res.Inserted) != tc.wantInserted[i] {
					t.Fatalf("page %d inserted %d, want %d", i, len(res.Inserted), tc.wantInserted[i])
				}
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			rail, ok, err := s.LoadOrgMessageRail(ctx)
			if err != nil || !ok {
				t.Fatalf("LoadOrgMessageRail: ok=%v err=%v", ok, err)
			}
			if rail.Cursor != tc.wantCursor {
				t.Fatalf("cursor = %d, want %d", rail.Cursor, tc.wantCursor)
			}
			if !rail.HavePolicy || !rail.Policy.DevThreadsAllowed || rail.FetchState != "ok" || rail.LastOKAt == "" {
				t.Fatalf("rail = %+v", rail)
			}
			var n int
			if err := s.db.QueryRow(`SELECT COUNT(*) FROM org_messages_inbox`).Scan(&n); err != nil || n != tc.wantMessages {
				t.Fatalf("messages = %d (%v), want %d", n, err, tc.wantMessages)
			}
		})
	}
}

func TestOrgMessageReadAckAndSummary(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.SaveOrgMessagePage(ctx, msgPage(0, 3, []orgcontract.OrgMessageThreadRow{
		thread("t1", "alert", "open"), thread("t2", "note", "open"),
	}, adminMsg(1, "t1", true), adminMsg(2, "t1", false), adminMsg(3, "t2", false))); err != nil {
		t.Fatal(err)
	}
	sum, err := s.OrgMessageSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Unread != 3 || sum.UnreadThreads != 2 || sum.NeedsAck != 1 || sum.UnreadAlerts != 2 {
		t.Fatalf("summary = %+v", sum)
	}
	if sum.Newest == nil || sum.Newest.MessageID != 3 || sum.NewestAlert == nil || sum.NewestAlert.MessageID != 2 {
		t.Fatalf("newest = %+v alert = %+v", sum.Newest, sum.NewestAlert)
	}

	// Reading without receipts (an individual node that switched them off)
	// marks the messages but queues nothing.
	n, err := s.MarkOrgMessageThreadRead(ctx, "t2", "org-1", false, msgNow)
	if err != nil || n != 1 {
		t.Fatalf("read t2: n=%d err=%v", n, err)
	}
	// Reading with receipts queues one per message; reading again queues none.
	if n, err := s.MarkOrgMessageThreadRead(ctx, "t1", "org-1", true, msgNow); err != nil || n != 2 {
		t.Fatalf("read t1: n=%d err=%v", n, err)
	}
	if n, err := s.MarkOrgMessageThreadRead(ctx, "t1", "org-1", true, msgNow); err != nil || n != 0 {
		t.Fatalf("read t1 again: n=%d err=%v", n, err)
	}
	if _, err := s.MarkOrgMessageThreadRead(ctx, "nope", "org-1", true, msgNow); !errors.Is(err, ErrOrgMessageNotFound) {
		t.Fatalf("unknown thread err = %v", err)
	}
	pending, err := s.PendingOrgMessageOutbox(ctx, "org-1")
	if err != nil || len(pending) != 2 {
		t.Fatalf("pending = %d (%v), want 2 read receipts", len(pending), err)
	}

	ackCases := []struct {
		id      int64
		wantErr error
	}{
		{2, ErrOrgMessageAckNotRequested},
		{99, ErrOrgMessageNotFound},
		{1, nil},
		{1, nil}, // again: a no-op
	}
	for _, c := range ackCases {
		if _, err := s.AckOrgMessage(ctx, c.id, "org-1", msgNow); !errors.Is(err, c.wantErr) {
			t.Fatalf("ack %d err = %v, want %v", c.id, err, c.wantErr)
		}
	}
	pending, _ = s.PendingOrgMessageOutbox(ctx, "org-1")
	if len(pending) != 3 {
		t.Fatalf("pending = %d, want 2 read + 1 acknowledged", len(pending))
	}
	sum, _ = s.OrgMessageSummary(ctx)
	if sum.Unread != 0 || sum.NeedsAck != 0 || sum.Newest != nil {
		t.Fatalf("summary after read and ack = %+v", sum)
	}
	// Another org's queue is never flushed to this one.
	if other, _ := s.PendingOrgMessageOutbox(ctx, "org-2"); len(other) != 0 {
		t.Fatalf("org-2 pending = %d", len(other))
	}
}

func TestOrgMessageOutboxLifecycle(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	invalid := []OrgMessagePostDraft{
		{ClientMsgID: "a", OrgID: "org-1", Body: "x"},                                                     // neither reply nor new thread
		{ClientMsgID: "b", OrgID: "org-1", ThreadID: "t1", NewSubject: "s", NewTopic: "other", Body: "x"}, // both
		{ClientMsgID: "c", OrgID: "org-1", ThreadID: "t1", Body: "   "},                                   // empty
		{ClientMsgID: "d", OrgID: "org-1", NewSubject: "s", Body: "x"},                                    // no topic
		{ClientMsgID: "", OrgID: "org-1", ThreadID: "t1", Body: "x"},                                      // no client id
		{ClientMsgID: "e", OrgID: "", ThreadID: "t1", Body: "x"},                                          // not enrolled
	}
	for i, d := range invalid {
		if _, err := s.EnqueueOrgMessagePost(ctx, d); !errors.Is(err, ErrOrgMessageInvalid) {
			t.Fatalf("invalid draft %d err = %v", i, err)
		}
	}
	draft := OrgMessagePostDraft{ClientMsgID: "c-1", OrgID: "org-1", NewSubject: "Budget question", NewTopic: "budget", Body: "Can I get more room this week?", Now: msgNow}
	item, err := s.EnqueueOrgMessagePost(ctx, draft)
	if err != nil || item.State != OrgMessageOutboxQueued {
		t.Fatalf("enqueue: %+v %v", item, err)
	}
	// Idempotent on the client id.
	again, err := s.EnqueueOrgMessagePost(ctx, draft)
	if err != nil || again.ClientMsgID != "c-1" {
		t.Fatalf("enqueue again: %+v %v", again, err)
	}
	if err := s.NoteOrgMessageOutboxAttempt(ctx, "c-1", "org unreachable", "", false, msgNow); err != nil {
		t.Fatal(err)
	}
	item, _, _ = s.GetOrgMessageOutboxItem(ctx, "c-1")
	if item.State != OrgMessageOutboxQueued || item.Attempts != 1 || item.LastError == "" {
		t.Fatalf("after transient failure: %+v", item)
	}
	if err := s.NoteOrgMessageOutboxAttempt(ctx, "c-1", "the org does not take new threads", orgcontract.OrgMessageErrThreadsDisabled, true, msgNow); err != nil {
		t.Fatal(err)
	}
	item, _, _ = s.GetOrgMessageOutboxItem(ctx, "c-1")
	if item.State != OrgMessageOutboxFailed || item.LastErrorCode != orgcontract.OrgMessageErrThreadsDisabled {
		t.Fatalf("after refusal: %+v", item)
	}
	if pending, _ := s.PendingOrgMessageOutbox(ctx, "org-1"); len(pending) != 0 {
		t.Fatalf("a failed row is flushed: %d", len(pending))
	}
	if sum, _ := s.OrgMessageSummary(ctx); sum.FailedOutbox != 1 {
		t.Fatalf("failed outbox = %d", sum.FailedOutbox)
	}
	if ok, err := s.RequeueOrgMessageOutbox(ctx, "c-1"); err != nil || !ok {
		t.Fatalf("requeue: %v %v", ok, err)
	}
	if err := s.MarkOrgMessageOutboxSent(ctx, "c-1", 40, "t-new", msgNow); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.DiscardOrgMessageOutbox(ctx, "c-1"); ok {
		t.Fatal("a sent row was discarded")
	}
	// The pull brings the stored copy back: the sent row goes.
	dev := orgcontract.OrgMessageRow{ID: 40, ThreadID: "t-new", AuthorKind: orgcontract.OrgMessageAuthorDeveloper, AuthorName: "Dev", Body: draft.Body, ClientMsgID: "c-1", CreatedAt: "2026-10-15T12:00:00Z"}
	if _, err := s.SaveOrgMessagePage(ctx, msgPage(0, 40, []orgcontract.OrgMessageThreadRow{thread("t-new", "note", "open")}, dev)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetOrgMessageOutboxItem(ctx, "c-1"); ok {
		t.Fatal("the sent post stayed after its stored copy arrived")
	}
	// A developer's own message is never unread.
	if sum, _ := s.OrgMessageSummary(ctx); sum.Unread != 0 {
		t.Fatalf("own message counted unread: %+v", sum)
	}

	// Discard a queued one; the queue is bounded.
	for i := 0; i < MaxOrgMessageOutboxPosts; i++ {
		d := draft
		d.ClientMsgID = "bulk-" + time.Duration(i).String()
		if _, err := s.EnqueueOrgMessagePost(ctx, d); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	d := draft
	d.ClientMsgID = "one-too-many"
	if _, err := s.EnqueueOrgMessagePost(ctx, d); !errors.Is(err, ErrOrgMessageOutboxFull) {
		t.Fatalf("full queue err = %v", err)
	}
	if ok, err := s.DiscardOrgMessageOutbox(ctx, "bulk-0s"); err != nil || !ok {
		t.Fatalf("discard: %v %v", ok, err)
	}
}

func TestOrgMessageThreadsAndPrune(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.SaveOrgMessagePage(ctx, msgPage(0, 2, []orgcontract.OrgMessageThreadRow{
		thread("t1", "coaching", "open"), thread("t2", "note", "closed"),
	}, adminMsg(1, "t1", false), adminMsg(2, "t2", false))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueOrgMessagePost(ctx, OrgMessagePostDraft{ClientMsgID: "r1", OrgID: "org-1", ThreadID: "t1", Body: "Thanks, will do.", Now: msgNow}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListOrgMessageThreads(ctx, OrgMessageThreadFilter{})
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d (%v)", len(list), err)
	}
	open, _ := s.ListOrgMessageThreads(ctx, OrgMessageThreadFilter{Status: "open"})
	if len(open) != 1 || open[0].ID != "t1" || open[0].Unread != 1 || open[0].Pending != 1 || open[0].LastAuthorName != "Asha Kim" {
		t.Fatalf("open = %+v", open)
	}
	detail, ok, err := s.GetOrgMessageThread(ctx, "t1")
	if err != nil || !ok || len(detail.Messages) != 1 || len(detail.Outbox) != 1 || len(detail.Messages[0].Attachments) != 1 {
		t.Fatalf("detail = %+v ok=%v err=%v", detail, ok, err)
	}
	if _, ok, _ := s.GetOrgMessageThread(ctx, "nope"); ok {
		t.Fatal("unknown thread found")
	}

	cases := []struct {
		name      string
		now       time.Time
		days      int
		wantGone  int
		wantLeft  int
		wantInbox int
	}{
		{"inside the window keeps the closed thread", msgNow.Add(24 * time.Hour), 30, 0, 2, 2},
		{"past the window drops it with its messages", msgNow.Add(31 * 24 * time.Hour), 30, 1, 1, 1},
	}
	for _, c := range cases {
		gone, err := s.PruneOrgMessages(ctx, c.days, c.now)
		if err != nil || gone != c.wantGone {
			t.Fatalf("%s: gone=%d err=%v", c.name, gone, err)
		}
		all, _ := s.ListOrgMessageThreads(ctx, OrgMessageThreadFilter{})
		var inbox int
		_ = s.db.QueryRow(`SELECT COUNT(*) FROM org_messages_inbox`).Scan(&inbox)
		if len(all) != c.wantLeft || inbox != c.wantInbox {
			t.Fatalf("%s: threads=%d inbox=%d", c.name, len(all), inbox)
		}
	}

	if err := s.ClearIdentityBoundDocs(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.LoadOrgMessageRail(ctx); ok {
		t.Fatal("rail survived an identity clear")
	}
	if all, _ := s.ListOrgMessageThreads(ctx, OrgMessageThreadFilter{}); len(all) != 0 {
		t.Fatalf("threads survived an identity clear: %d", len(all))
	}
}

func TestNoteOrgMessageFetch(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	steps := []struct {
		state, err string
		wantOK     bool
	}{
		{"not_supported", "", false},
		{"ok", "", true},
		{"unreachable", "dial tcp: refused", true}, // keeps the earlier last_ok_at
	}
	for i, st := range steps {
		if err := s.NoteOrgMessageFetch(ctx, st.state, st.err, msgNow.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
		rail, ok, err := s.LoadOrgMessageRail(ctx)
		if err != nil || !ok || rail.FetchState != st.state || (rail.LastOKAt != "") != st.wantOK || rail.Cursor != 0 {
			t.Fatalf("step %d rail = %+v", i, rail)
		}
	}
}
