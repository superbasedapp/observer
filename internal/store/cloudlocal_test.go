package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// cloudTestStore opens a real store on a fresh migrated DB (schema at the
// current version, incl. migration 097). A fresh DB is DEFINITIVELY unenrolled,
// so a plain UpsertSession stamps authority 'personal' == eligible.
func cloudTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cloud.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(database), database
}

// seedEligibleSession upserts a project + session on the fresh (unenrolled)
// store, yielding an authority='personal' session eligible for personal cloud.
func seedEligibleSession(t *testing.T, s *Store, id string) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/cloud/p", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: "codex", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	eligible, err := s.EligibleForPersonalCloud(ctx, id)
	if err != nil || !eligible {
		t.Fatalf("precondition: session %q must be eligible (eligible=%v err=%v)", id, eligible, err)
	}
}

// cloudTestEndpoint is the endpoint seedReceipt binds; the send path (FD1)
// requires PrepareCloudOutboxSend to be called with a matching endpoint.
const cloudTestEndpoint = "https://cloud.example/enrich"

// seedReceipt inserts a live receipt binding uploadDigest and returns its id.
func seedReceipt(t *testing.T, s *Store, uploadDigest string) string {
	t.Helper()
	id, err := s.InsertCloudConsentReceipt(context.Background(), CloudConsentReceipt{
		AccountPseudonym:      "acct-abc",
		Purpose:               "bounded_context_enrichment",
		FieldClassesJSON:      `["content_excerpts"]`,
		EnvelopeSchemaVersion: "session-evidence.v1-candidate",
		ScrubberVersion:       "scrub-v1",
		Endpoint:              "https://cloud.example/enrich",
		UploadDigest:          uploadDigest,
	})
	if err != nil {
		t.Fatalf("InsertCloudConsentReceipt: %v", err)
	}
	return id
}

func TestCloudLocalPseudonymMapping(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	// Get-or-create is idempotent: same local id -> same pseudonym.
	p1, err := s.GetOrCreateCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	p1again, err := s.GetOrCreateCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if p1 != p1again {
		t.Fatalf("get-or-create not idempotent: %q vs %q", p1, p1again)
	}
	// Distinct local ids -> distinct pseudonyms.
	p2, err := s.GetOrCreateCloudSessionPseudonym(ctx, "local-sess-2")
	if err != nil {
		t.Fatalf("distinct: %v", err)
	}
	if p1 == p2 {
		t.Fatalf("distinct local ids produced the same pseudonym %q", p1)
	}
	// The pseudonym must NOT be derived from the local id.
	if p1 == "local-sess-1" || p1 == "cs_local-sess-1" ||
		len(p1) < len("cs_")+16 || p1[:3] != "cs_" {
		t.Fatalf("pseudonym %q looks derived from / too short for a random id", p1)
	}
	// Project map is a separate namespace with its own prefix.
	pp, err := s.GetOrCreateCloudProjectPseudonym(ctx, "local-proj-1")
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	if pp[:3] != "cp_" {
		t.Fatalf("project pseudonym %q missing cp_ prefix", pp)
	}
}

func TestCloudLocalReverseLookupByPseudonym(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	p1, err := s.GetOrCreateCloudSessionPseudonym(ctx, "local-sess-1")
	if err != nil {
		t.Fatalf("mint p1: %v", err)
	}
	p2, err := s.GetOrCreateCloudSessionPseudonym(ctx, "local-sess-2")
	if err != nil {
		t.Fatalf("mint p2: %v", err)
	}

	cases := []struct {
		name      string
		pseudonym string
		wantLocal string
		wantOK    bool
	}{
		{name: "known pseudonym resolves its local session", pseudonym: p1, wantLocal: "local-sess-1", wantOK: true},
		{name: "a distinct known pseudonym resolves its own local session", pseudonym: p2, wantLocal: "local-sess-2", wantOK: true},
		{name: "unknown pseudonym is a routine miss, not an error", pseudonym: "cs_never_minted_by_this_device", wantOK: false},
		{name: "empty pseudonym is a routine miss", pseudonym: "", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok, err := s.LookupLocalSessionByCloudPseudonym(ctx, tc.pseudonym)
			if err != nil {
				t.Fatalf("LookupLocalSessionByCloudPseudonym(%q): %v", tc.pseudonym, err)
			}
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.wantLocal {
				t.Fatalf("local session = %q, want %q", got, tc.wantLocal)
			}
		})
	}
}

func TestCloudLocalReceiptCRUD(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	id := seedReceipt(t, s, "sha256:UP1")
	got, ok, err := s.GetCloudConsentReceipt(ctx, id)
	if err != nil || !ok {
		t.Fatalf("get receipt: ok=%v err=%v", ok, err)
	}
	if got.UploadDigest != "sha256:UP1" || got.InvalidatedAt != nil {
		t.Fatalf("unexpected receipt: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("receipt created_at should be stamped")
	}

	// Missing id -> ok=false, no error.
	if _, ok, err := s.GetCloudConsentReceipt(ctx, "nope"); err != nil || ok {
		t.Fatalf("missing receipt: ok=%v err=%v", ok, err)
	}

	// Invalidate, then confirm the stamp; re-invalidate is a no-op that keeps
	// the first timestamp.
	if err := s.InvalidateCloudConsentReceipt(ctx, id); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	inv1, _, err := s.GetCloudConsentReceipt(ctx, id)
	if err != nil {
		t.Fatalf("get after invalidate: %v", err)
	}
	if inv1.InvalidatedAt == nil {
		t.Fatal("receipt should be invalidated")
	}
	if err := s.InvalidateCloudConsentReceipt(ctx, id); err != nil {
		t.Fatalf("re-invalidate: %v", err)
	}
	inv2, _, _ := s.GetCloudConsentReceipt(ctx, id)
	if !inv1.InvalidatedAt.Equal(*inv2.InvalidatedAt) {
		t.Fatalf("re-invalidate changed the stamp: %v -> %v", *inv1.InvalidatedAt, *inv2.InvalidatedAt)
	}
}

func TestCloudOutboxEnqueueEligibilityGate(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	rcpt := seedReceipt(t, s, "sha256:UP")

	base := func(sessID string) CloudOutboxItem {
		return CloudOutboxItem{
			SessionID:             sessID,
			EvidenceContentDigest: "sha256:EV",
			UploadDigest:          "sha256:UP",
			ReceiptID:             rcpt,
		}
	}

	// Eligible (personal) session enqueues.
	seedEligibleSession(t, s, "sess-personal")
	if _, err := s.EnqueueCloudOutbox(ctx, base("sess-personal")); err != nil {
		t.Fatalf("eligible enqueue: %v", err)
	}

	// Org-authority session is refused.
	seedEligibleSession(t, s, "sess-org")
	if _, err := database.ExecContext(ctx, `UPDATE sessions SET authority='org' WHERE id='sess-org'`); err != nil {
		t.Fatalf("force org: %v", err)
	}
	if _, err := s.EnqueueCloudOutbox(ctx, base("sess-org")); !errors.Is(err, ErrCloudSessionIneligible) {
		t.Fatalf("org session: want ErrCloudSessionIneligible, got %v", err)
	}

	// Unknown (NULL) authority is refused.
	seedEligibleSession(t, s, "sess-unknown")
	if _, err := database.ExecContext(ctx, `UPDATE sessions SET authority=NULL, authority_classifier_version=NULL WHERE id='sess-unknown'`); err != nil {
		t.Fatalf("force unknown: %v", err)
	}
	if _, err := s.EnqueueCloudOutbox(ctx, base("sess-unknown")); !errors.Is(err, ErrCloudSessionIneligible) {
		t.Fatalf("unknown session: want ErrCloudSessionIneligible, got %v", err)
	}

	// Missing session is refused.
	if _, err := s.EnqueueCloudOutbox(ctx, base("sess-missing")); !errors.Is(err, ErrCloudSessionIneligible) {
		t.Fatalf("missing session: want ErrCloudSessionIneligible, got %v", err)
	}

	// Digest incoherent with the receipt is refused even for an eligible session.
	seedEligibleSession(t, s, "sess-incoherent")
	bad := base("sess-incoherent")
	bad.UploadDigest = "sha256:DIFFERENT"
	if _, err := s.EnqueueCloudOutbox(ctx, bad); !errors.Is(err, ErrCloudReceiptDigestMismatch) {
		t.Fatalf("incoherent digest: want ErrCloudReceiptDigestMismatch, got %v", err)
	}

	// Invalidated receipt is refused (reconfirmation required).
	seedEligibleSession(t, s, "sess-invalid-rcpt")
	if err := s.InvalidateCloudConsentReceipt(ctx, rcpt); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	if _, err := s.EnqueueCloudOutbox(ctx, base("sess-invalid-rcpt")); !errors.Is(err, ErrCloudReconfirmationRequired) {
		t.Fatalf("invalidated receipt: want ErrCloudReconfirmationRequired, got %v", err)
	}
}

func TestCloudOutboxReconfirmationRule(t *testing.T) {
	ctx := context.Background()

	// Helper: fresh store with one eligible session and a live receipt binding
	// uploadDigest, one enqueued pending item, returns (store, itemID, rcptID).
	setup := func(t *testing.T, evDigest, upDigest string) (*Store, string, string) {
		s, _ := cloudTestStore(t)
		seedEligibleSession(t, s, "sess-1")
		rcpt := seedReceipt(t, s, upDigest)
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: "sess-1", EvidenceContentDigest: evDigest, UploadDigest: upDigest, ReceiptID: rcpt,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		return s, id, rcpt
	}

	t.Run("match yields sending and bytes", func(t *testing.T) {
		s, id, _ := setup(t, "sha256:EV", "sha256:UP")
		want := []byte("the-rebuilt-upload-bytes")
		rebuild := func(context.Context) ([]byte, string, string, error) {
			return want, "sha256:EV", "sha256:UP", nil
		}
		got, _, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild)
		if err != nil {
			t.Fatalf("PrepareCloudOutboxSend: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("bytes = %q, want %q", got, want)
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxSending {
			t.Fatalf("state = %q, want sending", it.State)
		}
	})

	t.Run("evidence digest mismatch requires reconfirmation", func(t *testing.T) {
		s, id, _ := setup(t, "sha256:EV", "sha256:UP")
		rebuild := func(context.Context) ([]byte, string, string, error) {
			return []byte("x"), "sha256:EV-CHANGED", "sha256:UP", nil
		}
		_, _, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild)
		if !errors.Is(err, ErrCloudReconfirmationRequired) {
			t.Fatalf("want ErrCloudReconfirmationRequired, got %v", err)
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxReconfirmationRequired {
			t.Fatalf("state = %q, want reconfirmation_required", it.State)
		}
		if it.LastError != "digest_mismatch" {
			t.Fatalf("last_error = %q, want digest_mismatch", it.LastError)
		}
		// The stored digest must NOT have been auto-updated.
		if it.EvidenceContentDigest != "sha256:EV" {
			t.Fatalf("evidence digest auto-updated to %q — must never happen", it.EvidenceContentDigest)
		}
	})

	t.Run("upload digest mismatch requires reconfirmation", func(t *testing.T) {
		s, id, _ := setup(t, "sha256:EV", "sha256:UP")
		rebuild := func(context.Context) ([]byte, string, string, error) {
			return []byte("x"), "sha256:EV", "sha256:UP-CHANGED", nil
		}
		if _, _, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild); !errors.Is(err, ErrCloudReconfirmationRequired) {
			t.Fatalf("want ErrCloudReconfirmationRequired, got %v", err)
		}
	})

	t.Run("rebuild error leaves state unchanged", func(t *testing.T) {
		s, id, _ := setup(t, "sha256:EV", "sha256:UP")
		rebuild := func(context.Context) ([]byte, string, string, error) {
			return nil, "", "", errors.New("boom")
		}
		if _, _, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild); err == nil {
			t.Fatal("expected the rebuild error to propagate")
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxPending {
			t.Fatalf("state = %q, want pending (unchanged after rebuild error)", it.State)
		}
	})

	t.Run("invalidated receipt requires reconfirmation without rebuild", func(t *testing.T) {
		s, id, rcpt := setup(t, "sha256:EV", "sha256:UP")
		if err := s.InvalidateCloudConsentReceipt(ctx, rcpt); err != nil {
			t.Fatalf("invalidate: %v", err)
		}
		called := false
		rebuild := func(context.Context) ([]byte, string, string, error) {
			called = true
			return []byte("x"), "sha256:EV", "sha256:UP", nil
		}
		if _, _, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild); !errors.Is(err, ErrCloudReconfirmationRequired) {
			t.Fatalf("want ErrCloudReconfirmationRequired, got %v", err)
		}
		if called {
			t.Fatal("rebuild must not run when the bound receipt is already invalidated")
		}
	})

	t.Run("reconfirm then prepare succeeds", func(t *testing.T) {
		s, id, _ := setup(t, "sha256:EV", "sha256:UP")
		// Drive to reconfirmation_required via a mismatch.
		_, _, _ = s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, func(context.Context) ([]byte, string, string, error) {
			return []byte("x"), "sha256:EV", "sha256:UP-CHANGED", nil
		})
		// The developer re-previews and confirms a NEW receipt.
		rcpt2 := seedReceipt(t, s, "sha256:UP2")
		if err := s.ReconfirmCloudOutbox(ctx, id, rcpt2, "sha256:EV2", "sha256:UP2"); err != nil {
			t.Fatalf("ReconfirmCloudOutbox: %v", err)
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxPending || it.EvidenceContentDigest != "sha256:EV2" || it.UploadDigest != "sha256:UP2" {
			t.Fatalf("after reconfirm: %+v", it)
		}
		// A rebuild matching the NEW digests now sends.
		got, _, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, func(context.Context) ([]byte, string, string, error) {
			return []byte("new-bytes"), "sha256:EV2", "sha256:UP2", nil
		})
		if err != nil {
			t.Fatalf("prepare after reconfirm: %v", err)
		}
		if string(got) != "new-bytes" {
			t.Fatalf("bytes = %q", got)
		}
	})
}

func TestCloudOutboxStateMachineTransitions(t *testing.T) {
	ctx := context.Background()
	all := []CloudOutboxState{
		CloudOutboxPending, CloudOutboxReconfirmationRequired, CloudOutboxSending,
		CloudOutboxSent, CloudOutboxFailedRetryable, CloudOutboxFailedTerminal, CloudOutboxCancelled,
	}

	// Each event names the ONLY states it may run from; every other state must
	// be rejected with ErrIllegalCloudOutboxTransition.
	events := []struct {
		name    string
		allowed map[CloudOutboxState]bool
		run     func(s *Store, id string) error
	}{
		{
			name:    "MarkSent",
			allowed: map[CloudOutboxState]bool{CloudOutboxSending: true},
			run:     func(s *Store, id string) error { return s.MarkCloudOutboxSent(ctx, id) },
		},
		{
			name:    "MarkRetryable",
			allowed: map[CloudOutboxState]bool{CloudOutboxSending: true},
			run:     func(s *Store, id string) error { return s.MarkCloudOutboxRetryable(ctx, id, "neterr") },
		},
		{
			name:    "MarkTerminal",
			allowed: map[CloudOutboxState]bool{CloudOutboxSending: true, CloudOutboxFailedRetryable: true},
			run:     func(s *Store, id string) error { return s.MarkCloudOutboxTerminal(ctx, id, "badreq") },
		},
		{
			name:    "Reconfirm",
			allowed: map[CloudOutboxState]bool{CloudOutboxReconfirmationRequired: true},
			run: func(s *Store, id string) error {
				// A valid new receipt so only the STATE guard can reject.
				rc := seedReceipt(t, s, "sha256:UP2")
				return s.ReconfirmCloudOutbox(ctx, id, rc, "sha256:EV2", "sha256:UP2")
			},
		},
	}

	for _, ev := range events {
		for _, from := range all {
			t.Run(ev.name+"_from_"+string(from), func(t *testing.T) {
				s, database := cloudTestStore(t)
				seedEligibleSession(t, s, "sess-1")
				rcpt := seedReceipt(t, s, "sha256:UP")
				id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
					SessionID: "sess-1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rcpt,
				})
				if err != nil {
					t.Fatalf("enqueue: %v", err)
				}
				// Force the from-state directly for exhaustive coverage.
				if _, err := database.ExecContext(ctx, `UPDATE cloud_outbox SET state=? WHERE id=?`, string(from), id); err != nil {
					t.Fatalf("force state: %v", err)
				}
				err = ev.run(s, id)
				if ev.allowed[from] {
					if err != nil {
						t.Fatalf("%s from %s: want success, got %v", ev.name, from, err)
					}
					return
				}
				if !errors.Is(err, ErrIllegalCloudOutboxTransition) {
					t.Fatalf("%s from %s: want ErrIllegalCloudOutboxTransition, got %v", ev.name, from, err)
				}
			})
		}
	}

	// Not-found: every transition method reports ErrCloudOutboxNotFound.
	t.Run("not_found", func(t *testing.T) {
		s, _ := cloudTestStore(t)
		for _, run := range []func() error{
			func() error { return s.MarkCloudOutboxSent(ctx, "ghost") },
			func() error { return s.MarkCloudOutboxRetryable(ctx, "ghost", "x") },
			func() error { return s.MarkCloudOutboxTerminal(ctx, "ghost", "x") },
		} {
			if err := run(); !errors.Is(err, ErrCloudOutboxNotFound) {
				t.Fatalf("want ErrCloudOutboxNotFound, got %v", err)
			}
		}
	})

	// MarkRetryable increments retry_count on each success.
	t.Run("retry_count_increments", func(t *testing.T) {
		s, database := cloudTestStore(t)
		seedEligibleSession(t, s, "sess-1")
		rcpt := seedReceipt(t, s, "sha256:UP")
		id, _ := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: "sess-1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rcpt,
		})
		for want := 1; want <= 2; want++ {
			if _, err := database.ExecContext(ctx, `UPDATE cloud_outbox SET state='sending' WHERE id=?`, id); err != nil {
				t.Fatalf("force sending: %v", err)
			}
			if err := s.MarkCloudOutboxRetryable(ctx, id, "neterr"); err != nil {
				t.Fatalf("retryable: %v", err)
			}
			it, _, _ := s.GetCloudOutbox(ctx, id)
			if it.RetryCount != want {
				t.Fatalf("retry_count = %d, want %d", it.RetryCount, want)
			}
		}
	})
}

func TestCloudOutboxCancelForReceipt(t *testing.T) {
	s, database := cloudTestStore(t)
	ctx := context.Background()
	rcpt := seedReceipt(t, s, "sha256:UP")

	// One session per item: the duplicate guard refuses a second LIVE enqueue
	// of the same bytes on one session, and cancel-by-receipt is
	// session-independent anyway.
	var seq int
	mk := func(state CloudOutboxState) string {
		seq++
		sess := fmt.Sprintf("sess-%d", seq)
		seedEligibleSession(t, s, sess)
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: sess, EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rcpt,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, err := database.ExecContext(ctx, `UPDATE cloud_outbox SET state=? WHERE id=?`, string(state), id); err != nil {
			t.Fatalf("force state: %v", err)
		}
		return id
	}

	pending := mk(CloudOutboxPending)
	recon := mk(CloudOutboxReconfirmationRequired)
	retry := mk(CloudOutboxFailedRetryable)
	sending := mk(CloudOutboxSending)
	sent := mk(CloudOutboxSent)

	n, err := s.CancelCloudOutboxForReceipt(ctx, rcpt)
	if err != nil {
		t.Fatalf("cancel: %v", err)
	}
	// FD3: a revoked receipt now also cancels an in-flight `sending` row so a
	// concurrent sync cannot upload against a revoked receipt.
	if n != 4 {
		t.Fatalf("cancelled %d, want 4 (pending, reconfirmation_required, failed_retryable, sending)", n)
	}
	for _, id := range []string{pending, recon, retry, sending} {
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxCancelled {
			t.Fatalf("item %q state = %q, want cancelled", id, it.State)
		}
	}
	// Terminal items are untouched.
	if it, _, _ := s.GetCloudOutbox(ctx, sent); it.State != CloudOutboxSent {
		t.Fatalf("sent item state = %q, want left as sent", it.State)
	}
}

func TestCloudResultUpsertAndOverrides(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()

	// v1 result for the session.
	v1, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID:     "sess-1",
		SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON:    `{"title":"AI title v1"}`,
		Provenance:    CloudResultProvenance{ModelRoute: "luna", Tokens: 100, CostUSD: 0.01},
	})
	if err != nil {
		t.Fatalf("upsert v1: %v", err)
	}

	got, overrides, ok, err := s.GetCloudSessionResult(ctx, "sess-1")
	if err != nil || !ok {
		t.Fatalf("get v1: ok=%v err=%v", ok, err)
	}
	if got.ID != v1 || got.SupersededBy != nil || overrides != nil {
		t.Fatalf("unexpected v1 read: %+v overrides=%v", got, overrides)
	}
	if got.Provenance.ModelRoute != "luna" || got.Provenance.Tokens != 100 {
		t.Fatalf("provenance lost: %+v", got.Provenance)
	}

	// The user edits the title on v1.
	if err := s.SetCloudResultOverride(ctx, v1, "title", "User's own title"); err != nil {
		t.Fatalf("override: %v", err)
	}
	_, overrides, _, _ = s.GetCloudSessionResult(ctx, "sess-1")
	if o, ok := overrides["title"]; !ok || o.UserValue != "User's own title" {
		t.Fatalf("override not applied on read: %+v", overrides)
	}

	// A regeneration lands as v2, superseding v1.
	v2, err := s.UpsertCloudResult(ctx, CloudResult{
		SessionID:     "sess-1",
		SchemaVersion: "session_enrichment.v2-candidate",
		ResultJSON:    `{"title":"AI title v2"}`,
	})
	if err != nil {
		t.Fatalf("upsert v2: %v", err)
	}
	got, overrides, _, _ = s.GetCloudSessionResult(ctx, "sess-1")
	if got.ID != v2 {
		t.Fatalf("newest result = %q, want v2 %q", got.ID, v2)
	}
	// v1 is now superseded_by v2.
	v1row, _, _, _ := s.getCloudResultByID(ctx, v1)
	if v1row.SupersededBy == nil || *v1row.SupersededBy != v2 {
		t.Fatalf("v1.superseded_by = %v, want %q", v1row.SupersededBy, v2)
	}
	// The override (bound to v1) STILL wins for v2 — a regenerated result never
	// clobbers a user edit.
	if o, ok := overrides["title"]; !ok || o.UserValue != "User's own title" {
		t.Fatalf("regeneration clobbered the override: %+v", overrides)
	}
}

// getCloudResultByID is a test-only read of a single result row by id (the
// production read is session-scoped). Defined here to keep the seam's public
// surface exactly what the CLI needs.
func (s *Store) getCloudResultByID(ctx context.Context, id string) (CloudResult, map[string]CloudResultOverride, bool, error) {
	var (
		r            CloudResult
		receivedAt   string
		supersededBy sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT id, session_id, schema_version, result_json, model_route, prompt_hash,
		       tokens, cost_usd, received_at, superseded_by
		  FROM cloud_results WHERE id = ?`, id).
		Scan(&r.ID, &r.SessionID, &r.SchemaVersion, &r.ResultJSON, &r.Provenance.ModelRoute,
			&r.Provenance.PromptHash, &r.Provenance.Tokens, &r.Provenance.CostUSD,
			&receivedAt, &supersededBy)
	if errors.Is(err, sql.ErrNoRows) {
		return CloudResult{}, nil, false, nil
	}
	if err != nil {
		return CloudResult{}, nil, false, err
	}
	r.ReceivedAt = cloudParseTime(receivedAt)
	if supersededBy.Valid && supersededBy.String != "" {
		v := supersededBy.String
		r.SupersededBy = &v
	}
	return r, nil, true, nil
}

// TestPrepareCloudOutboxSendEndpointBinding is the FD1 regression: an item
// whose receipt bound endpoint A must be REFUSED (reconfirmation) when the sync
// send target is a different origin B — confirmed evidence can only ever reach
// the approved origin+path. A matching endpoint (modulo trailing-slash/port
// normalization) is accepted.
func TestPrepareCloudOutboxSendEndpointBinding(t *testing.T) {
	ctx := context.Background()
	match := func(context.Context) ([]byte, string, string, error) {
		return []byte("bytes"), "sha256:EV", "sha256:UP", nil
	}
	setup := func(t *testing.T) (*Store, string) {
		s, _ := cloudTestStore(t)
		seedEligibleSession(t, s, "sess-1")
		// Receipt binds the APPROVED endpoint.
		rid, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
			AccountPseudonym: "acct", Endpoint: "https://approved.example/v1/jobs", UploadDigest: "sha256:UP",
		})
		if err != nil {
			t.Fatalf("receipt: %v", err)
		}
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: "sess-1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rid,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		return s, id
	}

	t.Run("different origin refused, not sent", func(t *testing.T) {
		s, id := setup(t)
		called := false
		_, _, err := s.PrepareCloudOutboxSend(ctx, id, "https://attacker.example/v1/jobs",
			func(ctx context.Context) ([]byte, string, string, error) { called = true; return match(ctx) })
		if !errors.Is(err, ErrCloudEndpointMismatch) {
			t.Fatalf("want ErrCloudEndpointMismatch, got %v", err)
		}
		if called {
			t.Fatal("rebuild must not run when the send endpoint is not the approved one")
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxReconfirmationRequired || it.LastError != "endpoint_mismatch" {
			t.Fatalf("item state=%q last_error=%q, want reconfirmation_required/endpoint_mismatch", it.State, it.LastError)
		}
	})

	t.Run("matching origin (normalized) accepted", func(t *testing.T) {
		s, id := setup(t)
		// Trailing slash + explicit default port must normalize equal.
		got, lease, err := s.PrepareCloudOutboxSend(ctx, id, "https://approved.example:443/v1/jobs/", match)
		if err != nil {
			t.Fatalf("PrepareCloudOutboxSend: %v", err)
		}
		if string(got) != "bytes" || lease.OutboxID != id {
			t.Fatalf("unexpected bytes/lease: %q %+v", got, lease)
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State != CloudOutboxSending {
			t.Fatalf("state = %q, want sending", it.State)
		}
	})
}

// TestPrepareCloudOutboxSendReconfirmationRace is the FD3 barrier: authorization
// that changes DURING the rebuild (the receipt is invalidated, or the session is
// upgraded to org) must NOT reach `sending` — the atomic re-verify catches it and
// moves the item to reconfirmation_required. The rebuild closure is the barrier:
// it mutates authorization before returning digests that would otherwise match.
func TestPrepareCloudOutboxSendReconfirmationRace(t *testing.T) {
	ctx := context.Background()

	t.Run("receipt invalidated during rebuild does not send", func(t *testing.T) {
		s, _ := cloudTestStore(t)
		seedEligibleSession(t, s, "sess-1")
		rid, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
			AccountPseudonym: "acct", Endpoint: cloudTestEndpoint, UploadDigest: "sha256:UP",
		})
		if err != nil {
			t.Fatalf("receipt: %v", err)
		}
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: "sess-1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rid,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		rebuild := func(ctx context.Context) ([]byte, string, string, error) {
			// Barrier: invalidate the bound receipt after the pre-rebuild checks
			// passed but before returning otherwise-matching digests.
			if err := s.InvalidateCloudConsentReceipt(ctx, rid); err != nil {
				return nil, "", "", err
			}
			return []byte("bytes"), "sha256:EV", "sha256:UP", nil
		}
		_, _, err = s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild)
		if !errors.Is(err, ErrCloudReconfirmationRequired) {
			t.Fatalf("want ErrCloudReconfirmationRequired, got %v", err)
		}
		it, _, _ := s.GetCloudOutbox(ctx, id)
		if it.State == CloudOutboxSending {
			t.Fatal("item reached SENDING despite the receipt being invalidated mid-rebuild (FD3)")
		}
		if it.State != CloudOutboxReconfirmationRequired {
			t.Fatalf("state = %q, want reconfirmation_required", it.State)
		}
	})

	t.Run("session upgraded to org during rebuild does not send", func(t *testing.T) {
		s, database := cloudTestStore(t)
		seedEligibleSession(t, s, "sess-1")
		rid, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
			AccountPseudonym: "acct", Endpoint: cloudTestEndpoint, UploadDigest: "sha256:UP",
		})
		if err != nil {
			t.Fatalf("receipt: %v", err)
		}
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: "sess-1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rid,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		rebuild := func(context.Context) ([]byte, string, string, error) {
			// Barrier: flip the session to org authority mid-rebuild.
			if _, err := database.ExecContext(ctx,
				`UPDATE sessions SET authority='org' WHERE id='sess-1'`); err != nil {
				return nil, "", "", err
			}
			return []byte("bytes"), "sha256:EV", "sha256:UP", nil
		}
		_, _, err = s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint, rebuild)
		if !errors.Is(err, ErrCloudReconfirmationRequired) {
			t.Fatalf("want ErrCloudReconfirmationRequired, got %v", err)
		}
		if it, _, _ := s.GetCloudOutbox(ctx, id); it.State == CloudOutboxSending {
			t.Fatal("item reached SENDING despite the session upgrading to org mid-rebuild (FD3)")
		}
	})
}

// TestVerifyCloudSendAuthorization is the FD3 final-pre-dispatch check: after a
// clean prepare (item in `sending`), an authorization change before the HTTP
// upload must abort the send and move the item off `sending`.
func TestVerifyCloudSendAuthorization(t *testing.T) {
	ctx := context.Background()
	prep := func(t *testing.T) (*Store, string, string, CloudSendLease) {
		s, _ := cloudTestStore(t)
		seedEligibleSession(t, s, "sess-1")
		rid, err := s.InsertCloudConsentReceipt(ctx, CloudConsentReceipt{
			AccountPseudonym: "acct", Endpoint: cloudTestEndpoint, UploadDigest: "sha256:UP",
		})
		if err != nil {
			t.Fatalf("receipt: %v", err)
		}
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: "sess-1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rid,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		_, lease, err := s.PrepareCloudOutboxSend(ctx, id, cloudTestEndpoint,
			func(context.Context) ([]byte, string, string, error) {
				return []byte("b"), "sha256:EV", "sha256:UP", nil
			})
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		return s, id, rid, lease
	}

	t.Run("still authorized", func(t *testing.T) {
		s, _, _, lease := prep(t)
		if err := s.VerifyCloudSendAuthorization(ctx, lease); err != nil {
			t.Fatalf("want nil, got %v", err)
		}
	})

	t.Run("receipt invalidated after prepare aborts and unwinds sending", func(t *testing.T) {
		s, id, rid, lease := prep(t)
		if err := s.InvalidateCloudConsentReceipt(ctx, rid); err != nil {
			t.Fatalf("invalidate: %v", err)
		}
		if err := s.VerifyCloudSendAuthorization(ctx, lease); !errors.Is(err, ErrCloudSendUnauthorized) {
			t.Fatalf("want ErrCloudSendUnauthorized, got %v", err)
		}
		if it, _, _ := s.GetCloudOutbox(ctx, id); it.State != CloudOutboxReconfirmationRequired {
			t.Fatalf("state = %q, want reconfirmation_required after aborted send", it.State)
		}
	})
}

// TestReclaimStaleCloudSending is the FD4 regression: an item stranded in
// `sending` by a crash-before-mark is reclaimed to failed_retryable on the next
// sync so it is picked up again; a freshly-sending item is left alone.
func TestReclaimStaleCloudSending(t *testing.T) {
	ctx := context.Background()
	s, database := cloudTestStore(t)
	seedEligibleSession(t, s, "sess-1")
	seedEligibleSession(t, s, "sess-2")
	rid := seedReceipt(t, s, "sha256:UP")

	// Two sessions: the duplicate guard refuses a second in-flight enqueue of
	// the same bytes on one session.
	sessions := []string{"sess-1", "sess-2"}
	mkSending := func(updatedAt time.Time) string {
		sess := sessions[0]
		sessions = sessions[1:]
		id, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{
			SessionID: sess, EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: rid,
		})
		if err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		if _, err := database.ExecContext(ctx,
			`UPDATE cloud_outbox SET state='sending', updated_at=? WHERE id=?`,
			updatedAt.UTC().Format(time.RFC3339Nano), id); err != nil {
			t.Fatalf("force sending: %v", err)
		}
		return id
	}

	stale := mkSending(time.Now().Add(-time.Hour)) // stranded by a prior crash
	fresh := mkSending(time.Now())                 // genuinely in-flight now

	// Precondition: neither is sendable while stuck in `sending`.
	if items, err := s.ListSendableCloudOutbox(ctx); err != nil || len(items) != 0 {
		t.Fatalf("precondition: want 0 sendable, got %d (err=%v)", len(items), err)
	}

	n, err := s.ReclaimStaleCloudSending(ctx, time.Now().Add(-30*time.Minute))
	if err != nil {
		t.Fatalf("reclaim: %v", err)
	}
	if n != 1 {
		t.Fatalf("reclaimed %d, want 1 (only the stale item)", n)
	}
	if it, _, _ := s.GetCloudOutbox(ctx, stale); it.State != CloudOutboxFailedRetryable {
		t.Fatalf("stale item state = %q, want failed_retryable (reclaimed)", it.State)
	}
	if it, _, _ := s.GetCloudOutbox(ctx, fresh); it.State != CloudOutboxSending {
		t.Fatalf("fresh item state = %q, want left as sending", it.State)
	}
	// The reclaimed item is now sendable again.
	items, err := s.ListSendableCloudOutbox(ctx)
	if err != nil {
		t.Fatalf("list sendable: %v", err)
	}
	if len(items) != 1 || items[0].ID != stale {
		t.Fatalf("sendable = %+v, want just the reclaimed stale item", items)
	}
}

// TestCloudDashboardReadSeam is the FF1 regression: the aggregate reads the node
// dashboard renders now live in the store seam (not ad-hoc SQL in the handler).
// It exercises each exported method against seeded state.
func TestCloudDashboardReadSeam(t *testing.T) {
	ctx := context.Background()
	s, database := cloudTestStore(t)
	seedEligibleSession(t, s, "s1")

	// Two receipts: one live, one invalidated.
	live := seedReceipt(t, s, "sha256:UP")
	inv := seedReceipt(t, s, "sha256:UP2")
	if err := s.InvalidateCloudConsentReceipt(ctx, inv); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	total, liveN, err := s.CloudReceiptCounts(ctx)
	if err != nil {
		t.Fatalf("CloudReceiptCounts: %v", err)
	}
	if total != 2 || liveN != 1 {
		t.Fatalf("receipt counts = (%d,%d), want (2,1)", total, liveN)
	}

	// Two outbox items on s1: force one to sent, then leave one pending (in
	// that order - the duplicate guard only counts in-flight rows, so a sent
	// row never blocks a re-enqueue of the same bytes).
	id2, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{SessionID: "s1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: live})
	if err != nil {
		t.Fatalf("enqueue 2: %v", err)
	}
	if _, err := database.ExecContext(ctx, `UPDATE cloud_outbox SET state='sent' WHERE id=?`, id2); err != nil {
		t.Fatalf("force sent: %v", err)
	}
	id1, err := s.EnqueueCloudOutbox(ctx, CloudOutboxItem{SessionID: "s1", EvidenceContentDigest: "sha256:EV", UploadDigest: "sha256:UP", ReceiptID: live})
	if err != nil {
		t.Fatalf("enqueue 1: %v", err)
	}
	byState, outboxTotal, err := s.CloudOutboxCountsByState(ctx)
	if err != nil {
		t.Fatalf("CloudOutboxCountsByState: %v", err)
	}
	if outboxTotal != 2 || byState["pending"] != 1 || byState["sent"] != 1 {
		t.Fatalf("outbox counts = %v total=%d, want pending:1 sent:1 total:2", byState, outboxTotal)
	}

	forSession, err := s.ListCloudOutboxForSession(ctx, "s1")
	if err != nil {
		t.Fatalf("ListCloudOutboxForSession: %v", err)
	}
	if len(forSession) != 2 {
		t.Fatalf("session outbox = %d items, want 2", len(forSession))
	}
	seen := map[string]bool{}
	for _, it := range forSession {
		seen[it.ID] = true
	}
	if !seen[id1] || !seen[id2] {
		t.Fatalf("session outbox missing ids: %v", seen)
	}

	// One result for s1.
	if _, err := s.UpsertCloudResult(ctx, CloudResult{SessionID: "s1", SchemaVersion: "v", ResultJSON: `{"title":"x"}`}); err != nil {
		t.Fatalf("UpsertCloudResult: %v", err)
	}
	resTotal, last, err := s.CloudResultsSummary(ctx)
	if err != nil {
		t.Fatalf("CloudResultsSummary: %v", err)
	}
	if resTotal != 1 || last == "" {
		t.Fatalf("results summary = (%d, %q), want (1, non-empty)", resTotal, last)
	}
}

// TestCloudOutboxEnqueueDuplicateGuard pins the idempotency guard (review
// 2026-09-15): the same session's SAME upload bytes are queued once - the
// auto-enrich sweep and a manual "Enrich now" racing on one session must not
// double-send. Different bytes (a session that grew) and terminal states
// (sent / cancelled) do not block a new enqueue.
func TestCloudOutboxEnqueueDuplicateGuard(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	seedEligibleSession(t, s, "sess-dup")

	rcptA := seedReceipt(t, s, "sha256:UP-A")
	rcptA2 := seedReceipt(t, s, "sha256:UP-A")
	rcptB := seedReceipt(t, s, "sha256:UP-B")
	item := func(rcpt, up string) CloudOutboxItem {
		return CloudOutboxItem{SessionID: "sess-dup", EvidenceContentDigest: "sha256:EV", UploadDigest: up, ReceiptID: rcpt}
	}

	first, err := s.EnqueueCloudOutbox(ctx, item(rcptA, "sha256:UP-A"))
	if err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if _, err := s.EnqueueCloudOutbox(ctx, item(rcptA2, "sha256:UP-A")); !errors.Is(err, ErrCloudOutboxDuplicate) {
		t.Fatalf("second enqueue of identical bytes: want ErrCloudOutboxDuplicate, got %v", err)
	}
	live, found, err := s.FindLiveCloudOutboxForUpload(ctx, "sess-dup", "sha256:UP-A")
	if err != nil || !found || live.ID != first {
		t.Fatalf("FindLiveCloudOutboxForUpload: found=%v id=%q err=%v, want the first job %q", found, live.ID, err, first)
	}
	// Different bytes for the same session are a different upload.
	if _, err := s.EnqueueCloudOutbox(ctx, item(rcptB, "sha256:UP-B")); err != nil {
		t.Fatalf("enqueue of different bytes: %v", err)
	}
	// Once the first is terminal (sent), the identical bytes may be queued again
	// (a deliberate re-run is the caller's decision, not the store's).
	if err := s.moveCloudOutbox(ctx, first, []CloudOutboxState{CloudOutboxPending}, CloudOutboxSent, false, ""); err != nil {
		t.Fatalf("move first to sent: %v", err)
	}
	if _, _, err := s.FindLiveCloudOutboxForUpload(ctx, "sess-dup", "sha256:UP-A"); err != nil {
		t.Fatalf("FindLiveCloudOutboxForUpload after sent: %v", err)
	} else if _, found, _ := s.FindLiveCloudOutboxForUpload(ctx, "sess-dup", "sha256:UP-A"); found {
		t.Fatalf("a sent job must not count as live")
	}
	if _, err := s.EnqueueCloudOutbox(ctx, item(rcptA2, "sha256:UP-A")); err != nil {
		t.Fatalf("re-enqueue after sent: %v", err)
	}
}

// TestCloudResultCursorPerHost pins the per-host results cursor (2026-09-15):
// staging's cursor must never be replayed against production - each host
// starts from "" and advances independently, the bare legacy key is a
// separate slot, and HasCloudResultCursor sees any of them.
func TestCloudResultCursorPerHost(t *testing.T) {
	s, _ := cloudTestStore(t)
	ctx := context.Background()
	if has, err := s.HasCloudResultCursor(ctx); err != nil || has {
		t.Fatalf("fresh store: has=%v err=%v, want false", has, err)
	}
	if err := s.SaveCloudResultCursor(ctx, "staging-cloud.superbased.app", "v2:6"); err != nil {
		t.Fatalf("save staging: %v", err)
	}
	if v, err := s.LoadCloudResultCursor(ctx, "cloud.superbased.app"); err != nil || v != "" {
		t.Fatalf("prod cursor after staging save = %q err=%v, want \"\" (fresh pull per host)", v, err)
	}
	if v, err := s.LoadCloudResultCursor(ctx, "STAGING-cloud.superbased.app"); err != nil || v != "v2:6" {
		t.Fatalf("staging cursor (case-insensitive host) = %q err=%v, want v2:6", v, err)
	}
	if v, _ := s.LoadCloudResultCursor(ctx, ""); v != "" {
		t.Fatalf("legacy bare key = %q, want \"\" (never a fallback)", v)
	}
	if err := s.SaveCloudResultCursor(ctx, "cloud.superbased.app", "v2:2"); err != nil {
		t.Fatalf("save prod: %v", err)
	}
	if v, _ := s.LoadCloudResultCursor(ctx, "cloud.superbased.app"); v != "v2:2" {
		t.Fatalf("prod cursor = %q, want v2:2", v)
	}
	if v, _ := s.LoadCloudResultCursor(ctx, "staging-cloud.superbased.app"); v != "v2:6" {
		t.Fatalf("staging cursor disturbed: %q", v)
	}
	if has, _ := s.HasCloudResultCursor(ctx); !has {
		t.Fatalf("HasCloudResultCursor = false after saves")
	}
	if err := s.SaveCloudResultCursor(ctx, "cloud.superbased.app", ""); err != nil {
		t.Fatalf("empty save: %v", err)
	}
	if v, _ := s.LoadCloudResultCursor(ctx, "cloud.superbased.app"); v != "v2:2" {
		t.Fatalf("empty save clobbered the cursor: %q", v)
	}
}
