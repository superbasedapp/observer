//go:build !sbo_omit_security

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestLoadChangeFacts pins the record builder's attribution read: the
// co-contributed commit names both sessions, carries the AI lines the
// linkage reached per file and leaves human capture unmeasured; a commit
// no AI edit reached and a commit not in the ledger get no record.
func TestLoadChangeFacts(t *testing.T) {
	t.Parallel()
	s, projectID, _ := ownershipFixture(t)
	ctx := context.Background()
	f, skip, err := s.LoadChangeFacts(ctx, projectID, strings.Repeat("a", 64), "c1sha", 0)
	if err != nil || skip != "" {
		t.Fatalf("c1: skip %q err %v", skip, err)
	}
	if strings.Join(f.Sessions, ",") != "sA,sB" || len(f.Files) != 3 || len(f.PromptIDs) != 2 {
		t.Fatalf("c1 facts = %+v", f)
	}
	ai := 0
	for _, x := range f.Files {
		ai += x.AI
		if x.RelPath == "" || x.PathHash == "" {
			t.Errorf("file without path or hash: %+v", x)
		}
	}
	if ai == 0 || f.HumanCapture != "none" || len(f.Tools) == 0 {
		t.Errorf("c1: ai lines %d, human capture %q, tools %v", ai, f.HumanCapture, f.Tools)
	}
	if f.Evidence != nil {
		t.Errorf("no sandbox run: evidence must be nil, got %+v", f.Evidence)
	}
	if _, skip, _ := s.LoadChangeFacts(ctx, projectID, "h", "c2sha", 0); skip != ChangeSkipNotOwned {
		t.Errorf("c2 skip = %q, want %q", skip, ChangeSkipNotOwned)
	}
	if _, skip, _ := s.LoadChangeFacts(ctx, projectID, "h", "nosuch", 0); skip != ChangeSkipUnknownCommit {
		t.Errorf("unknown skip = %q", skip)
	}
}

func changeRow(root, sha string) ChangeRecordRow {
	return ChangeRecordRow{
		ProjectID: 1, ProjectRootHash: root, CommitSHA: sha, TreeSHA: strings.Repeat("2", 40),
		PatchFP: strings.Repeat("3", 40), KeyID: strings.Repeat("4", 32), AttestationLevel: "self_attested",
		KeyStorage: "keychain", RecordDigest: strings.Repeat("5", 64), Envelope: []byte(`{}`),
		Files: 1, AILines: 4, UnknownLines: 1, HumanCapture: "none",
		Sessions: []string{"sess-1"}, Models: []string{"claude-opus-5-5"}, Tools: []string{"claude-code"},
		Paths:       []string{"src/a.go"},
		CommittedAt: time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		RecordedAt:  time.Now().UTC().Format(time.RFC3339),
	}
}

func TestChangeRecordTables(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	root, sha := strings.Repeat("a", 64), strings.Repeat("1", 40)
	if ok, err := s.InsertChangeRecord(ctx, changeRow(root, sha)); err != nil || !ok {
		t.Fatalf("insert: %v %v", ok, err)
	}
	if ok, _ := s.InsertChangeRecord(ctx, changeRow(root, sha)); ok {
		t.Fatal("the same project, commit and key recorded twice")
	}
	if has, _ := s.HasChangeRecord(ctx, root, sha); !has {
		t.Fatal("HasChangeRecord = false")
	}
	recs, err := s.ListChangeRecords(ctx, root, 10)
	if err != nil || len(recs) != 1 || recs[0].Paths[0] != "src/a.go" || recs[0].NoteWrittenAt != "" {
		t.Fatalf("list: %+v %v", recs, err)
	}
	pending, _ := s.ChangeRecordsWithoutNote(ctx, root, 10)
	if len(pending) != 1 {
		t.Fatal("record without a note not listed")
	}
	if err := s.MarkChangeNoteWritten(ctx, recs[0].ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if pending, _ := s.ChangeRecordsWithoutNote(ctx, root, 10); len(pending) != 0 {
		t.Fatal("note written but still pending")
	}

	// Keys: the newest unretired one is active; a retired key stays listed.
	now := time.Now().UTC()
	for i, id := range []string{"k1", "k2"} {
		if err := s.SaveChangeKey(ctx, ChangeKey{KeyID: id, PublicKey: "p", Storage: "keychain", Attestation: "self_attested", CreatedAt: now.Add(time.Duration(i) * time.Minute).Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	}
	if k, ok, _ := s.ActiveChangeKey(ctx); !ok || k.KeyID != "k2" {
		t.Fatalf("active = %+v", k)
	}
	if err := s.RetireChangeKey(ctx, "k2", "rotate_age", now); err != nil {
		t.Fatal(err)
	}
	if k, _, _ := s.ActiveChangeKey(ctx); k.KeyID != "k1" {
		t.Fatalf("after retire active = %+v", k)
	}
	if keys, _ := s.ChangeKeys(ctx); len(keys) != 2 {
		t.Fatalf("keys = %d, want 2 (retired kept)", len(keys))
	}

	// Consent: given, then withdrawn (history kept).
	c := ChangeConsent{ProjectRootHash: root, RootPath: "/repo", Notes: true, Surface: "cli"}
	if err := s.SetChangeConsent(ctx, c, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeConsentFor(ctx, root); !got.Notes || got.Trailer || got.GivenAt == "" {
		t.Fatalf("consent = %+v", got)
	}
	c.Notes = false
	if err := s.SetChangeConsent(ctx, c, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ChangeConsentFor(ctx, root); got.Notes || got.RevokedAt == "" || got.GivenAt == "" {
		t.Fatalf("withdrawn consent = %+v", got)
	}
	if none, _ := s.ChangeConsentFor(ctx, "other"); none.Notes || none.Trailer {
		t.Fatal("no row must mean no consent")
	}
}

// TestChangeRecordFamilyWaitsForTheLoop is audit finding F6: a push that
// runs before the provenance loop is up skips the change record family
// instead of committing it empty, so the records already in the table ship
// on the first push after the loop starts.
func TestChangeRecordFamilyWaitsForTheLoop(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	root := sha256Hex("/repo/a")
	if _, err := s.InsertChangeRecord(ctx, changeRow(root, strings.Repeat("1", 40))); err != nil {
		t.Fatal(err)
	}
	live := false
	p := secOrgProviders(s, SecurityShare{Level: "findings"})
	p.ChangeRecords = func(ctx context.Context, max int, scope SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
		if !live {
			return nil, nil
		}
		return s.SelectChangeRecordRows(ctx, max, scope)
	}
	p.ChangeRecordsLive = func() bool { return live }
	s.SetSecurityOrgProviders(p)
	b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@x", ShareOptions{}, ScopeOptions{})
	if err != nil || len(b.AIChangeRecords) != 0 {
		t.Fatalf("before the loop: %d rows %v", len(b.AIChangeRecords), err)
	}
	s.CommitPushedSnapshots()
	live = true
	b, err = s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@x", ShareOptions{}, ScopeOptions{})
	if err != nil || len(b.AIChangeRecords) != 1 {
		t.Fatalf("after the loop started: %d rows %v", len(b.AIChangeRecords), err)
	}
}

// TestChangeRecordWireShareModes pins the producer through the E2 seam in
// every share mode: nothing at off and posture, metadata at findings, and
// the commit sha and paths only under raw content; a project outside the
// push's scope never ships.
func TestChangeRecordWireShareModes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cases := []struct {
		name    string
		level   SecurityShare
		share   ShareOptions
		scope   ScopeOptions
		wantRow bool
		wantRaw bool
	}{
		{"off", SecurityShare{Level: "off"}, ShareOptions{FullContent: true}, ScopeOptions{}, false, false},
		{"posture", SecurityShare{Level: "posture"}, ShareOptions{FullContent: true}, ScopeOptions{}, false, false},
		{"findings, metadata only", SecurityShare{Level: "findings"}, ShareOptions{}, ScopeOptions{}, true, false},
		{"findings, raw (own opt-in)", SecurityShare{Level: "findings"}, ShareOptions{FullContent: true}, ScopeOptions{}, true, true},
		{"findings, raw (managed grant)", SecurityShare{Level: "findings"}, ShareOptions{EnterpriseGranted: true}, ScopeOptions{}, true, true},
		{"findings, project denied", SecurityShare{Level: "findings"}, ShareOptions{FullContent: true}, ScopeOptions{ProjectRootDenylist: []string{"/repo/denied"}}, false, false},
	}
	for _, c := range cases {
		s, _ := newTestStore(t)
		root := sha256Hex("/repo/denied")
		if _, err := s.InsertChangeRecord(ctx, changeRow(root, strings.Repeat("1", 40))); err != nil {
			t.Fatal(err)
		}
		p := secOrgProviders(s, c.level)
		p.ChangeRecords = s.SelectChangeRecordRows
		s.SetSecurityOrgProviders(p)
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@x", c.share, c.scope)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := len(b.AIChangeRecords) == 1; got != c.wantRow {
			t.Fatalf("%s: rows %d, want one=%v", c.name, len(b.AIChangeRecords), c.wantRow)
		}
		if !c.wantRow {
			continue
		}
		r := b.AIChangeRecords[0]
		if (r.CommitSHA != "") != c.wantRaw || (len(r.Paths) != 0) != c.wantRaw {
			t.Errorf("%s: raw fields sha=%q paths=%v, want raw=%v", c.name, r.CommitSHA, r.Paths, c.wantRaw)
		}
		if r.CommitIdentityHash != ChangeCommitIdentityHash(root, strings.Repeat("1", 40)) || r.CommitIdentityHash == strings.Repeat("1", 40) {
			t.Errorf("%s: commit identity %q", c.name, r.CommitIdentityHash)
		}
		if r.AttestationLevel != "local" || r.HumanCapture != "none" || r.AILines != 4 || r.UserEmail != "dev@x" || r.OrgID != "org-1" {
			t.Errorf("%s: always fields %+v", c.name, r)
		}
	}
}
