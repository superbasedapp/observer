package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestNormalizeTag is the table-driven pin on the plan §0 normalization rules:
// trim, lowercase, whitespace-runs → '-', charset [a-z0-9._-], 1..40 chars.
// Anything else is REJECTED (never silently stripped) so two intended labels
// can't collapse into one vocabulary entry.
func TestNormalizeTag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"plain", "backend", "backend", false},
		{"trims", "  backend  ", "backend", false},
		{"lowercases", "Backend", "backend", false},
		{"space to dash", "ui ux", "ui-ux", false},
		{"space run collapses", "ui   ux", "ui-ux", false},
		{"tab and newline are whitespace", "ui\tux\nrework", "ui-ux-rework", false},
		{"leading/trailing dashes trimmed", "--junk--", "junk", false},
		{"internal dot underscore dash kept", "v1.8_2-rc", "v1.8_2-rc", false},
		{"digits ok", "2026", "2026", false},
		{"empty rejected", "", "", true},
		{"whitespace only rejected", "   \t ", "", true},
		{"dashes only rejected", "---", "", true},
		{"unicode letter rejected", "café", "", true},
		{"emoji rejected", "junk🔥", "", true},
		{"cyrillic rejected", "бэкенд", "", true},
		{"slash rejected", "ui/ux", "", true},
		{"colon rejected", "ticket:123", "", true},
		{"hash rejected", "#backend", "", true},
		{"at 40 chars ok", strings.Repeat("a", MaxTagLen), strings.Repeat("a", MaxTagLen), false},
		{"41 chars rejected", strings.Repeat("a", MaxTagLen+1), "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeTag(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeTag(%q) = %q, want error", tc.in, got)
				}
				if !errors.Is(err, ErrInvalidTag) {
					t.Fatalf("NormalizeTag(%q) error = %v, want ErrInvalidTag", tc.in, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeTag(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeTag(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestMutateSessionTagsIdempotent pins add/remove idempotence, normalization on
// write, and remove-before-add ordering.
func TestMutateSessionTagsIdempotent(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const sid = "sess-tags-1"

	if err := s.MutateSessionTags(ctx, sid, []string{"Backend", "ui ux"}, nil); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Re-adding the same tags is a no-op, not a constraint error.
	if err := s.MutateSessionTags(ctx, sid, []string{"backend", "ui-ux"}, nil); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	got, err := s.SessionTags(ctx, sid)
	if err != nil {
		t.Fatalf("SessionTags: %v", err)
	}
	if len(got) != 2 || got[0] != "backend" || got[1] != "ui-ux" {
		t.Fatalf("tags after add = %v, want [backend ui-ux]", got)
	}

	// Removing an absent tag is a no-op.
	if err := s.MutateSessionTags(ctx, sid, nil, []string{"never-applied"}); err != nil {
		t.Fatalf("remove absent: %v", err)
	}
	if err := s.MutateSessionTags(ctx, sid, nil, []string{"backend"}); err != nil {
		t.Fatalf("remove: %v", err)
	}
	got, _ = s.SessionTags(ctx, sid)
	if len(got) != 1 || got[0] != "ui-ux" {
		t.Fatalf("tags after remove = %v, want [ui-ux]", got)
	}

	// An invalid tag anywhere in the batch fails the WHOLE call.
	if err := s.MutateSessionTags(ctx, sid, []string{"valid", "invalid/tag"}, nil); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("invalid tag in batch: err=%v, want ErrInvalidTag", err)
	}
	got, _ = s.SessionTags(ctx, sid)
	if len(got) != 1 {
		t.Fatalf("rejected batch mutated state: %v", got)
	}
	if err := s.MutateSessionTags(ctx, "", []string{"x"}, nil); err == nil {
		t.Fatal("empty session id accepted")
	}
}

// TestMutateSessionTagsCap pins MaxTagsPerSession: the cap is checked AFTER
// removals (so a swap on a full session succeeds) and a rejected add writes
// nothing.
func TestMutateSessionTagsCap(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	const sid = "sess-tags-cap"

	full := make([]string, 0, MaxTagsPerSession)
	for i := 0; i < MaxTagsPerSession; i++ {
		full = append(full, fmt.Sprintf("tag-%02d", i))
	}
	if err := s.MutateSessionTags(ctx, sid, full, nil); err != nil {
		t.Fatalf("seed %d tags: %v", MaxTagsPerSession, err)
	}

	// One more exceeds the cap and writes nothing.
	if err := s.MutateSessionTags(ctx, sid, []string{"one-too-many"}, nil); !errors.Is(err, ErrTooManyTags) {
		t.Fatalf("over-cap add: err=%v, want ErrTooManyTags", err)
	}
	got, _ := s.SessionTags(ctx, sid)
	if len(got) != MaxTagsPerSession {
		t.Fatalf("over-cap add mutated state: %d tags", len(got))
	}

	// Re-adding an EXISTING tag on a full session is fine (no growth).
	if err := s.MutateSessionTags(ctx, sid, []string{"tag-00"}, nil); err != nil {
		t.Fatalf("idempotent add on a full session: %v", err)
	}

	// A swap succeeds because removals apply first.
	if err := s.MutateSessionTags(ctx, sid, []string{"swapped-in"}, []string{"tag-00"}); err != nil {
		t.Fatalf("swap on a full session: %v", err)
	}
	got, _ = s.SessionTags(ctx, sid)
	if len(got) != MaxTagsPerSession {
		t.Fatalf("after swap = %d tags, want %d", len(got), MaxTagsPerSession)
	}
	for _, tag := range got {
		if tag == "tag-00" {
			t.Fatal("swap did not remove tag-00")
		}
	}
}

// TestSetSessionAnnotationPartialAndGC pins the partial-update semantics (nil
// pointer = leave alone) and the row garbage-collection when the state returns
// to favorite=false AND note="".
func TestSetSessionAnnotationPartialAndGC(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	const sid = "sess-annot-1"

	countRows := func() int {
		var n int
		if err := db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM session_annotations WHERE session_id = ?`, sid).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		return n
	}

	if a, err := s.GetSessionAnnotation(ctx, sid); err != nil || a.Favorite || a.Note != "" {
		t.Fatalf("unannotated session: %+v err=%v, want zero value", a, err)
	}

	yes, no := true, false
	if err := s.SetSessionAnnotation(ctx, sid, &yes, nil, nil, nil); err != nil {
		t.Fatalf("set favorite: %v", err)
	}
	if countRows() != 1 {
		t.Fatal("favorite=true did not create a row")
	}

	note := "the run where compression broke"
	if err := s.SetSessionAnnotation(ctx, sid, nil, &note, nil, nil); err != nil {
		t.Fatalf("set note: %v", err)
	}
	a, err := s.GetSessionAnnotation(ctx, sid)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !a.Favorite || a.Note != note {
		t.Fatalf("partial update clobbered a field: %+v", a)
	}

	// Un-favoriting alone keeps the row (the note still carries meaning).
	if err := s.SetSessionAnnotation(ctx, sid, &no, nil, nil, nil); err != nil {
		t.Fatalf("unset favorite: %v", err)
	}
	if countRows() != 1 {
		t.Fatal("row GC'd while a note was still set")
	}

	// A rating alone keeps the row after the note is cleared.
	empty := ""
	seven := 7
	if err := s.SetSessionAnnotation(ctx, sid, nil, &empty, &seven, nil); err != nil {
		t.Fatalf("clear note + set rating: %v", err)
	}
	if countRows() != 1 {
		t.Fatal("row GC'd while a rating was still set")
	}
	if a, err := s.GetSessionAnnotation(ctx, sid); err != nil || a.Rating != 7 {
		t.Fatalf("rating not persisted: %+v err=%v, want Rating=7", a, err)
	}

	// A title alone keeps the row after the rating is cleared.
	zeroRating := 0
	title := "the compression regression run"
	if err := s.SetSessionAnnotation(ctx, sid, nil, nil, &zeroRating, &title); err != nil {
		t.Fatalf("clear rating + set title: %v", err)
	}
	if countRows() != 1 {
		t.Fatal("row GC'd while a title was still set")
	}
	if a, err := s.GetSessionAnnotation(ctx, sid); err != nil || a.Title != title {
		t.Fatalf("title not persisted: %+v err=%v, want Title=%q", a, err, title)
	}

	// Clearing the title too ("") returns the state to zero → the row is GC'd.
	emptyTitle := ""
	if err := s.SetSessionAnnotation(ctx, sid, nil, nil, nil, &emptyTitle); err != nil {
		t.Fatalf("clear title: %v", err)
	}
	if countRows() != 0 {
		t.Fatal("zero-value annotation row was not garbage-collected")
	}

	long := strings.Repeat("x", MaxNoteLen+1)
	if err := s.SetSessionAnnotation(ctx, sid, nil, &long, nil, nil); !errors.Is(err, ErrNoteTooLong) {
		t.Fatalf("over-long note: err=%v, want ErrNoteTooLong", err)
	}
	badRating := MaxRating + 1
	if err := s.SetSessionAnnotation(ctx, sid, nil, nil, &badRating, nil); !errors.Is(err, ErrInvalidRating) {
		t.Fatalf("out-of-range rating: err=%v, want ErrInvalidRating", err)
	}
	longTitle := strings.Repeat("t", MaxTitleLen+1)
	if err := s.SetSessionAnnotation(ctx, sid, nil, nil, nil, &longTitle); !errors.Is(err, ErrTitleTooLong) {
		t.Fatalf("over-long title: err=%v, want ErrTitleTooLong", err)
	}
	newlineTitle := "line one\nline two"
	if err := s.SetSessionAnnotation(ctx, sid, nil, nil, nil, &newlineTitle); !errors.Is(err, ErrInvalidTitle) {
		t.Fatalf("newline title: err=%v, want ErrInvalidTitle", err)
	}
	if err := s.SetSessionAnnotation(ctx, "", &yes, nil, nil, nil); err == nil {
		t.Fatal("empty session id accepted")
	}
}

// TestListSessionTagsAndAnnotationsBatched pins the batched page loads: one
// query each, sessions with nothing are absent from the map, and an empty id
// list returns an empty (non-nil) map without touching the DB.
func TestListSessionTagsAndAnnotationsBatched(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.MutateSessionTags(ctx, "a", []string{"backend", "experiment"}, nil); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if err := s.MutateSessionTags(ctx, "b", []string{"junk"}, nil); err != nil {
		t.Fatalf("seed b: %v", err)
	}
	yes := true
	if err := s.SetSessionAnnotation(ctx, "b", &yes, nil, nil, nil); err != nil {
		t.Fatalf("seed annotation b: %v", err)
	}
	title := "the compression baseline"
	if err := s.SetSessionAnnotation(ctx, "a", nil, nil, nil, &title); err != nil {
		t.Fatalf("seed title a: %v", err)
	}

	tags, err := s.ListSessionTags(ctx, []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("ListSessionTags: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("ListSessionTags = %v, want 2 keyed sessions", tags)
	}
	if got := tags["a"]; len(got) != 2 || got[0] != "backend" || got[1] != "experiment" {
		t.Fatalf("tags[a] = %v, want sorted [backend experiment]", got)
	}
	if _, ok := tags["c"]; ok {
		t.Fatal("untagged session c present in the map")
	}

	annots, err := s.ListAnnotations(ctx, []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("ListAnnotations: %v", err)
	}
	if len(annots) != 2 || !annots["b"].Favorite {
		t.Fatalf("ListAnnotations = %v, want b favorited and a titled", annots)
	}
	if annots["a"].Title != title {
		t.Fatalf("ListAnnotations[a].Title = %q, want %q", annots["a"].Title, title)
	}

	if m, err := s.ListSessionTags(ctx, nil); err != nil || m == nil || len(m) != 0 {
		t.Fatalf("ListSessionTags(nil) = %v err=%v, want empty non-nil map", m, err)
	}
	if m, err := s.ListAnnotations(ctx, nil); err != nil || m == nil || len(m) != 0 {
		t.Fatalf("ListAnnotations(nil) = %v err=%v, want empty non-nil map", m, err)
	}

	assign, err := s.TagAssignments(ctx)
	if err != nil {
		t.Fatalf("TagAssignments: %v", err)
	}
	if len(assign) != 2 || len(assign["a"]) != 2 || len(assign["b"]) != 1 {
		t.Fatalf("TagAssignments = %v", assign)
	}
}

// TestTagVocabularyAndSessionIDsForTag pins the DISTINCT-derived vocabulary
// (count desc, tag asc) and the per-tag session lookup that feeds
// cost.Options.SessionIDs.
func TestTagVocabularyAndSessionIDsForTag(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	for _, sid := range []string{"s1", "s2", "s3"} {
		if err := s.MutateSessionTags(ctx, sid, []string{"backend"}, nil); err != nil {
			t.Fatalf("seed %s: %v", sid, err)
		}
	}
	if err := s.MutateSessionTags(ctx, "s1", []string{"experiment"}, nil); err != nil {
		t.Fatalf("seed s1 experiment: %v", err)
	}

	vocab, err := s.TagVocabulary(ctx)
	if err != nil {
		t.Fatalf("TagVocabulary: %v", err)
	}
	if len(vocab) != 2 {
		t.Fatalf("vocabulary = %v, want 2 entries", vocab)
	}
	if vocab[0].Tag != "backend" || vocab[0].Sessions != 3 {
		t.Fatalf("vocab[0] = %+v, want backend/3 first (count desc)", vocab[0])
	}
	if vocab[1].Tag != "experiment" || vocab[1].Sessions != 1 {
		t.Fatalf("vocab[1] = %+v", vocab[1])
	}

	ids, err := s.SessionIDsForTag(ctx, "Backend", 0)
	if err != nil {
		t.Fatalf("SessionIDsForTag: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("SessionIDsForTag = %v, want 3", ids)
	}
	if ids, err := s.SessionIDsForTag(ctx, "backend", 2); err != nil || len(ids) != 2 {
		t.Fatalf("SessionIDsForTag limit 2 = %v err=%v", ids, err)
	}
	if _, err := s.SessionIDsForTag(ctx, "bad/tag", 0); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("SessionIDsForTag(invalid) err=%v, want ErrInvalidTag", err)
	}
}

// TestRenameTagMergesCollisions pins the merge behaviour: renaming onto a tag a
// session already carries must collapse to ONE row (INSERT OR IGNORE + delete),
// never a constraint error and never a duplicate.
func TestRenameTagMergesCollisions(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	// s1 carries both → collision. s2 carries only the source.
	if err := s.MutateSessionTags(ctx, "s1", []string{"be", "backend"}, nil); err != nil {
		t.Fatalf("seed s1: %v", err)
	}
	if err := s.MutateSessionTags(ctx, "s2", []string{"be"}, nil); err != nil {
		t.Fatalf("seed s2: %v", err)
	}

	n, err := s.RenameTag(ctx, "be", "backend")
	if err != nil {
		t.Fatalf("RenameTag: %v", err)
	}
	if n != 2 {
		t.Fatalf("RenameTag affected = %d, want 2 (both source rows)", n)
	}
	got, _ := s.SessionTags(ctx, "s1")
	if len(got) != 1 || got[0] != "backend" {
		t.Fatalf("s1 after merge = %v, want [backend]", got)
	}
	got, _ = s.SessionTags(ctx, "s2")
	if len(got) != 1 || got[0] != "backend" {
		t.Fatalf("s2 after rename = %v, want [backend]", got)
	}
	vocab, _ := s.TagVocabulary(ctx)
	if len(vocab) != 1 || vocab[0].Tag != "backend" || vocab[0].Sessions != 2 {
		t.Fatalf("vocabulary after merge = %v", vocab)
	}

	// Renaming to itself (after normalization) is a no-op, not a delete.
	if n, err := s.RenameTag(ctx, "backend", "Backend"); err != nil || n != 0 {
		t.Fatalf("self-rename = %d err=%v, want 0/nil", n, err)
	}
	if vocab, _ := s.TagVocabulary(ctx); len(vocab) != 1 {
		t.Fatalf("self-rename dropped the tag: %v", vocab)
	}
	if _, err := s.RenameTag(ctx, "backend", "bad tag/x"); !errors.Is(err, ErrInvalidTag) {
		t.Fatalf("rename to invalid: err=%v, want ErrInvalidTag", err)
	}
}

// TestDeleteTag pins vocabulary deletion: every assignment row drops, the count
// is returned, and deleting an unknown tag is a zero-affected no-op.
func TestDeleteTag(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	if err := s.MutateSessionTags(ctx, "s1", []string{"junk", "keep"}, nil); err != nil {
		t.Fatalf("seed s1: %v", err)
	}
	if err := s.MutateSessionTags(ctx, "s2", []string{"junk"}, nil); err != nil {
		t.Fatalf("seed s2: %v", err)
	}

	n, err := s.DeleteTag(ctx, "JUNK")
	if err != nil {
		t.Fatalf("DeleteTag: %v", err)
	}
	if n != 2 {
		t.Fatalf("DeleteTag affected = %d, want 2", n)
	}
	got, _ := s.SessionTags(ctx, "s1")
	if len(got) != 1 || got[0] != "keep" {
		t.Fatalf("s1 after delete = %v, want [keep]", got)
	}
	if n, err := s.DeleteTag(ctx, "never-existed"); err != nil || n != 0 {
		t.Fatalf("delete unknown = %d err=%v, want 0/nil", n, err)
	}
}

// TestResolveSessionIDPrefix pins the CLI's unique-prefix resolution: exact
// match wins, a unique prefix resolves, an ambiguous prefix returns the
// candidate list, and an unknown prefix returns ErrSessionNotFound.
func TestResolveSessionIDPrefix(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()

	pid, err := s.UpsertProject(ctx, "/tmp/tagproj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	for _, id := range []string{"abc111", "abc222", "zzz999"} {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', '2026-07-30T00:00:00Z')`,
			id, pid); err != nil {
			t.Fatalf("seed session %s: %v", id, err)
		}
	}

	if got, err := s.ResolveSessionIDPrefix(ctx, "zzz", 10); err != nil || got != "zzz999" {
		t.Fatalf("unique prefix = %q err=%v", got, err)
	}
	if got, err := s.ResolveSessionIDPrefix(ctx, "abc111", 10); err != nil || got != "abc111" {
		t.Fatalf("full id = %q err=%v", got, err)
	}

	_, err = s.ResolveSessionIDPrefix(ctx, "abc", 10)
	var amb *ErrSessionPrefixAmbiguous
	if !errors.As(err, &amb) {
		t.Fatalf("ambiguous prefix err=%v, want *ErrSessionPrefixAmbiguous", err)
	}
	if len(amb.Candidates) != 2 {
		t.Fatalf("candidates = %v, want 2", amb.Candidates)
	}

	if _, err := s.ResolveSessionIDPrefix(ctx, "nope", 10); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("unknown prefix err=%v, want ErrSessionNotFound", err)
	}
	// A prefix carrying SQL wildcards must not widen the match.
	if _, err := s.ResolveSessionIDPrefix(ctx, "%", 10); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("wildcard prefix err=%v, want ErrSessionNotFound", err)
	}
	if _, err := s.ResolveSessionIDPrefix(ctx, "  ", 10); err == nil {
		t.Fatal("blank prefix accepted")
	}
}

// TestValidateClassificationInput is the table-driven pin on the whole-request
// pre-flight that makes a combined tag+annotation mutation all-or-nothing: the
// handler and `observer tag` call it BEFORE any write, so a body that would be
// rejected halfway through never commits its first half.
func TestValidateClassificationInput(t *testing.T) {
	t.Parallel()
	note := func(n int) *string { s := strings.Repeat("n", n); return &s }
	many := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("t%d", i))
		}
		return out
	}
	rating := func(n int) *int { return &n }
	title := func(s string) *string { return &s }
	longTitle := func(n int) *string { s := strings.Repeat("t", n); return &s }
	tests := []struct {
		name    string
		add     []string
		remove  []string
		note    *string
		rating  *int
		title   *string
		wantErr error
	}{
		{"empty", nil, nil, nil, nil, nil, nil},
		{"valid combo", []string{"Backend", "ui ux"}, []string{"junk"}, note(MaxNoteLen), rating(MaxRating), title("baseline run"), nil},
		{"invalid add", []string{"bad/tag"}, nil, nil, nil, nil, ErrInvalidTag},
		{"invalid remove", nil, []string{"bad/tag"}, nil, nil, nil, ErrInvalidTag},
		{"note one over", nil, nil, note(MaxNoteLen + 1), nil, nil, ErrNoteTooLong},
		{"add list over cap", many(MaxTagsPerSession + 1), nil, nil, nil, nil, ErrTooManyTags},
		{"add list at cap", many(MaxTagsPerSession), nil, nil, nil, nil, nil},
		{"duplicates do not consume cap", append(many(MaxTagsPerSession), "t0", "T0"), nil, nil, nil, nil, nil},
		// The whole body is judged: valid tags + an over-long note is a
		// rejection, which is exactly the case that used to half-commit.
		{"valid tags with over-long note", []string{"x"}, nil, note(MaxNoteLen + 1), nil, nil, ErrNoteTooLong},
		// Rating bounds: 0 (clear) and MaxRating are valid; over/under are not.
		{"rating clear", nil, nil, nil, rating(0), nil, nil},
		{"rating at max", nil, nil, nil, rating(MaxRating), nil, nil},
		{"rating over max", nil, nil, nil, rating(MaxRating + 1), nil, ErrInvalidRating},
		{"rating negative", nil, nil, nil, rating(-1), nil, ErrInvalidRating},
		// Title bounds: "" (clear) and MaxTitleLen are valid; over-long and a
		// newline are not.
		{"title clear", nil, nil, nil, nil, title(""), nil},
		{"title at max", nil, nil, nil, nil, longTitle(MaxTitleLen), nil},
		{"title one over", nil, nil, nil, nil, longTitle(MaxTitleLen + 1), ErrTitleTooLong},
		{"title with newline", nil, nil, nil, nil, title("line one\nline two"), ErrInvalidTitle},
		{"valid tags with over-long title", []string{"x"}, nil, nil, nil, longTitle(MaxTitleLen + 1), ErrTitleTooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClassificationInput(tc.add, tc.remove, tc.note, tc.rating, tc.title)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateClassificationInput = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateClassificationInput = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestResolveSessionIDPrefixExactBeatsCollisions pins the exact-match-first
// rule (codex MEDIUM #5b). A full session id that is ALSO the prefix of many
// newer sessions must resolve to itself: the pre-fix resolver ran the prefix
// query with LIMIT maxList+1 ordered by started_at DESC and only then looked
// for the exact id inside that window, so 11 newer collisions pushed the exact
// row out of the result set and a fully-typed id came back "ambiguous".
func TestResolveSessionIDPrefixExactBeatsCollisions(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/prefixproj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	insert := func(id, startedAt string) {
		t.Helper()
		if _, err := db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', ?)`,
			id, pid, startedAt); err != nil {
			t.Fatalf("seed session %s: %v", id, err)
		}
	}
	// The exact id is the OLDEST row.
	insert("sess-exact", "2026-01-01T00:00:00Z")
	// 11 newer sessions that all carry it as a prefix - one more than the
	// default candidate list cap, so the exact row cannot survive on luck.
	for i := 0; i < 11; i++ {
		insert(fmt.Sprintf("sess-exact-child-%02d", i), fmt.Sprintf("2026-07-%02dT00:00:00Z", i+1))
	}

	got, err := s.ResolveSessionIDPrefix(ctx, "sess-exact", 10)
	if err != nil {
		t.Fatalf("exact id with 11 prefix-collisions: %v", err)
	}
	if got != "sess-exact" {
		t.Fatalf("resolved %q, want the exact id sess-exact", got)
	}

	// A genuine prefix over the same corpus is still ambiguous, and the count
	// is reported HONESTLY as "10+" because the list is capped at 10 of 12.
	_, err = s.ResolveSessionIDPrefix(ctx, "sess-", 10)
	var amb *ErrSessionPrefixAmbiguous
	if !errors.As(err, &amb) {
		t.Fatalf("prefix err = %v, want *ErrSessionPrefixAmbiguous", err)
	}
	if !amb.Truncated {
		t.Fatalf("Truncated = false with 12 matches and a 10-candidate cap")
	}
	if len(amb.Candidates) != 10 {
		t.Fatalf("candidates = %d, want 10", len(amb.Candidates))
	}
	if amb.MatchCountLabel() != "10+" {
		t.Fatalf("MatchCountLabel = %q, want 10+", amb.MatchCountLabel())
	}
	if !strings.Contains(amb.Error(), "10+ matches") {
		t.Fatalf("Error() = %q, want an honest 10+ matches", amb.Error())
	}

	// An UNtruncated ambiguity still reports the exact count (no "+").
	_, err = s.ResolveSessionIDPrefix(ctx, "sess-exact-child-0", 10)
	if !errors.As(err, &amb) {
		t.Fatalf("child prefix err = %v, want *ErrSessionPrefixAmbiguous", err)
	}
	if amb.Truncated || amb.MatchCountLabel() != "10" {
		t.Fatalf("untruncated ambiguity reported %q (truncated=%v), want 10", amb.MatchCountLabel(), amb.Truncated)
	}
}

// TestSessionPrefixRangeQueryPlanUsesIndex pins the ACCESS PATH (codex LOW #5a):
// the prefix lookup must SEARCH the sessions primary-key index over a byte
// range, never SCAN the table. The pre-fix query filtered on
// substr(id, 1, ?) = ?, which no index can serve, so every abbreviated
// `observer tag <prefix>` read the whole sessions table.
func TestSessionPrefixRangeQueryPlanUsesIndex(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/planproj", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	for i := 0; i < 50; i++ {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, ?, 'claude-code', '2026-07-30T00:00:00Z')`,
			fmt.Sprintf("plan-%03d", i), pid); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	query, args, ok := sessionPrefixRangeQuery("plan-0", 11)
	if !ok {
		t.Fatal("sessionPrefixRangeQuery declined an ASCII prefix")
	}
	rows, err := db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+query, args...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("plan rows: %v", err)
	}
	if len(plan) == 0 {
		t.Fatal("empty query plan")
	}
	joined := strings.Join(plan, " | ")
	for _, step := range plan {
		if strings.HasPrefix(step, "SCAN sessions") {
			t.Fatalf("prefix lookup SCANS the sessions table: %s", joined)
		}
	}
	if !strings.Contains(joined, "SEARCH sessions") {
		t.Fatalf("prefix lookup does not SEARCH an index: %s", joined)
	}

	// The range path is declined only for prefixes with no representable
	// successor byte; ASCII ids (every adapter's shape) take the fast path.
	if _, _, ok := sessionPrefixRangeQuery("", 5); ok {
		t.Error("empty prefix must decline the range path")
	}
	if _, _, ok := sessionPrefixRangeQuery("cafeé", 5); ok {
		t.Error("prefix ending in a non-ASCII byte must decline the range path")
	}
	// ...and the resolver still WORKS on the declined shape (substr fallback).
	if _, err := s.ResolveSessionIDPrefix(ctx, "cafeé", 10); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("non-ASCII prefix fallback err = %v, want ErrSessionNotFound", err)
	}
}
