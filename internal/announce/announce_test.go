package announce

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// now is the fixed clock every table below reasons against — nothing in
// this package reads the wall clock, which is the point of Merge taking
// `now`.
var now = time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)

// valid returns a minimal well-formed announcement the tables mutate one
// field at a time.
func valid() Announcement {
	return Announcement{
		ID:        "2026-07-31-example",
		Severity:  SeverityInfo,
		Title:     "one line",
		Body:      "a short plain-text body",
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		Source:    SourceRelease,
	}
}

// with applies a mutator to a valid announcement — keeps each table row
// to the single field it is actually about.
func with(f func(*Announcement)) Announcement {
	a := valid()
	f(&a)
	return a
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		in      Announcement
		wantErr bool
		// wantMsg is a substring of the error, asserted so a row can't
		// pass by failing for an unrelated reason.
		wantMsg string
	}{
		{name: "minimal valid", in: valid()},
		{name: "https url accepted", in: with(func(a *Announcement) {
			a.URL = "https://superbased.app/docs/reference/measurement-honesty"
		})},
		{name: "org source accepted", in: with(func(a *Announcement) { a.Source = SourceOrg })},
		{name: "critical severity accepted", in: with(func(a *Announcement) { a.Severity = SeverityCritical })},
		{name: "notice severity accepted", in: with(func(a *Announcement) { a.Severity = SeverityNotice })},
		{name: "body at exactly 280 runes", in: with(func(a *Announcement) {
			a.Body = strings.Repeat("x", MaxBodyChars)
		})},
		{name: "multibyte body counted in runes not bytes", in: with(func(a *Announcement) {
			a.Body = strings.Repeat("é", MaxBodyChars) // 560 bytes, 280 runes
		})},

		{
			name:    "missing expiry rejected",
			in:      with(func(a *Announcement) { a.ExpiresAt = "" }),
			wantErr: true, wantMsg: "expires_at is required",
		},
		{
			name:    "whitespace expiry rejected",
			in:      with(func(a *Announcement) { a.ExpiresAt = "   " }),
			wantErr: true, wantMsg: "expires_at is required",
		},
		{
			name:    "non-RFC3339 expiry rejected",
			in:      with(func(a *Announcement) { a.ExpiresAt = "2026-08-01" }),
			wantErr: true, wantMsg: "not RFC3339",
		},
		{
			name:    "body over 280 rejected",
			in:      with(func(a *Announcement) { a.Body = strings.Repeat("x", MaxBodyChars+1) }),
			wantErr: true, wantMsg: "body is 281 chars",
		},
		{
			name:    "empty body rejected",
			in:      with(func(a *Announcement) { a.Body = "" }),
			wantErr: true, wantMsg: "body is required",
		},
		{
			name:    "newline in body rejected",
			in:      with(func(a *Announcement) { a.Body = "line one\nline two" }),
			wantErr: true, wantMsg: "plain text",
		},
		{
			name:    "http url rejected",
			in:      with(func(a *Announcement) { a.URL = "http://superbased.app/notes" }),
			wantErr: true, wantMsg: "url must be https",
		},
		{
			name:    "javascript url rejected",
			in:      with(func(a *Announcement) { a.URL = "javascript:alert(1)" }),
			wantErr: true, wantMsg: "url must be https",
		},
		{
			name:    "schemeless url rejected",
			in:      with(func(a *Announcement) { a.URL = "superbased.app/notes" }),
			wantErr: true, wantMsg: "url must be https",
		},
		{
			name:    "https url without host rejected",
			in:      with(func(a *Announcement) { a.URL = "https:///notes" }),
			wantErr: true, wantMsg: "no host",
		},
		{
			name:    "unknown severity rejected",
			in:      with(func(a *Announcement) { a.Severity = "warning" }),
			wantErr: true, wantMsg: `unknown severity "warning"`,
		},
		{
			name:    "empty severity rejected",
			in:      with(func(a *Announcement) { a.Severity = "" }),
			wantErr: true, wantMsg: "unknown severity",
		},
		{
			name:    "unknown source rejected",
			in:      with(func(a *Announcement) { a.Source = "vendor" }),
			wantErr: true, wantMsg: `unknown source "vendor"`,
		},
		{
			name:    "missing id rejected",
			in:      with(func(a *Announcement) { a.ID = "" }),
			wantErr: true, wantMsg: "id is required",
		},
		{
			name:    "over-long id rejected",
			in:      with(func(a *Announcement) { a.ID = strings.Repeat("i", MaxIDChars+1) }),
			wantErr: true, wantMsg: "id exceeds",
		},
		{
			name:    "missing title rejected",
			in:      with(func(a *Announcement) { a.Title = "" }),
			wantErr: true, wantMsg: "title is required",
		},
		{
			name:    "over-long title rejected",
			in:      with(func(a *Announcement) { a.Title = strings.Repeat("t", MaxTitleChars+1) }),
			wantErr: true, wantMsg: "title exceeds",
		},
		{
			name:    "newline in title rejected",
			in:      with(func(a *Announcement) { a.Title = "one\ntwo" }),
			wantErr: true, wantMsg: "single plain-text line",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := Validate(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate() = nil, want error")
				}
				if !errors.Is(err, ErrInvalid) {
					t.Errorf("Validate() error does not wrap ErrInvalid: %v", err)
				}
				if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
					t.Errorf("Validate() error = %q, want substring %q", err, tc.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestMergeExpiryBoundary pins the exact instant a banner retires: live
// strictly BEFORE ExpiresAt, gone at and after it.
func TestMergeExpiryBoundary(t *testing.T) {
	exp := now.Add(time.Hour)
	a := with(func(a *Announcement) { a.ExpiresAt = exp.Format(time.RFC3339) })

	tests := []struct {
		name string
		at   time.Time
		want int
	}{
		{name: "well before expiry", at: exp.Add(-time.Hour), want: 1},
		{name: "one second before expiry", at: exp.Add(-time.Second), want: 1},
		{name: "exactly at expiry is retired", at: exp, want: 0},
		{name: "one second after expiry", at: exp.Add(time.Second), want: 0},
		{name: "long after expiry", at: exp.Add(30 * 24 * time.Hour), want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Merge(tc.at, []Announcement{a})
			if len(got) != tc.want {
				t.Fatalf("Merge() returned %d announcements, want %d", len(got), tc.want)
			}
		})
	}
}

// TestMergeNeverReturnsNil pins the property the dashboard endpoint
// relies on to emit {"announcements":[]} rather than null.
func TestMergeNeverReturnsNil(t *testing.T) {
	if got := Merge(now); got == nil {
		t.Error("Merge() with no sources = nil, want empty non-nil slice")
	}
	if got := Merge(now, nil, []Announcement{}); got == nil {
		t.Error("Merge() with empty sources = nil, want empty non-nil slice")
	}
}

// TestMergeOrdering pins severity-descending, then newest (later
// expiry) first, then id.
func TestMergeOrdering(t *testing.T) {
	mk := func(id string, sev Severity, expiresIn time.Duration) Announcement {
		return with(func(a *Announcement) {
			a.ID = id
			a.Severity = sev
			a.ExpiresAt = now.Add(expiresIn).Format(time.RFC3339)
		})
	}
	in := []Announcement{
		mk("info-old", SeverityInfo, 24*time.Hour),
		mk("notice-new", SeverityNotice, 72*time.Hour),
		mk("critical", SeverityCritical, 1*time.Hour),
		mk("info-new", SeverityInfo, 48*time.Hour),
		mk("notice-old", SeverityNotice, 36*time.Hour),
	}
	want := []string{"critical", "notice-new", "notice-old", "info-new", "info-old"}

	got := Merge(now, in)
	if len(got) != len(want) {
		t.Fatalf("Merge() returned %d, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Errorf("Merge()[%d] = %q, want %q (full order %v)", i, got[i].ID, id, ids(got))
		}
	}
}

// TestMergeTieBreakOnID pins the deterministic last resort: same
// severity AND same expiry orders by id, so the endpoint's output is
// stable across calls.
func TestMergeTieBreakOnID(t *testing.T) {
	mk := func(id string) Announcement {
		return with(func(a *Announcement) { a.ID = id })
	}
	got := Merge(now, []Announcement{mk("zulu"), mk("alpha"), mk("mike")})
	want := []string{"alpha", "mike", "zulu"}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("Merge() = %v, want %v", ids(got), want)
		}
	}
}

// TestMergeMultipleSources covers the shape the dashboard handler uses
// today (one source) and the shape rail R3 will use (two): invalid rows
// are dropped rather than surfaced, and a duplicate id collapses to the
// first source that carried it.
func TestMergeMultipleSources(t *testing.T) {
	release := []Announcement{
		with(func(a *Announcement) { a.ID = "shared"; a.Title = "from release" }),
		with(func(a *Announcement) { a.ID = "release-only" }),
	}
	org := []Announcement{
		with(func(a *Announcement) { a.ID = "shared"; a.Title = "from org"; a.Source = SourceOrg }),
		with(func(a *Announcement) { a.ID = "org-only"; a.Source = SourceOrg }),
		// Malformed wire row: dropped, and its presence must not stop
		// the well-formed rows around it from being served.
		with(func(a *Announcement) { a.ID = "org-bad"; a.Source = SourceOrg; a.ExpiresAt = "" }),
		// Expired org row: dropped.
		with(func(a *Announcement) {
			a.ID = "org-expired"
			a.Source = SourceOrg
			a.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
		}),
	}

	got := Merge(now, release, org)
	want := []string{"org-only", "release-only", "shared"} // all same severity+expiry → id order
	if len(got) != len(want) {
		t.Fatalf("Merge() = %v, want %v", ids(got), want)
	}
	for i, id := range want {
		if got[i].ID != id {
			t.Fatalf("Merge() = %v, want %v", ids(got), want)
		}
	}
	for _, a := range got {
		if a.ID == "shared" && a.Title != "from release" {
			t.Errorf("duplicate id resolved to %q, want the first source's row", a.Title)
		}
	}
}

// TestReleaseAnnouncementsAreValid guards rail R1's authoring surface: a
// malformed literal added at release time fails the build here rather
// than silently never rendering.
func TestReleaseAnnouncementsAreValid(t *testing.T) {
	seen := map[string]bool{}
	for i, a := range releaseAnnouncements {
		if err := Validate(a); err != nil {
			t.Errorf("releaseAnnouncements[%d] (%q) invalid: %v", i, a.ID, err)
		}
		if a.Source != SourceRelease {
			t.Errorf("releaseAnnouncements[%d] (%q) source = %q, want %q", i, a.ID, a.Source, SourceRelease)
		}
		if seen[a.ID] {
			t.Errorf("releaseAnnouncements[%d] reuses id %q — ids are dismissal keys and must be unique", i, a.ID)
		}
		seen[a.ID] = true
	}
}

// TestReleaseIsACopy pins that a caller cannot mutate the binary's
// compiled-in data through the accessor.
func TestReleaseIsACopy(t *testing.T) {
	prev := releaseAnnouncements
	releaseAnnouncements = []Announcement{valid()}
	defer func() { releaseAnnouncements = prev }()

	got := Release()
	if len(got) != 1 {
		t.Fatalf("Release() len = %d, want 1", len(got))
	}
	got[0].Title = "mutated"
	if releaseAnnouncements[0].Title == "mutated" {
		t.Error("Release() returned the backing array — callers can mutate the compiled-in set")
	}
}

func ids(as []Announcement) []string {
	out := make([]string, len(as))
	for i, a := range as {
		out[i] = a.ID
	}
	return out
}

// TestDecodeShapes pins the three document shapes Decode must accept
// (plan §4 wire): the retraction, one object, and an array. The array
// leg is the one nothing publishes yet — it exists so a multi-
// announcement composer later needs no wire change against nodes that
// are already deployed.
func TestDecodeShapes(t *testing.T) {
	one := valid()
	oneJSON, err := Encode([]Announcement{one})
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	tests := []struct {
		name    string
		body    string
		wantIDs []string
	}{
		{"retraction (empty)", "", nil},
		{"retraction (whitespace only)", "   \n\t ", nil},
		{"single object", oneJSON, []string{one.ID}},
		{"array", "[" + oneJSON + "]", []string{one.ID}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decode(tc.body)
			if err != nil {
				t.Fatalf("Decode(%q): %v", tc.body, err)
			}
			if diff := len(got) != len(tc.wantIDs); diff {
				t.Fatalf("Decode(%q) = %v, want ids %v", tc.body, ids(got), tc.wantIDs)
			}
			for i, want := range tc.wantIDs {
				if got[i].ID != want {
					t.Errorf("Decode(%q)[%d].ID = %q, want %q", tc.body, i, got[i].ID, want)
				}
			}
		})
	}
}

// TestDecodeMalformed pins that garbage is an ERROR class of its own —
// distinct from "an announcement that breaks a §1 rule", because the
// two callers react differently (the server refuses to sign; the node
// dashboard degrades to no banner).
func TestDecodeMalformed(t *testing.T) {
	for _, body := range []string{"not json", "{", "[{}", `{"id":`} {
		if _, err := Decode(body); !errors.Is(err, ErrMalformedDocument) {
			t.Errorf("Decode(%q) err = %v, want ErrMalformedDocument", body, err)
		}
	}
}

// TestDecodeIgnoresUnknownFields pins forward compatibility: a newer
// server adding a field must not brick an older node.
func TestDecodeIgnoresUnknownFields(t *testing.T) {
	got, err := Decode(`{"id":"x","severity":"info","title":"t","body":"b",` +
		`"expires_at":"2030-01-01T00:00:00Z","source":"org","future_field":{"nested":1}}`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got) != 1 || got[0].ID != "x" {
		t.Fatalf("Decode = %v", ids(got))
	}
}

// TestEncodeRoundTrip pins Encode/Decode symmetry and the ONE
// representation of a retraction: zero announcements encode to "" (not
// "[]"), so a retraction has exactly one body and therefore one hash.
func TestEncodeRoundTrip(t *testing.T) {
	if got, err := Encode(nil); err != nil || got != "" {
		t.Fatalf("Encode(nil) = %q, %v — want the empty retraction body", got, err)
	}
	in := []Announcement{valid(), with(func(a *Announcement) { a.ID = "second" })}
	body, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	got, err := Decode(body)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got) != 2 || got[0].ID != in[0].ID || got[1].ID != in[1].ID {
		t.Errorf("round trip = %v, want %v", ids(got), ids(in))
	}
}

// TestDecodeRetractionHasExactlyOneRepresentation is security finding 6.
// "Show nothing" must be ONE document, not three: the empty body is the
// retraction, and "[]" / "null" are malformed documents.
//
// Three spellings of the same instruction would be three different
// bodies, three different BodyHashes and three different signatures over
// what an operator reads as one thing — while Encode already guarantees
// the server only ever emits the empty form. Anything else arriving on
// the rail did not come from Encode, and the honest answer to that is an
// error, not a silent third meaning of nothing.
func TestDecodeRetractionHasExactlyOneRepresentation(t *testing.T) {
	if got, err := Decode(""); err != nil || got != nil {
		t.Errorf(`Decode("") = %v, %v — the empty body IS the retraction`, ids(got), err)
	}
	if got, err := Decode("  \n\t "); err != nil || got != nil {
		t.Errorf("Decode(whitespace) = %v, %v — want the retraction", ids(got), err)
	}
	for _, body := range []string{"[]", "null", " [] ", "\nnull\n"} {
		got, err := Decode(body)
		if !errors.Is(err, ErrMalformedDocument) {
			t.Errorf("Decode(%q) = %v, err %v — want ErrMalformedDocument", body, ids(got), err)
		}
		if got != nil {
			t.Errorf("Decode(%q) returned %v alongside its error", body, ids(got))
		}
	}
}

// TestForVersion (WINNODE2 16b): an announcement fixed in a release is
// dropped on a node at or past it, kept below it, and kept on a node whose
// version is not a release (a dev build).
func TestForVersion(t *testing.T) {
	list := []Announcement{{ID: "fix", FixedIn: "1.32.0"}, {ID: "always"}}
	cases := []struct {
		running string
		want    string
	}{
		{"1.36.0", "always"},
		{"v1.32.0", "always"},
		{"1.31.9", "fix,always"},
		{"1.32.0-rc.1", "always"},
		{"dev", "fix,always"},
		{"", "fix,always"},
	}
	for _, tc := range cases {
		var ids []string
		for _, a := range ForVersion(list, tc.running) {
			ids = append(ids, a.ID)
		}
		if got := strings.Join(ids, ","); got != tc.want {
			t.Errorf("ForVersion(%q) = %q, want %q", tc.running, got, tc.want)
		}
	}
	bad := valid()
	bad.FixedIn = "soon"
	if Validate(bad) == nil {
		t.Fatal("a non-release fixed_in validated")
	}
}
