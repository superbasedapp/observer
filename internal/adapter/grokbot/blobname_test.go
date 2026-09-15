package grokbot

import "testing"

// TestBlobNameRoundTrip pins the codec against the app's own encoder. The
// "live" case is a REAL filename observed on a Grok Bot 0.28.0 Windows
// install (2026-08-28) with the account id anonymized; if our decoder ever
// drifts from the app's, this is the case that catches it.
func TestBlobNameRoundTrip(t *testing.T) {
	t.Parallel()
	keys := []string{
		"sand.client.slice.client-meta.account-slot",
		"sand.client.slice.account.acct.roster.last-roster",
		"sand.client.slice.account.auth0%7Cuser_00000000000000000000000000.transcript.replicas.11111111-2222-3333-4444-555555555555",
	}
	for _, k := range keys {
		name := encodeBlobName(k)
		got, ok := decodeBlobName(name)
		if !ok {
			t.Fatalf("decodeBlobName(%q) = !ok, want ok", name)
		}
		if got != k {
			t.Errorf("round trip: got %q, want %q", got, k)
		}
	}
}

// TestDecodeBlobNameAgainstLiveFilename pins the decoder against a filename
// captured verbatim from the live install (only the embedded account id and
// agent uuid are anonymized — the ENCODING is untouched). A hand-written
// encoder that happens to agree with itself would pass the round-trip test
// above; only a real filename proves we match the app.
func TestDecodeBlobNameAgainstLiveFilename(t *testing.T) {
	t.Parallel()
	// Captured shape: sand.client.slice.client-meta.account-slot
	const live = "onqw4zbomnwgszlooqxhg3djmnss4y3mnfsw45bnnvsxiyjomfrwg33vnz2c243mn52a.blob"
	got, ok := decodeBlobName(live)
	if !ok {
		t.Fatalf("decodeBlobName(live) = !ok; the codec has drifted from the app's")
	}
	if want := "sand.client.slice.client-meta.account-slot"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestDecodeBlobNameRejects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, in, why string
	}{
		{"no suffix", "onqw4zbo", "must end .blob"},
		{"empty body", ".blob", "empty body"},
		{"bad char", "onqw4zb0.blob", "'0' is not in the lowercase base32 alphabet"},
		{"uppercase", "ONQW4ZBO.blob", "the app's alphabet is lowercase"},
		{"padding", "onqw4zbo=.blob", "the app emits unpadded base32"},
		{"not sand namespace", encodeBlobName("other.client.slice.x"), "must start with the sand. namespace"},
		{"over length cap", encodeBlobName("sand." + longString(400)), "the app refuses >240-char names outright"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, ok := decodeBlobName(tc.in); ok {
				t.Errorf("decodeBlobName(%q) = ok, want rejected (%s)", tc.in, tc.why)
			}
		})
	}
}

// TestDecodeBlobNameRejectsNonCanonicalPadBits pins the app's own
// canonical-encoding check: a truncated name whose leftover bits are non-zero
// must be refused, not silently decoded into a plausible-looking key.
func TestDecodeBlobNameRejectsNonCanonicalPadBits(t *testing.T) {
	t.Parallel()
	// 31 bytes = 248 bits = 49 full 5-bit symbols + 3 leftover bits, so the
	// final symbol MUST carry zero pad bits. (A key whose length is a
	// multiple of 5 encodes exactly and would make this test vacuous.)
	const key = "sand.client.slice.account-slotX"
	if len(key)%5 == 0 {
		t.Fatalf("test key is %d bytes, a multiple of 5 — it encodes exactly and cannot exercise pad bits", len(key))
	}
	full := encodeBlobName(key)
	if _, ok := decodeBlobName(full); !ok {
		t.Fatal("the canonical name failed to decode; the test fixture is wrong")
	}
	body := full[:len(full)-len(blobSuffix)]
	// 'h' is alphabet index 7 (0b00111): its low bits are set, so the
	// trailing group is no longer zero-padded.
	mutated := body[:len(body)-1] + "h" + blobSuffix
	if mutated == full {
		t.Fatal("mutation was a no-op; pick a different substitute symbol")
	}
	if _, ok := decodeBlobName(mutated); ok {
		t.Error("a name with non-zero pad bits decoded; the canonical-encoding check is missing")
	}
}

func TestParseSliceKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, key          string
		wantOK             bool
		acct, slice, param string
	}{
		{
			name:   "account transcript",
			key:    "sand.client.slice.account.auth0%7Cuser_ABC.transcript.replicas.11111111-2222-3333-4444-555555555555",
			wantOK: true, acct: "auth0%7Cuser_ABC", slice: transcriptSlice,
			param: "11111111-2222-3333-4444-555555555555",
		},
		{
			name: "account roster", key: "sand.client.slice.account.acct.roster.last-roster",
			wantOK: true, acct: "acct", slice: rosterSlice,
		},
		{
			name: "global slice", key: "sand.client.slice.client-meta.account-slot",
			wantOK: true, slice: "client-meta.account-slot",
		},
		{name: "wrong prefix", key: "other.client.slice.x"},
		{name: "prefix only", key: "sand.client.slice."},
		{name: "transcript without agent id", key: "sand.client.slice.account.acct.transcript.replicas."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := parseSliceKey(tc.key)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.Account != tc.acct || got.Slice != tc.slice || got.Param != tc.param {
				t.Errorf("got %+v, want account=%q slice=%q param=%q", got, tc.acct, tc.slice, tc.param)
			}
		})
	}
}

// TestTranscriptAgentIDIgnoresTmp pins that a half-written blob (the app's
// atomic-write staging name) is never treated as a session file.
func TestTranscriptAgentIDIgnoresTmp(t *testing.T) {
	t.Parallel()
	key := "sand.client.slice.account.acct.transcript.replicas.abc"
	name := encodeBlobName(key)
	if got := transcriptAgentID(name); got != "abc" {
		t.Fatalf("transcriptAgentID(%q) = %q, want %q", name, got, "abc")
	}
	if got := transcriptAgentID(name + tmpSuffix); got != "" {
		t.Errorf("transcriptAgentID on a .tmp staging file = %q, want empty", got)
	}
}

// TestTranscriptAgentIDRejectsRosterSlice pins the documented decision that
// the roster slice is recognised but NOT ingested (doc.go).
func TestTranscriptAgentIDRejectsRosterSlice(t *testing.T) {
	t.Parallel()
	name := encodeBlobName("sand.client.slice.account.acct." + rosterSlice)
	if got := transcriptAgentID(name); got != "" {
		t.Errorf("roster blob yielded agent id %q; the roster must not be ingested", got)
	}
}

func longString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}
