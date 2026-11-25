package parseutil

import (
	"bufio"
	"strings"
	"testing"
	"time"
)

func TestParseRFC3339(t *testing.T) {
	plus2 := time.FixedZone("", 2*3600)
	cases := []struct {
		raw        string
		want       time.Time
		wantUTC    time.Time
		wantMillis time.Time
	}{
		{"", time.Time{}, time.Time{}, time.Time{}},
		{"not a time", time.Time{}, time.Time{}, time.Time{}},
		{"2026-05-01T10:00:00Z", time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC), time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC), time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)},
		{"2026-05-01T10:00:00.123456789Z", time.Date(2026, 5, 1, 10, 0, 0, 123456789, time.UTC), time.Date(2026, 5, 1, 10, 0, 0, 123456789, time.UTC), time.Date(2026, 5, 1, 10, 0, 0, 123456789, time.UTC)},
		{"2026-05-01T12:00:00.5+02:00", time.Date(2026, 5, 1, 12, 0, 0, 500000000, plus2), time.Date(2026, 5, 1, 10, 0, 0, 500000000, time.UTC), time.Date(2026, 5, 1, 10, 0, 0, 500000000, time.UTC)},
	}
	for _, tc := range cases {
		if got := ParseRFC3339(tc.raw); !got.Equal(tc.want) || got.IsZero() != tc.want.IsZero() {
			t.Errorf("ParseRFC3339(%q) = %v, want %v", tc.raw, got, tc.want)
		}
		if got := ParseRFC3339UTC(tc.raw); !got.Equal(tc.wantUTC) || (!got.IsZero() && got.Location() != time.UTC) {
			t.Errorf("ParseRFC3339UTC(%q) = %v, want %v in UTC", tc.raw, got, tc.wantUTC)
		}
		if got := ParseRFC3339UTCMillisZ(tc.raw); !got.Equal(tc.wantMillis) || (!got.IsZero() && got.Location() != time.UTC) {
			t.Errorf("ParseRFC3339UTCMillisZ(%q) = %v, want %v in UTC", tc.raw, got, tc.wantMillis)
		}
	}
	// ParseRFC3339 keeps the string's own offset.
	if _, off := ParseRFC3339("2026-05-01T12:00:00+02:00").Zone(); off != 2*3600 {
		t.Errorf("ParseRFC3339 offset = %d, want +02:00 kept", off)
	}
}

func TestLooksLikeUUID(t *testing.T) {
	cases := map[string]bool{
		"0190a3b2-1c2d-7e8f-9a0b-1c2d3e4f5a6b": true,
		"0190A3B2-1C2D-7E8F-9A0B-1C2D3E4F5A6B": true,
		"0190a3b2-1c2d-7e8f-9a0b-1c2d3e4f5a6":  false,
		"0190a3b2x1c2d-7e8f-9a0b-1c2d3e4f5a6b": false,
		"0190a3b2-1c2d-7e8f-9a0b-1c2d3e4f5a6g": false,
		"":                                     false,
	}
	for s, want := range cases {
		if got := LooksLikeUUID(s); got != want {
			t.Errorf("LooksLikeUUID(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestSplitLinesKeepTerminator(t *testing.T) {
	sc := bufio.NewScanner(strings.NewReader("a\nbb\r\n\ntail"))
	sc.Split(SplitLinesKeepTerminator)
	var got []string
	for sc.Scan() {
		got = append(got, sc.Text())
	}
	want := []string{"a\n", "bb\r\n", "\n", "tail"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tokens = %q, want %q", got, want)
	}
}

func TestIsAbsAnyOS(t *testing.T) {
	cases := map[string]bool{
		"/home/u/x":      true,
		`\\server\share`: true,
		`C:\Users\u`:     true,
		"c:/users/u":     true,
		"C:":             false,
		"C:x":            false,
		"1:/x":           false,
		"relative/x":     false,
		`relative\x`:     false,
		"":               false,
	}
	for p, want := range cases {
		if got := IsAbsAnyOS(p); got != want {
			t.Errorf("IsAbsAnyOS(%q) = %v, want %v", p, got, want)
		}
	}
}
