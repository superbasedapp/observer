package store

import (
	"testing"
	"time"
)

// TestSQLValCodecs pins the NULL encoders in sqlval.go.
func TestSQLValCodecs(t *testing.T) {
	f, i64, i := 1.5, int64(7), 3
	at := time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("x", 3600))
	for _, tc := range []struct {
		name string
		got  any
		want any
	}{
		{"string empty", nullableString(""), nil},
		{"string set", nullableString("a"), "a"},
		{"float ptr nil", nullableFloat64Ptr(nil), nil},
		{"float ptr set", nullableFloat64Ptr(&f), 1.5},
		{"int64 ptr nil", nullableInt64Ptr(nil), nil},
		{"int64 ptr set", nullableInt64Ptr(&i64), int64(7)},
		{"int ptr nil", nullableIntPtr(nil), nil},
		{"int ptr set", nullableIntPtr(&i), 3},
		{"int64 zero", nullableInt64(0), nil},
		{"int64 set", nullableInt64(9), int64(9)},
		{"int zero", nullableInt(0), nil},
		{"int set", nullableInt(4), 4},
		{"float zero", nullableFloat64(0), nil},
		{"float set", nullableFloat64(2.5), 2.5},
		{"bool true", boolInt(true), 1},
		{"bool false", boolInt(false), 0},
		{"time zero", nullableTimestamp(time.Time{}), nil},
		{"time set", nullableTimestamp(at), "2026-01-02T02:04:05.000000006Z"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: got %#v, want %#v", tc.name, tc.got, tc.want)
		}
	}
}

// TestParseStoredTime pins the stored-timestamp parser: RFC3339Nano and
// RFC3339 both parse and keep their offset, anything else is the zero time
// with ok=false.
func TestParseStoredTime(t *testing.T) {
	for _, tc := range []struct {
		in     string
		want   time.Time
		wantOK bool
	}{
		{"2026-01-02T03:04:05.123456789Z", time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.UTC), true},
		{"2026-01-02T03:04:05Z", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), true},
		{"2026-01-02T03:04:05+01:00", time.Date(2026, 1, 2, 2, 4, 5, 0, time.UTC), true},
		{"0001-01-01T00:00:00Z", time.Time{}, true},
		{"", time.Time{}, false},
		{"2026-01-02 03:04:05", time.Time{}, false},
		{"garbage", time.Time{}, false},
	} {
		got, ok := parseStoredTimeOK(tc.in)
		if !got.Equal(tc.want) || ok != tc.wantOK {
			t.Errorf("parseStoredTimeOK(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.wantOK)
		}
		if p := parseStoredTime(tc.in); !p.Equal(got) {
			t.Errorf("parseStoredTime(%q) = %v, want %v", tc.in, p, got)
		}
	}
}
