package store

import "time"

// sqlval.go is the one home of the store's small SQL value codecs: the
// "empty, zero or nil means NULL" argument encoders and the stored-timestamp
// parser. Variants whose semantics differ (timestamp, where the zero time
// means now; parseLOCTime's extra layout; the RFC3339-only or
// RFC3339Nano-only parsers) stay beside their callers.

// nullableString maps "" to SQL NULL and any other string to itself.
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullableFloat64Ptr maps a nil *float64 to SQL NULL and a non-nil one to
// its value.
func nullableFloat64Ptr(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// nullableInt64Ptr maps a nil *int64 to SQL NULL and a non-nil one to its
// value.
func nullableInt64Ptr(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// nullableIntPtr maps a nil *int to SQL NULL and a non-nil one to its value.
func nullableIntPtr(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

// nullableInt64 maps 0 to SQL NULL and any other value to itself.
func nullableInt64(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

// nullableInt maps 0 to SQL NULL and any other value to itself.
func nullableInt(v int) any {
	if v == 0 {
		return nil
	}
	return v
}

// nullableFloat64 maps 0 to SQL NULL and any other value to itself.
func nullableFloat64(v float64) any {
	if v == 0 {
		return nil
	}
	return v
}

// boolInt maps a bool to the 0/1 integer SQLite stores it as.
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

// nullableTimestamp maps the zero time to SQL NULL and any other time to
// its UTC RFC3339Nano text, the form every stored timestamp uses.
func nullableTimestamp(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseStoredTime parses a stored timestamp, trying RFC3339Nano and then
// RFC3339. An empty or unparseable value yields the zero time. The result
// keeps the offset the text carried; call .UTC() where UTC is required.
func parseStoredTime(s string) time.Time {
	t, _ := parseStoredTimeOK(s)
	return t
}

// parseStoredTimeOK is parseStoredTime that also reports whether the value
// parsed, so a caller can skip an unparseable one.
func parseStoredTimeOK(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, true
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	return time.Time{}, false
}
