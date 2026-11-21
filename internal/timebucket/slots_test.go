package timebucket

import (
	"testing"
	"time"
)

func TestParseStoredTS(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"2026-10-03T12:34:56Z", "2026-10-03T12:34:56Z", true},
		{"2026-10-03T12:34:56.123456789Z", "2026-10-03T12:34:56Z", true},
		{"2026-10-03 12:34:56", "2026-10-03T12:34:56Z", true},
		{"garbage", "", false},
	}
	for _, c := range cases {
		got, ok := ParseStoredTS(c.in)
		if ok != c.ok {
			t.Fatalf("%q: ok=%v want %v", c.in, ok, c.ok)
		}
		if ok && got.UTC().Truncate(time.Second).Format(time.RFC3339) != c.want {
			t.Errorf("%q: got %s want %s", c.in, got.UTC().Format(time.RFC3339), c.want)
		}
	}
}

func TestStoredKeyer(t *testing.T) {
	until := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	day, err := Resolve(Request{Gran: "1d", TZ: "UTC", Since: until.Add(-72 * time.Hour), Until: until})
	if err != nil {
		t.Fatal(err)
	}
	hour, err := Resolve(Request{Gran: "1h", TZ: "UTC", Since: until.Add(-72 * time.Hour), Until: until})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		spec Spec
		ts   string
		want string
	}{
		{"day", day, "2026-10-08T23:59:00Z", "2026-10-08"},
		{"day memo hit", day, "2026-10-08T23:59:30Z", "2026-10-08"},
		{"hour", hour, "2026-10-08T23:59:00Z", "2026-10-08T23:00:00Z"},
		{"sqlite form", day, "2026-10-07 01:00:00", "2026-10-07"},
		{"unparseable keeps date prefix", day, "2026-10-06Tjunk", "2026-10-06"},
		{"short junk", day, "x", "x"},
	}
	keyers := map[string]func(string) string{}
	for _, c := range cases {
		k, ok := keyers[string(c.spec.Gran)]
		if !ok {
			k = StoredKeyer(c.spec)
			keyers[string(c.spec.Gran)] = k
		}
		if got := k(c.ts); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestSlotsZeroFillsAndKeepsOutliers(t *testing.T) {
	until := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	spec, err := Resolve(Request{Gran: "1d", TZ: "UTC", Since: until.Add(-48 * time.Hour), Until: until})
	if err != nil {
		t.Fatal(err)
	}
	data := map[string]time.Time{
		"2026-10-09": time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		"legacy":     {},
	}
	got := Slots(spec, data)
	want := []string{"legacy", "2026-10-08", "2026-10-09"}
	if len(got) != len(want) {
		t.Fatalf("got %d slots %+v, want %v", len(got), got, want)
	}
	for i, w := range want {
		if got[i].Key != w {
			t.Errorf("slot %d: got %q want %q", i, got[i].Key, w)
		}
	}
	if !KeyStart(spec, "2026-10-08").Equal(time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("KeyStart day: %v", KeyStart(spec, "2026-10-08"))
	}
	if !KeyStart(spec, "2026-10-08T05:00:00Z").Equal(time.Date(2026, 10, 8, 5, 0, 0, 0, time.UTC)) {
		t.Errorf("KeyStart rfc3339")
	}
	if !KeyStart(spec, "nope").IsZero() {
		t.Errorf("KeyStart junk should be zero")
	}
}

func TestResolveWithLoc(t *testing.T) {
	until := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
	ist := time.FixedZone("IST", 5*3600+1800)
	cases := []struct {
		name    string
		req     Request
		wantTZ  string
		wantKey string // bucket key of 2026-10-08T20:00Z
	}{
		{"loc wins over tz and is named by it", Request{Gran: "1d", TZ: "Asia/Kolkata", Loc: ist}, "Asia/Kolkata", "2026-10-09"},
		{"loc alone is named by its String", Request{Gran: "1d", Loc: ist}, "IST", "2026-10-09"},
		{"no loc keeps the tz rule", Request{Gran: "1d", TZ: "UTC"}, "UTC", "2026-10-08"},
	}
	for _, c := range cases {
		c.req.Since, c.req.Until = until.Add(-72*time.Hour), until
		sp, err := Resolve(c.req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if sp.TZ != c.wantTZ || sp.TZFallback {
			t.Errorf("%s: tz %q fallback %v", c.name, sp.TZ, sp.TZFallback)
		}
		if got := sp.KeyOf(time.Date(2026, 10, 8, 20, 0, 0, 0, time.UTC)); got != c.wantKey {
			t.Errorf("%s: key %s want %s", c.name, got, c.wantKey)
		}
	}
}
