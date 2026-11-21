package telemetrylog

import (
	"reflect"
	"strings"
	"testing"
)

// TestAckedFloor pins the trim floor rules one row per rule (T-823): a record
// may leave the log only once every durable acked it, a missing required
// durable holds the trim, and a caught-up durable never holds it.
func TestAckedFloor(t *testing.T) {
	apply := func(ack, pending, ackPending uint64) ConsumerFloor {
		return ConsumerFloor{Name: "applyworker", AckFloor: ack, Pending: pending, AckPending: ackPending}
	}
	sor := func(ack, pending, ackPending uint64) ConsumerFloor {
		return ConsumerFloor{Name: "sorwriter", AckFloor: ack, Pending: pending, AckPending: ackPending}
	}
	tests := []struct {
		name         string
		lastSeq      uint64
		consumers    []ConsumerFloor
		required     []string
		wantFloor    uint64
		wantLimiting string
		wantHeld     []string
	}{
		{"required durable missing holds the trim", 100, []ConsumerFloor{apply(0, 0, 0)}, []string{"applyworker", "sorwriter"}, 0, "", []string{"sorwriter"}},
		{"held names sorted", 100, nil, []string{"sorwriter", "applyworker"}, 0, "", []string{"applyworker", "sorwriter"}},
		{"no durables trims nothing", 100, nil, nil, 0, "", nil},
		{"caught-up durable floors at last sequence", 100, []ConsumerFloor{apply(40, 0, 0)}, []string{"applyworker"}, 100, "applyworker", nil},
		{"pending durable floors at its ack floor", 100, []ConsumerFloor{apply(40, 60, 0)}, nil, 40, "applyworker", nil},
		{"ack-pending durable floors at its ack floor", 100, []ConsumerFloor{apply(40, 0, 1)}, nil, 40, "applyworker", nil},
		{"slowest durable wins (sor behind)", 100, []ConsumerFloor{apply(0, 0, 0), sor(10, 90, 0)}, []string{"applyworker", "sorwriter"}, 10, "sorwriter", nil},
		{"slowest durable wins (apply behind)", 100, []ConsumerFloor{apply(5, 95, 0), sor(0, 0, 0)}, nil, 5, "applyworker", nil},
		{"unrequired durable still holds the floor", 100, []ConsumerFloor{apply(0, 0, 0), {Name: "clickhouseworker", AckFloor: 3, Pending: 97}}, []string{"applyworker"}, 3, "clickhouseworker", nil},
		// F01: a position above the only read of the last sequence holds the
		// trim (it used to be clamped to lastSeq, which purged a recreated
		// stream's every record unapplied).
		{"ack floor above last sequence holds the trim", 50, []ConsumerFloor{apply(70, 1, 0)}, nil, 0, "", nil},
		{"tie names the first durable alphabetically", 100, []ConsumerFloor{sor(7, 1, 0), apply(7, 1, 0)}, nil, 7, "applyworker", nil},
		{"empty required name ignored", 100, []ConsumerFloor{apply(0, 0, 0)}, []string{""}, 100, "applyworker", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			floor, limiting, held := AckedFloor(tc.lastSeq, tc.consumers, tc.required)
			if floor != tc.wantFloor || limiting != tc.wantLimiting || !reflect.DeepEqual(held, tc.wantHeld) {
				t.Fatalf("AckedFloor = (%d, %q, %v), want (%d, %q, %v)", floor, limiting, held, tc.wantFloor, tc.wantLimiting, tc.wantHeld)
			}
		})
	}
}

// TestTrimFloor pins the full verdict, one row per rule, including the F01
// reproduction: the stream SBO_TELEMETRY recreated at last_seq 106 while the
// durables applyworker and sorwriter sat at delivered/ack floor 15491 with
// nothing pending. Before the fix rule 3 plus the clamp made the floor 106 and
// the trim purged every new record unapplied.
func TestTrimFloor(t *testing.T) {
	c := func(name string, ack, delivered, pending, ackPending uint64) ConsumerFloor {
		return ConsumerFloor{Name: name, AckFloor: ack, Delivered: delivered, Pending: pending, AckPending: ackPending}
	}
	req := []string{"applyworker", "sorwriter"}
	tests := []struct {
		name      string
		stats     StreamStats
		consumers []ConsumerFloor
		required  []string
		want      FloorVerdict
	}{
		{
			"F01 recreated stream: both durables ahead, nothing trimmed",
			StreamStats{FirstSequence: 1, LastSequence: 106, CeilingSequence: 106},
			[]ConsumerFloor{c("sorwriter", 15491, 15491, 0, 0), c("applyworker", 15491, 15491, 0, 0)},
			req,
			FloorVerdict{Ahead: []ConsumerAhead{{"applyworker", 15491, 106}, {"sorwriter", 15491, 106}}},
		},
		{
			"F01 one durable ahead holds the trim even when the other is caught up",
			StreamStats{LastSequence: 106, CeilingSequence: 106},
			[]ConsumerFloor{c("applyworker", 106, 106, 0, 0), c("sorwriter", 15491, 15491, 0, 0)},
			req,
			FloorVerdict{Ahead: []ConsumerAhead{{"sorwriter", 15491, 106}}},
		},
		{
			"delivered ahead with ack floor still inside is a fault",
			StreamStats{LastSequence: 106},
			[]ConsumerFloor{c("applyworker", 0, 15491, 0, 0)},
			nil,
			FloorVerdict{Ahead: []ConsumerAhead{{"applyworker", 15491, 106}}},
		},
		{
			"ack of a record published between the reads is not a fault",
			StreamStats{LastSequence: 100, CeilingSequence: 103},
			[]ConsumerFloor{c("applyworker", 102, 102, 1, 0)},
			nil,
			FloorVerdict{Floor: 100, Limiting: "applyworker"},
		},
		{
			"position above even the re-read is a fault",
			StreamStats{LastSequence: 100, CeilingSequence: 103},
			[]ConsumerFloor{c("applyworker", 104, 104, 0, 0)},
			nil,
			FloorVerdict{Ahead: []ConsumerAhead{{"applyworker", 104, 103}}},
		},
		{
			"missing required and ahead both reported",
			StreamStats{LastSequence: 10},
			[]ConsumerFloor{c("applyworker", 50, 50, 0, 0)},
			req,
			FloorVerdict{Held: []string{"sorwriter"}, Ahead: []ConsumerAhead{{"applyworker", 50, 10}}},
		},
		{
			"healthy: caught-up and behind durables, floor is the slowest ack",
			StreamStats{LastSequence: 106, CeilingSequence: 106},
			[]ConsumerFloor{c("applyworker", 106, 106, 0, 0), c("sorwriter", 90, 100, 16, 6)},
			req,
			FloorVerdict{Floor: 90, Limiting: "sorwriter"},
		},
		{
			"unknown delivered position (0) never faults",
			StreamStats{LastSequence: 106},
			[]ConsumerFloor{c("applyworker", 40, 0, 66, 0)},
			nil,
			FloorVerdict{Floor: 40, Limiting: "applyworker"},
		},
		{"no durables", StreamStats{LastSequence: 5}, nil, nil, FloorVerdict{}},
		{
			"R-A05 unknown ceiling: a durable above the first read holds, no fault",
			StreamStats{LastSequence: 100, CeilingUnknown: true},
			[]ConsumerFloor{c("applyworker", 102, 102, 0, 0), c("sorwriter", 90, 100, 10, 0)},
			nil,
			FloorVerdict{CeilingUnknown: true},
		},
		{
			"R-A05 unknown ceiling with every durable inside the first read trims as usual",
			StreamStats{LastSequence: 100, CeilingUnknown: true},
			[]ConsumerFloor{c("applyworker", 100, 100, 0, 0), c("sorwriter", 90, 100, 10, 0)},
			nil,
			FloorVerdict{Floor: 90, Limiting: "sorwriter"},
		},
		{
			"R-A05 unknown ceiling still reports a missing required durable",
			StreamStats{LastSequence: 100, CeilingUnknown: true},
			[]ConsumerFloor{c("applyworker", 150, 150, 0, 0)},
			req,
			FloorVerdict{Held: []string{"sorwriter"}, CeilingUnknown: true},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TrimFloor(tc.stats, tc.consumers, tc.required)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("TrimFloor = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestDescribeAhead pins the operator sentence: it names every consumer, its
// position and the ceiling, and points at the recovery procedure.
func TestDescribeAhead(t *testing.T) {
	if DescribeAhead(nil) != "" {
		t.Fatal("no fault must describe as empty")
	}
	got := DescribeAhead([]ConsumerAhead{{"applyworker", 15491, 106}})
	for _, want := range []string{"applyworker at 15491 > stream last 106", "consumer ahead of the stream", "Durable log: consumer ahead of the stream"} {
		if !strings.Contains(got, want) {
			t.Fatalf("DescribeAhead = %q, missing %q", got, want)
		}
	}
}

// TestFloorsOf pins the projection from StreamStats.
func TestFloorsOf(t *testing.T) {
	got := FloorsOf(StreamStats{Consumers: []ConsumerStats{{Name: "a", Pending: 1, AckPending: 2, AckFloor: 3, Delivered: 4, Redelivered: 9}}})
	want := []ConsumerFloor{{Name: "a", AckFloor: 3, Pending: 1, AckPending: 2, Delivered: 4}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FloorsOf = %+v, want %+v", got, want)
	}
}

// TestAheadOfSkipsUnknownCeiling pins R-A05: AheadOf reports nothing when the
// ceiling re-read failed, and the usual ahead set otherwise.
func TestAheadOfSkipsUnknownCeiling(t *testing.T) {
	stats := StreamStats{LastSequence: 10, Consumers: []ConsumerStats{{Name: "applyworker", AckFloor: 50, Delivered: 50}}}
	if got := AheadOf(stats); len(got) != 1 || got[0].Name != "applyworker" {
		t.Fatalf("AheadOf(known) = %+v", got)
	}
	stats.CeilingUnknown = true
	if got := AheadOf(stats); got != nil {
		t.Fatalf("AheadOf(unknown) = %+v, want nil", got)
	}
}
