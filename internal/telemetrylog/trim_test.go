package telemetrylog

import (
	"reflect"
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
		{"ack floor above last sequence is clamped", 50, []ConsumerFloor{apply(70, 1, 0)}, nil, 50, "applyworker", nil},
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

// TestFloorsOf pins the projection from StreamStats.
func TestFloorsOf(t *testing.T) {
	got := FloorsOf(StreamStats{Consumers: []ConsumerStats{{Name: "a", Pending: 1, AckPending: 2, AckFloor: 3, Redelivered: 9}}})
	want := []ConsumerFloor{{Name: "a", AckFloor: 3, Pending: 1, AckPending: 2}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FloorsOf = %+v, want %+v", got, want)
	}
}
