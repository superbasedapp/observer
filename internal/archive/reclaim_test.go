package archive

import (
	"strings"
	"testing"
)

const (
	gib = 1 << 30
	mib = 1 << 20
)

// TestPlanReclaim walks the precondition table. Each row names the ONE rule it
// is exercising; rows differ from the ready case by a single field, so a rule
// that stops firing shows up as exactly one failure rather than a cascade.
func TestPlanReclaim(t *testing.T) {
	t.Parallel()

	// ready is the baseline: daemon down, 12 GiB on the freelist, 800 GiB free.
	ready := ReclaimInput{
		FileBytes:     36 * gib,
		PageSize:      4096,
		FreelistPages: 3 * mib, // 3Mi pages × 4 KiB = 12 GiB
		FreeDiskBytes: 800 * gib,
		FreeDiskKnown: true,
	}

	cases := []struct {
		name         string
		mutate       func(*ReclaimInput)
		want         ReclaimDecision
		wantShort    int64
		reasonSubstr string
	}{
		{
			name: "preconditions met",
			want: ReclaimReady,
		},
		{
			name:         "daemon live refuses first",
			mutate:       func(in *ReclaimInput) { in.DaemonLive = true },
			want:         ReclaimDaemonLive,
			reasonSubstr: "daemon-restart-runbook",
		},
		{
			// Ordering proof: a live daemon is refused even when the space
			// precondition ALSO fails, because stopping the daemon is what the
			// operator must do first either way.
			name: "daemon live outranks no space",
			mutate: func(in *ReclaimInput) {
				in.DaemonLive = true
				in.FreeDiskBytes = 1
			},
			want: ReclaimDaemonLive,
		},
		{
			name: "not enough free disk for the copy",
			mutate: func(in *ReclaimInput) {
				in.FreeDiskBytes = 30 * gib // < the 36 GiB file
			},
			want:         ReclaimNoSpace,
			wantShort:    6 * gib,
			reasonSubstr: "short by",
		},
		{
			// Exactly the file size is enough: the compacted copy can never
			// exceed the source, so >= is the honest boundary. An off-by-one
			// here would refuse a reclaim that fits.
			name: "free space exactly equal to the file is enough",
			mutate: func(in *ReclaimInput) {
				in.FreeDiskBytes = 36 * gib
			},
			want: ReclaimReady,
		},
		{
			name: "one byte short is refused",
			mutate: func(in *ReclaimInput) {
				in.FreeDiskBytes = 36*gib - 1
			},
			want:      ReclaimNoSpace,
			wantShort: 1,
		},
		{
			// An unmeasurable volume SKIPS the space rule rather than
			// guessing. Treating unknown as zero would refuse every reclaim on
			// Windows; treating it as infinite would be a fabricated pass — so
			// the rule simply does not weigh in, and the operator sees that.
			name: "unknown free space skips the rule, never fabricates one",
			mutate: func(in *ReclaimInput) {
				in.FreeDiskKnown = false
				in.FreeDiskBytes = 0
			},
			want: ReclaimReady,
		},
		{
			name: "empty freelist is not worth a rewrite",
			mutate: func(in *ReclaimInput) {
				in.FreelistPages = 0
			},
			want:         ReclaimNothingToReclaim,
			reasonSubstr: "--force",
		},
		{
			name: "just below the floor is refused",
			mutate: func(in *ReclaimInput) {
				in.FreelistPages = (MinReclaimBytes / 4096) - 1
			},
			want: ReclaimNothingToReclaim,
		},
		{
			name: "exactly the floor proceeds",
			mutate: func(in *ReclaimInput) {
				in.FreelistPages = MinReclaimBytes / 4096
			},
			want: ReclaimReady,
		},
		{
			name: "force lifts the floor",
			mutate: func(in *ReclaimInput) {
				in.FreelistPages = 1
				in.Force = true
			},
			want: ReclaimReady,
		},
		{
			// Force is explicitly NOT a master key: it lifts the "worth it"
			// threshold and nothing else. A --force that also skipped the space
			// check would fill the disk.
			name: "force does not lift the space precondition",
			mutate: func(in *ReclaimInput) {
				in.Force = true
				in.FreeDiskBytes = 1
			},
			want: ReclaimNoSpace,
		},
		{
			name: "force does not lift the daemon precondition",
			mutate: func(in *ReclaimInput) {
				in.Force = true
				in.DaemonLive = true
			},
			want: ReclaimDaemonLive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			in := ready
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			got := PlanReclaim(in)
			if got.Decision != tc.want {
				t.Fatalf("Decision = %q, want %q (reason: %s)", got.Decision, tc.want, got.Reason)
			}
			if got.OK() != (tc.want == ReclaimReady) {
				t.Errorf("OK() = %v for decision %q", got.OK(), got.Decision)
			}
			if tc.want == ReclaimReady && got.Reason != "" {
				t.Errorf("a ready plan carries a refusal reason: %q", got.Reason)
			}
			if tc.want != ReclaimReady && got.Reason == "" {
				t.Errorf("decision %q carries no reason — a refusal with no explanation is not an honest refusal", got.Decision)
			}
			if tc.wantShort != 0 && got.ShortfallBytes != tc.wantShort {
				t.Errorf("ShortfallBytes = %d, want %d", got.ShortfallBytes, tc.wantShort)
			}
			if tc.reasonSubstr != "" && !strings.Contains(got.Reason, tc.reasonSubstr) {
				t.Errorf("reason does not mention %q:\n%s", tc.reasonSubstr, got.Reason)
			}
		})
	}
}

// TestPlanReclaimArithmetic pins the two numbers the operator plans around.
// They are reported whatever the decision is — a refusal must still say what
// running it WOULD have returned, or the operator cannot tell whether it is
// worth freeing up space for.
func TestPlanReclaimArithmetic(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                     string
		in                       ReclaimInput
		wantReclaimable, wantEnd int64
	}{
		{
			name: "freelist times page size",
			in: ReclaimInput{
				FileBytes: 36 * gib, PageSize: 4096, FreelistPages: 3 * mib,
				FreeDiskKnown: true, FreeDiskBytes: 800 * gib,
			},
			wantReclaimable: 12 * gib, wantEnd: 24 * gib,
		},
		{
			name: "reported even when refused",
			in: ReclaimInput{
				FileBytes: 36 * gib, PageSize: 4096, FreelistPages: 3 * mib,
				DaemonLive: true,
			},
			wantReclaimable: 12 * gib, wantEnd: 24 * gib,
		},
		{
			// Defensive: a freelist larger than the file is impossible in
			// SQLite, but clamping at zero beats reporting a negative size.
			name: "post-size never goes negative",
			in: ReclaimInput{
				FileBytes: 1 * gib, PageSize: 4096, FreelistPages: mib,
				FreeDiskKnown: true, FreeDiskBytes: 800 * gib,
			},
			wantReclaimable: 4 * gib, wantEnd: 0,
		},
		{
			name:            "a zero-page database reports zero, not a guess",
			in:              ReclaimInput{},
			wantReclaimable: 0, wantEnd: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := PlanReclaim(tc.in)
			if got.ReclaimableBytes != tc.wantReclaimable {
				t.Errorf("ReclaimableBytes = %d, want %d", got.ReclaimableBytes, tc.wantReclaimable)
			}
			if got.EstimatedAfterBytes != tc.wantEnd {
				t.Errorf("EstimatedAfterBytes = %d, want %d", got.EstimatedAfterBytes, tc.wantEnd)
			}
			if got.RequiredFreeBytes != tc.in.FileBytes {
				t.Errorf("RequiredFreeBytes = %d, want the file size %d (VACUUM INTO needs room for one copy, not two)",
					got.RequiredFreeBytes, tc.in.FileBytes)
			}
		})
	}
}
