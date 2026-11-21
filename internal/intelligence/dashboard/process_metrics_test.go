package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/procmodel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// metricsBase is an epoch-aligned instant (1700000000 is divisible by 10 and
// by 60), so a 10s bucket grid starts exactly here and the expected bucket
// offsets in the tables below are readable.
var metricsBase = time.Unix(1700000000, 0).UTC()

func sampleAt(offsetSec int, cpuMs, ws, rb, wb int64) procmodel.MetricSample {
	return procmodel.MetricSample{
		T:          metricsBase.Add(time.Duration(offsetSec) * time.Second),
		CPUMs:      cpuMs,
		WorkingSet: ws,
		ReadBytes:  rb,
		WriteBytes: wb,
	}
}

func fptr(v float64) *float64 { return &v }
func iptr(v int64) *int64     { return &v }

// wantPoint is one expected bucket. A nil field asserts "no coverage" (a real
// gap), which is materially different from a zero value.
type wantPoint struct {
	offsetSec int
	cpuPct    *float64
	rssBytes  *int64
	diskBps   *float64
	procs     int
}

func checkPoints(t *testing.T, got []SessionMetricPoint, want []wantPoint) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("point count = %d, want %d (got %+v)", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		wantT := metricsBase.Add(time.Duration(w.offsetSec) * time.Second).Format(time.RFC3339)
		if g.T != wantT {
			t.Errorf("point[%d].t = %s, want %s", i, g.T, wantT)
		}
		checkF(t, i, "cpu_pct", g.CPUPct, w.cpuPct)
		checkF(t, i, "disk_bps", g.DiskBps, w.diskBps)
		checkI(t, i, "rss_bytes", g.RSSBytes, w.rssBytes)
		if w.procs != 0 && g.Procs != w.procs {
			t.Errorf("point[%d].procs = %d, want %d", i, g.Procs, w.procs)
		}
	}
}

func checkF(t *testing.T, i int, name string, got, want *float64) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("point[%d].%s = nil, want %v", i, name, *want)
	case want == nil:
		t.Errorf("point[%d].%s = %v, want nil (no coverage)", i, name, *got)
	case math.Abs(*got-*want) > 0.011:
		t.Errorf("point[%d].%s = %v, want %v", i, name, *got, *want)
	}
}

func checkI(t *testing.T, i int, name string, got, want *int64) {
	t.Helper()
	switch {
	case got == nil && want == nil:
	case got == nil:
		t.Errorf("point[%d].%s = nil, want %d", i, name, *want)
	case want == nil:
		t.Errorf("point[%d].%s = %d, want nil (no coverage)", i, name, *got)
	case *got != *want:
		t.Errorf("point[%d].%s = %d, want %d", i, name, *got, *want)
	}
}

// TestAggregateProcessMetrics is the differentiation + bucketing table. Every
// row is one of the traps that make a raw cumulative counter unplottable.
func TestAggregateProcessMetrics(t *testing.T) {
	const mb = int64(1 << 20)
	tests := []struct {
		name   string
		series []procMetricSeries
		bucket time.Duration
		want   []wantPoint
		// Expected aggregate metadata; zero values are not asserted.
		wantSampled   int
		wantRate      int
		wantCPUSeries bool
		wantNetSeries bool
	}{
		{
			// Monotonic counters: CPU% = Δcpu_ms / Δwall_ms × 100, disk B/s =
			// Δbytes / Δs. Plotted raw these counters would be a straight ramp.
			name: "monotonic counters differentiate to flat rates",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 100*mb, 0, 0),
					sampleAt(10, 5000, 110*mb, 1000, 0),
					sampleAt(20, 10000, 120*mb, 3000, 0),
				},
			}},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: fptr(50), rssBytes: iptr(100 * mb), diskBps: fptr(100), procs: 1},
				{offsetSec: 10, cpuPct: fptr(50), rssBytes: iptr(110 * mb), diskBps: fptr(200), procs: 1},
				// The final sample opens a bucket with a gauge reading but no
				// second sample yet ⇒ RSS present, rate a genuine gap.
				{offsetSec: 20, cpuPct: nil, rssBytes: iptr(120 * mb), diskBps: nil, procs: 1},
			},
			wantSampled:   1,
			wantRate:      1,
			wantCPUSeries: true,
		},
		{
			// A process that EXITS mid-window stops contributing after its last
			// sample — no negative delta, no phantom trailing zero. The subtree
			// total falls because the process genuinely stopped.
			name: "process exits mid-window",
			series: []procMetricSeries{
				{Key: "p1", StartedAt: metricsBase, Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 100*mb, 0, 0),
					sampleAt(10, 5000, 100*mb, 0, 0),
					sampleAt(20, 10000, 100*mb, 0, 0),
				}},
				{Key: "p2", StartedAt: metricsBase, Exited: true, Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 50*mb, 0, 0),
					sampleAt(10, 10000, 50*mb, 0, 0),
				}},
			},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: fptr(150), rssBytes: iptr(150 * mb), procs: 2},
				// p2 is gone: 50% not 50%+0%, and certainly not a negative.
				{offsetSec: 10, cpuPct: fptr(50), rssBytes: iptr(150 * mb), procs: 2},
				{offsetSec: 20, cpuPct: nil, rssBytes: iptr(100 * mb), procs: 1},
			},
			wantSampled: 2,
			wantRate:    2,
		},
		{
			// A process that STARTS mid-window carries a large cumulative CPU
			// counter from before it was attributed. Treating its first sample
			// as a delta against an implicit zero would spike the bucket by its
			// entire lifetime CPU (here +300%); the pair-based derivation never
			// does that.
			name: "process starts mid-window has no first-bucket rate",
			series: []procMetricSeries{
				{Key: "p1", StartedAt: metricsBase, Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 100*mb, 0, 0),
					sampleAt(10, 5000, 100*mb, 0, 0),
					sampleAt(20, 10000, 100*mb, 0, 0),
				}},
				{Key: "p2", StartedAt: metricsBase.Add(10 * time.Second), Samples: []procmodel.MetricSample{
					sampleAt(10, 30000, 20*mb, 0, 0),
					sampleAt(20, 32000, 20*mb, 0, 0),
				}},
			},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: fptr(50), rssBytes: iptr(100 * mb), procs: 1},
				{offsetSec: 10, cpuPct: fptr(70), rssBytes: iptr(120 * mb), procs: 2},
				{offsetSec: 20, cpuPct: nil, rssBytes: iptr(120 * mb), procs: 2},
			},
			wantSampled: 2,
			wantRate:    2,
		},
		{
			// A counter RESET (pid recycled / capture restarted) drops that pair
			// for that metric ONLY — the disk counter of the same pair, which
			// did not reset, still yields its rate.
			name: "counter reset drops only the resetting metric",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 10*mb, 0, 0),
					sampleAt(10, 5000, 10*mb, 1000, 0),
					sampleAt(20, 1000, 10*mb, 3000, 0),
				},
			}},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: fptr(50), rssBytes: iptr(10 * mb), diskBps: fptr(100)},
				{offsetSec: 10, cpuPct: nil, rssBytes: iptr(10 * mb), diskBps: fptr(200)},
				{offsetSec: 20, cpuPct: nil, rssBytes: iptr(10 * mb), diskBps: nil},
			},
			wantSampled: 1,
			wantRate:    1,
		},
		{
			// One sample yields no pair, hence no rate — but the instantaneous
			// gauge is still real and is reported.
			name: "single sample yields gauge only",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples:   []procmodel.MetricSample{sampleAt(0, 4242, 64*mb, 99, 99)},
			}},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: nil, rssBytes: iptr(64 * mb), diskBps: nil, procs: 1},
			},
			wantSampled: 1,
			wantRate:    0,
		},
		{
			name:        "empty ring yields no points",
			series:      []procMetricSeries{{Key: "p1", StartedAt: metricsBase}},
			bucket:      10 * time.Second,
			want:        []wantPoint{},
			wantSampled: 0,
			wantRate:    0,
		},
		{
			name:        "no processes at all",
			series:      nil,
			bucket:      10 * time.Second,
			want:        []wantPoint{},
			wantSampled: 0,
		},
		{
			// Unaligned per-process timestamps: p2 samples 3s off p1's phase, so
			// each of its pairs straddles a bucket boundary. Overlap weighting
			// must give it its true 100%/bucket — NOT 200% from two pairs
			// landing in the same bucket, and NOT a diluted value from the
			// bucket's full width being used as the denominator.
			name: "unaligned timestamps aggregate without double counting",
			series: []procMetricSeries{
				{Key: "p1", StartedAt: metricsBase, Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 0, 0, 0),
					sampleAt(10, 5000, 0, 0, 0),
					sampleAt(20, 10000, 0, 0, 0),
				}},
				{Key: "p2", StartedAt: metricsBase, Samples: []procmodel.MetricSample{
					sampleAt(3, 0, 0, 0, 0),
					sampleAt(13, 10000, 0, 0, 0),
					sampleAt(23, 20000, 0, 0, 0),
				}},
			},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: fptr(150), procs: 2},
				{offsetSec: 10, cpuPct: fptr(150), procs: 2},
				{offsetSec: 20, cpuPct: fptr(100), procs: 1},
			},
			wantSampled: 2,
			wantRate:    2,
		},
		{
			// A 4-thread process legitimately exceeds 100% of one core. Values
			// are per-core-summed and NOT clamped — clamping would hide it.
			name: "multicore cpu exceeds 100 percent",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 0, 0, 0),
					sampleAt(10, 40000, 0, 0, 0),
				},
			}},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: fptr(400), procs: 1},
			},
			wantSampled: 1,
			wantRate:    1,
		},
		{
			// A tree is dominated by short-lived single-sample commands. Their
			// lone readings must not stretch the window across the session and
			// leave the rate charts a mostly-empty strip: the window is
			// anchored to the first bucket with rate coverage.
			name: "leading gauge-only buckets are trimmed when rates exist",
			series: []procMetricSeries{
				// Three one-shot commands, each observed once, long before the
				// long-lived process starts reporting rates.
				{Key: "c1", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(0, 7, 9*mb, 0, 0)}},
				{Key: "c2", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(10, 7, 9*mb, 0, 0)}},
				{Key: "c3", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(20, 7, 9*mb, 0, 0)}},
				{Key: "long", StartedAt: metricsBase, Samples: []procmodel.MetricSample{
					sampleAt(30, 0, 100*mb, 0, 0),
					sampleAt(40, 5000, 100*mb, 0, 0),
				}},
			},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 30, cpuPct: fptr(50), rssBytes: iptr(100 * mb), procs: 1},
				{offsetSec: 40, cpuPct: nil, rssBytes: iptr(100 * mb), procs: 1},
			},
			wantSampled: 4,
			wantRate:    1,
		},
		{
			// With NO rate coverage anywhere, the gauge-only span is genuinely
			// all there is and is kept in full.
			name: "gauge-only span is kept when no rate exists",
			series: []procMetricSeries{
				{Key: "c1", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(0, 7, 9*mb, 0, 0)}},
				{Key: "c2", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(10, 7, 9*mb, 0, 0)}},
			},
			bucket: 10 * time.Second,
			want: []wantPoint{
				{offsetSec: 0, cpuPct: nil, rssBytes: iptr(9 * mb), procs: 1},
				{offsetSec: 10, cpuPct: nil, rssBytes: iptr(9 * mb), procs: 1},
			},
			wantSampled: 2,
			wantRate:    0,
		},
		{
			// A pair spanning far more than the bucket grid is a sampling gap
			// (daemon paused / tab backgrounded): smearing the delta evenly
			// would invent a plateau that never happened, so it is dropped and
			// the chart shows a gap.
			name: "long gap between samples is not smeared",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 0, 0, 0),
					sampleAt(600, 300000, 0, 0, 0),
				},
			}},
			bucket:      10 * time.Second,
			want:        []wantPoint{},
			wantSampled: 1,
			wantRate:    1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := aggregateProcessMetrics(tc.series, tc.bucket)
			checkPoints(t, got.Points, tc.want)
			if got.SampledProcesses != tc.wantSampled {
				t.Errorf("sampled processes = %d, want %d", got.SampledProcesses, tc.wantSampled)
			}
			if got.RateProcesses != tc.wantRate {
				t.Errorf("rate processes = %d, want %d", got.RateProcesses, tc.wantRate)
			}
			if got.Series.Network != tc.wantNetSeries {
				t.Errorf("series.network = %v, want %v", got.Series.Network, tc.wantNetSeries)
			}
			if got.BucketMs != tc.bucket.Milliseconds() {
				t.Errorf("bucket_ms = %d, want %d", got.BucketMs, tc.bucket.Milliseconds())
			}
		})
	}
}

// TestAggregateProcessMetricsNetworkAbsent pins the unmeasured-host contract:
// sampleAt never sets NetMeasured (it defaults false, as it would for a
// Windows-captured process or a ring predating the field), so the series flag
// stays false and the per-point fields are omitted entirely — never a flat
// zero line, which would read as "no traffic" when the truth is "not
// measured". See TestAggregateProcessMetricsNetwork for the measured and
// mixed-measurement cases.
func TestAggregateProcessMetricsNetworkAbsent(t *testing.T) {
	got := aggregateProcessMetrics([]procMetricSeries{{
		Key:       "p1",
		StartedAt: metricsBase,
		Samples: []procmodel.MetricSample{
			sampleAt(0, 0, 1024, 0, 0),
			sampleAt(10, 1000, 1024, 0, 0),
		},
	}}, 10*time.Second)
	if got.Series.Network {
		t.Fatal("series.network is true but no sample in this ring has NetMeasured set")
	}
	for i, p := range got.Points {
		if p.NetRxBps != nil || p.NetTxBps != nil {
			t.Errorf("point[%d] carries network values while unmeasured", i)
		}
	}
	if !got.Series.CPU || !got.Series.RSS {
		t.Errorf("cpu/rss availability = %v/%v, want true/true", got.Series.CPU, got.Series.RSS)
	}
	if got.Series.Disk {
		t.Error("series.disk is true but no disk counter ever advanced measurably")
	}
}

// netSampleAt builds a metric sample carrying the network counters + gate,
// for TestAggregateProcessMetricsNetwork below. WorkingSet is a fixed nonzero
// value so RSS is measured too (a realistic ring never carries network alone),
// and CPUMs ramps linearly so a CPU rate is measured in EVERY bucket from the
// start. That second part matters for the mixed-measurement case: without it,
// aggregateProcessMetrics's window anchor (firstRateBucket in
// aggregateProcessMetrics) would trim the leading buckets that have gauge
// coverage but no rate of ANY kind yet, and the test would be asserting that
// trim instead of the network-specific per-pair gate this test targets.
func netSampleAt(offsetSec int, netRx, netTx int64, measured bool) procmodel.MetricSample {
	return procmodel.MetricSample{
		T:           metricsBase.Add(time.Duration(offsetSec) * time.Second),
		CPUMs:       int64(offsetSec) * 100,
		WorkingSet:  1024,
		NetRxBytes:  netRx,
		NetTxBytes:  netTx,
		NetMeasured: measured,
	}
}

// TestSampleNetworkReadFuncs pins the per-sample Read semantics for
// sampleNetworkRx/sampleNetworkTx: NetMeasured is the SOLE gate on ok, never
// inferred from the byte values (a measured-and-idle sample must report
// ok=true with 0, and an unmeasured sample must report ok=false even if it
// happens to carry a nonzero — e.g. stale — value).
func TestSampleNetworkReadFuncs(t *testing.T) {
	tests := []struct {
		name   string
		sample procmodel.MetricSample
		wantRx int64
		wantTx int64
		wantOK bool
	}{
		{
			name:   "measured with traffic",
			sample: procmodel.MetricSample{NetRxBytes: 1000, NetTxBytes: 500, NetMeasured: true},
			wantRx: 1000, wantTx: 500, wantOK: true,
		},
		{
			name:   "measured and genuinely idle",
			sample: procmodel.MetricSample{NetRxBytes: 0, NetTxBytes: 0, NetMeasured: true},
			wantRx: 0, wantTx: 0, wantOK: true,
		},
		{
			name:   "unmeasured - a nonzero value is never trusted",
			sample: procmodel.MetricSample{NetRxBytes: 4096, NetTxBytes: 2048, NetMeasured: false},
			wantRx: 4096, wantTx: 2048, wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotRx, okRx := sampleNetworkRx(tc.sample)
			if gotRx != tc.wantRx || okRx != tc.wantOK {
				t.Errorf("sampleNetworkRx = (%d, %v), want (%d, %v)", gotRx, okRx, tc.wantRx, tc.wantOK)
			}
			gotTx, okTx := sampleNetworkTx(tc.sample)
			if gotTx != tc.wantTx || okTx != tc.wantOK {
				t.Errorf("sampleNetworkTx = (%d, %v), want (%d, %v)", gotTx, okTx, tc.wantTx, tc.wantOK)
			}
		})
	}
}

// TestAggregateProcessMetricsNetwork drives sampleNetworkRx/sampleNetworkTx
// through the full differentiation + availability pipeline:
//
//   - all samples measured: the cumulative net_rx/net_tx counters
//     differentiate into real B/s rates exactly like CPU/disk, and
//     series.network flips true.
//   - all samples unmeasured: series.network stays false and every point
//     omits the net fields — proven here with RSS still present, so the
//     assertion is "network specifically absent", not "no data at all".
//   - mixed: a single process's ring straddling a measured/unmeasured
//     transition (probes attaching mid-session, or a daemon restart). This
//     is NOT special-cased — it falls out of the existing PER-PAIR gate in
//     accumulateCounters, which requires BOTH samples of a differentiation
//     pair to read ok. A pair with one unmeasured end is dropped exactly
//     like an unmeasured-host pair, so the series shows an honest gap across
//     the transition rather than a diluted or fabricated rate; pairs fully
//     inside the measured span differentiate normally.
func TestAggregateProcessMetricsNetwork(t *testing.T) {
	tests := []struct {
		name          string
		series        []procMetricSeries
		wantNetSeries bool
		check         func(t *testing.T, got metricsAggregate)
	}{
		{
			name: "all samples measured differentiates a real rate",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					netSampleAt(0, 0, 0, true),
					netSampleAt(10, 10_000, 5_000, true),  // Δ10000/10s rx, Δ5000/10s tx
					netSampleAt(20, 30_000, 20_000, true), // Δ20000/10s rx, Δ15000/10s tx
				},
			}},
			wantNetSeries: true,
			check: func(t *testing.T, got metricsAggregate) {
				t.Helper()
				if len(got.Points) != 3 {
					t.Fatalf("points = %d, want 3", len(got.Points))
				}
				checkF(t, 0, "net_rx_bps", got.Points[0].NetRxBps, fptr(1000))
				checkF(t, 0, "net_tx_bps", got.Points[0].NetTxBps, fptr(500))
				checkF(t, 1, "net_rx_bps", got.Points[1].NetRxBps, fptr(2000))
				checkF(t, 1, "net_tx_bps", got.Points[1].NetTxBps, fptr(1500))
				// The final sample opens a bucket with no closing pair yet: a
				// genuine gap, not a zero.
				checkF(t, 2, "net_rx_bps", got.Points[2].NetRxBps, nil)
				checkF(t, 2, "net_tx_bps", got.Points[2].NetTxBps, nil)
			},
		},
		{
			name: "all samples unmeasured keeps the network series absent",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					netSampleAt(0, 0, 0, false),
					netSampleAt(10, 0, 0, false),
					netSampleAt(20, 0, 0, false),
				},
			}},
			wantNetSeries: false,
			check: func(t *testing.T, got metricsAggregate) {
				t.Helper()
				if !got.Series.RSS {
					t.Error("series.rss = false, want true - RSS is measured even though network is not")
				}
				if len(got.Points) != 3 {
					t.Fatalf("points = %d, want 3 (gauge coverage keeps the grid populated)", len(got.Points))
				}
				for i, p := range got.Points {
					if p.NetRxBps != nil || p.NetTxBps != nil {
						t.Errorf("point[%d] net = (%v, %v), want nil/nil - every sample is unmeasured", i, p.NetRxBps, p.NetTxBps)
					}
				}
			},
		},
		{
			name: "mixed measured and unmeasured samples gap across the transition",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					netSampleAt(0, 0, 0, false),          // unmeasured baseline
					netSampleAt(10, 0, 0, false),         // still unmeasured — probes not attached yet
					netSampleAt(20, 5_000, 2_000, true),  // probes attach here
					netSampleAt(30, 15_000, 8_000, true), // fully inside the measured span
				},
			}},
			wantNetSeries: true,
			check: func(t *testing.T, got metricsAggregate) {
				t.Helper()
				if len(got.Points) != 4 {
					t.Fatalf("points = %d, want 4", len(got.Points))
				}
				// pair(0,10): both ends unmeasured -> dropped, gap.
				checkF(t, 0, "net_rx_bps", got.Points[0].NetRxBps, nil)
				checkF(t, 0, "net_tx_bps", got.Points[0].NetTxBps, nil)
				// pair(10,20): straddles the transition (one end unmeasured) ->
				// dropped, gap — never diluted or backfilled.
				checkF(t, 1, "net_rx_bps", got.Points[1].NetRxBps, nil)
				checkF(t, 1, "net_tx_bps", got.Points[1].NetTxBps, nil)
				// pair(20,30): both ends measured -> real rate: Δ10000/10s rx,
				// Δ6000/10s tx.
				checkF(t, 2, "net_rx_bps", got.Points[2].NetRxBps, fptr(1000))
				checkF(t, 2, "net_tx_bps", got.Points[2].NetTxBps, fptr(600))
				// final sample: no closing pair, gap.
				checkF(t, 3, "net_rx_bps", got.Points[3].NetRxBps, nil)
				checkF(t, 3, "net_tx_bps", got.Points[3].NetTxBps, nil)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := aggregateProcessMetrics(tc.series, 10*time.Second)
			if got.Series.Network != tc.wantNetSeries {
				t.Errorf("series.network = %v, want %v", got.Series.Network, tc.wantNetSeries)
			}
			tc.check(t, got)
		})
	}
}

// TestAggregateProcessMetricsWindow pins the honest-window metadata: from/to
// bound the data actually covered, and the ring-truncation flag is derived
// from the data (first retained sample vs process start), never from the
// capture-side ring-capacity constant.
func TestAggregateProcessMetricsWindow(t *testing.T) {
	tests := []struct {
		name          string
		series        []procMetricSeries
		wantTruncated bool
	}{
		{
			name: "samples start with the process",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase,
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 1, 0, 0), sampleAt(15, 1, 1, 0, 0), sampleAt(30, 2, 1, 0, 0),
				},
			}},
			wantTruncated: false,
		},
		{
			name: "oldest retained sample is long after process start",
			series: []procMetricSeries{{
				Key:       "p1",
				StartedAt: metricsBase.Add(-30 * time.Minute),
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 1, 0, 0), sampleAt(15, 1, 1, 0, 0), sampleAt(30, 2, 1, 0, 0),
				},
			}},
			wantTruncated: true,
		},
		{
			name: "unknown process start cannot prove truncation",
			series: []procMetricSeries{{
				Key: "p1",
				Samples: []procmodel.MetricSample{
					sampleAt(0, 0, 1, 0, 0), sampleAt(15, 1, 1, 0, 0),
				},
			}},
			wantTruncated: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := aggregateProcessMetrics(tc.series, 15*time.Second)
			if got.WindowTruncated != tc.wantTruncated {
				t.Errorf("window_truncated = %v, want %v", got.WindowTruncated, tc.wantTruncated)
			}
			if len(got.Points) == 0 {
				t.Fatal("expected points")
			}
			if got.From.IsZero() || !got.To.After(got.From) {
				t.Errorf("window [%s, %s] is not a forward interval", got.From, got.To)
			}
		})
	}
}

// TestAggregateProcessMetricsBoundedPoints pins the series bound: an explicit
// fine ?bucket= over a long session returns the most RECENT metricsMaxPoints
// buckets rather than an unbounded payload, and from/to report that honestly.
func TestAggregateProcessMetricsBoundedPoints(t *testing.T) {
	var samples []procmodel.MetricSample
	for i := 0; i <= 600; i++ { // 600 samples, 1s apart, 1ms of CPU each
		samples = append(samples, sampleAt(i, int64(i), 4096, 0, 0))
	}
	got := aggregateProcessMetrics([]procMetricSeries{{
		Key: "p1", StartedAt: metricsBase, Samples: samples,
	}}, time.Second)
	if len(got.Points) != metricsMaxPoints {
		t.Fatalf("points = %d, want the %d-point cap", len(got.Points), metricsMaxPoints)
	}
	wantFrom := metricsBase.Add(time.Duration(600-metricsMaxPoints+1) * time.Second)
	if !got.From.Equal(wantFrom) {
		t.Errorf("from = %s, want %s (the most recent slice)", got.From, wantFrom)
	}
	if window := got.To.Sub(got.From); window != time.Duration(metricsMaxPoints)*time.Second {
		t.Errorf("window = %s, want %s", window, time.Duration(metricsMaxPoints)*time.Second)
	}
	// 1 ms of CPU per 1000 ms of wall = 0.1%. The final bucket holds only the
	// last sample's instant, so the newest RATE is the point before it.
	if p := got.Points[len(got.Points)-2]; p.CPUPct == nil || math.Abs(*p.CPUPct-0.1) > 0.001 {
		t.Errorf("newest cpu_pct = %v, want 0.1", p.CPUPct)
	}
}

// TestChooseBucket pins the "never hardcode the capture cadence" rule: the
// default bucket is derived from the OBSERVED sampling interval, so raising
// the sample frequency automatically tightens the grid.
func TestChooseBucket(t *testing.T) {
	tests := []struct {
		name           string
		explicit       time.Duration
		sampleInterval time.Duration
		window         time.Duration
		want           time.Duration
	}{
		{name: "explicit wins", explicit: 30 * time.Second, sampleInterval: 15 * time.Second, window: time.Hour, want: 30 * time.Second},
		{name: "explicit clamped low", explicit: time.Millisecond, want: time.Second},
		{name: "explicit clamped high", explicit: 48 * time.Hour, want: time.Hour},
		{name: "follows a 15s cadence", sampleInterval: 15 * time.Second, window: 15 * time.Minute, want: 15 * time.Second},
		{name: "follows a faster 2s cadence", sampleInterval: 2 * time.Second, window: 3 * time.Minute, want: 2 * time.Second},
		{
			// Resolution is preserved over history on a live panel: a long
			// session keeps capture-cadence buckets and the point cap trims the
			// window to its most recent slice instead.
			name:           "a long session keeps capture resolution",
			sampleInterval: time.Second,
			window:         10 * time.Hour,
			want:           time.Second,
		},
		{name: "no cadence observed falls back to the window split", sampleInterval: 0, window: 40 * time.Minute, want: time.Minute},
		{name: "no cadence and a huge window is split into points", sampleInterval: 0, window: 10 * time.Hour, want: 15 * time.Minute},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chooseBucket(tc.explicit, tc.sampleInterval, tc.window); got != tc.want {
				t.Errorf("chooseBucket = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestMedianSampleInterval covers the cadence derivation, including the
// unaligned multi-process case and the not-derivable case.
func TestMedianSampleInterval(t *testing.T) {
	tests := []struct {
		name   string
		series []procMetricSeries
		want   time.Duration
	}{
		{name: "no samples", want: 0},
		{
			name:   "single sample is not an interval",
			series: []procMetricSeries{{Samples: []procmodel.MetricSample{sampleAt(0, 0, 0, 0, 0)}}},
			want:   0,
		},
		{
			name: "median across two unaligned processes",
			series: []procMetricSeries{
				{Samples: []procmodel.MetricSample{sampleAt(0, 0, 0, 0, 0), sampleAt(10, 0, 0, 0, 0), sampleAt(20, 0, 0, 0, 0)}},
				{Samples: []procmodel.MetricSample{sampleAt(3, 0, 0, 0, 0), sampleAt(15, 0, 0, 0, 0)}},
			},
			want: 10 * time.Second,
		},
		{
			name: "backwards timestamps are ignored",
			series: []procMetricSeries{
				{Samples: []procmodel.MetricSample{sampleAt(0, 0, 0, 0, 0), sampleAt(0, 0, 0, 0, 0), sampleAt(5, 0, 0, 0, 0)}},
			},
			want: 5 * time.Second,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := medianSampleInterval(tc.series); got != tc.want {
				t.Errorf("medianSampleInterval = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestMetricsReason pins the table-driven explanation for an empty series —
// an empty panel must say WHY, not just render nothing.
func TestMetricsReason(t *testing.T) {
	tests := []struct {
		name string
		in   metricsReasonInput
		want string
	}{
		{name: "points need no reason", in: metricsReasonInput{ProcessEnabled: false, Points: 3}, want: ""},
		{name: "capture disabled", in: metricsReasonInput{}, want: "capture_disabled"},
		{name: "nothing attributed", in: metricsReasonInput{ProcessEnabled: true}, want: "no_processes"},
		{name: "attributed but never sampled", in: metricsReasonInput{ProcessEnabled: true, Processes: 3}, want: "no_samples"},
		{
			name: "sampled once, no rate yet",
			in:   metricsReasonInput{ProcessEnabled: true, Processes: 3, SampledProcesses: 2},
			want: "awaiting_second_sample",
		},
		{
			name: "rates derivable but every pair was dropped",
			in:   metricsReasonInput{ProcessEnabled: true, Processes: 3, SampledProcesses: 2, RateProcesses: 2},
			want: "no_points",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := metricsReason(tc.in); got != tc.want {
				t.Errorf("metricsReason = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHandleSessionMetrics drives the real route end to end: two attributed
// processes with unaligned rings go into the store, and GET
// /api/session/<id>/metrics comes back with a differentiated, subtree-summed
// series (not one process's raw counters).
func TestHandleSessionMetrics(t *testing.T) {
	s, _ := newTestServer(t) // seeds session "sA"
	ctx := context.Background()
	st := store.New(s.db())

	base := time.Now().UTC().Add(-2 * time.Minute).Truncate(time.Second)
	ring := func(offsets []int, cpuStep, wsBytes int64) []procmodel.MetricSample {
		out := make([]procmodel.MetricSample, 0, len(offsets))
		for i, off := range offsets {
			out = append(out, procmodel.MetricSample{
				T:          base.Add(time.Duration(off) * time.Second),
				CPUMs:      int64(i) * cpuStep,
				WorkingSet: wsBytes,
				ReadBytes:  int64(i) * 1000,
			})
		}
		return out
	}
	r1 := dashProcRun("m_a", "", "sA", 400, "node", "node a.js", base)
	r1.MetricSamples = ring([]int{0, 10, 20, 30}, 5000, 100<<20) // 50% of one core
	r2 := dashProcRun("m_b", "m_a", "sA", 401, "node", "node b.js", base)
	r2.MetricSamples = ring([]int{3, 13, 23}, 10000, 50<<20) // 100%, unaligned phase
	if _, err := st.PersistRuns(ctx, []procmodel.ProcessRun{r1, r2}); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/metrics?bucket=10s", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET metrics: %d - %s", rr.Code, rr.Body.String())
	}
	var resp SessionMetricsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v - %s", err, rr.Body.String())
	}
	if resp.SessionID != "sA" {
		t.Errorf("session_id = %q, want sA", resp.SessionID)
	}
	if resp.BucketMs != 10000 {
		t.Errorf("bucket_ms = %d, want 10000 (the explicit ?bucket=10s)", resp.BucketMs)
	}
	if resp.SampledProcesses != 2 || resp.RateProcesses != 2 {
		t.Errorf("sampled/rate = %d/%d, want 2/2", resp.SampledProcesses, resp.RateProcesses)
	}
	if resp.CPUScale != "per_core_sum" || resp.CPUCores <= 0 {
		t.Errorf("cpu scale/cores = %q/%d, want per_core_sum with a positive core count", resp.CPUScale, resp.CPUCores)
	}
	if !resp.Series.CPU || !resp.Series.RSS || !resp.Series.Disk {
		t.Errorf("series = %+v, want cpu/rss/disk all measured", resp.Series)
	}
	if resp.Series.Network {
		t.Error("series.network is true - this fixture's rings never set NetMeasured")
	}
	if resp.Reason != "" {
		t.Errorf("reason = %q, want empty (points were returned)", resp.Reason)
	}
	if len(resp.Points) < 3 {
		t.Fatalf("points = %d, want at least 3", len(resp.Points))
	}
	// Both processes are live across the middle bucket: 50% + 100% summed, and
	// their RSS summed. A single-process chart would have shown 50 or 100.
	var mid *SessionMetricPoint
	for i := range resp.Points {
		if resp.Points[i].CPUPct != nil && resp.Points[i].Procs == 2 {
			mid = &resp.Points[i]
			break
		}
	}
	if mid == nil {
		t.Fatalf("no bucket with both processes contributing: %+v", resp.Points)
	}
	if math.Abs(*mid.CPUPct-150) > 0.011 {
		t.Errorf("summed cpu_pct = %v, want 150", *mid.CPUPct)
	}
	if mid.RSSBytes == nil || *mid.RSSBytes != int64(150<<20) {
		t.Errorf("summed rss = %v, want %d", mid.RSSBytes, int64(150<<20))
	}
	if mid.DiskBps == nil || *mid.DiskBps <= 0 {
		t.Errorf("disk_bps = %v, want a positive differentiated rate", mid.DiskBps)
	}
}

// TestHandleSessionMetricsEmpty pins the honest empty payload: a session with
// no attributed processes returns a machine-readable reason instead of a bare
// empty array the UI would have to guess about.
func TestHandleSessionMetricsEmpty(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/metrics", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET metrics: %d - %s", rr.Code, rr.Body.String())
	}
	var resp SessionMetricsResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v - %s", err, rr.Body.String())
	}
	if len(resp.Points) != 0 {
		t.Errorf("points = %d, want 0", len(resp.Points))
	}
	if resp.Reason == "" {
		t.Error("reason is empty - an empty series must explain itself")
	}
	if !strings.Contains(rr.Body.String(), `"points":[]`) {
		t.Errorf("points serialized as null, want []: %s", rr.Body.String())
	}
}

// TestHandleSessionMetricsBadBucket pins the input guard.
func TestHandleSessionMetricsBadBucket(t *testing.T) {
	s, _ := newTestServer(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/sA/metrics?bucket=banana", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("GET metrics with a bad bucket: %d, want 400", rr.Code)
	}
}

// TestForEachBucketOverlap covers the grid arithmetic that makes unaligned
// timestamps aggregate: the overlaps of one interval always sum to its length.
func TestForEachBucketOverlap(t *testing.T) {
	tests := []struct {
		name         string
		fromSec      int
		toSec        int
		bucket       time.Duration
		wantBuckets  int
		wantTotalSum float64
	}{
		{name: "inside one bucket", fromSec: 1, toSec: 9, bucket: 10 * time.Second, wantBuckets: 1, wantTotalSum: 8000},
		{name: "straddles two buckets", fromSec: 3, toSec: 13, bucket: 10 * time.Second, wantBuckets: 2, wantTotalSum: 10000},
		{name: "exactly one bucket", fromSec: 0, toSec: 10, bucket: 10 * time.Second, wantBuckets: 1, wantTotalSum: 10000},
		{name: "spans three buckets", fromSec: 5, toSec: 25, bucket: 10 * time.Second, wantBuckets: 3, wantTotalSum: 20000},
		{name: "empty interval", fromSec: 5, toSec: 5, bucket: 10 * time.Second, wantBuckets: 0},
		{name: "backwards interval", fromSec: 9, toSec: 4, bucket: 10 * time.Second, wantBuckets: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var n int
			var total float64
			forEachBucketOverlap(
				metricsBase.Add(time.Duration(tc.fromSec)*time.Second),
				metricsBase.Add(time.Duration(tc.toSec)*time.Second),
				tc.bucket,
				func(_ int64, overlapMs float64) { n++; total += overlapMs },
			)
			if n != tc.wantBuckets {
				t.Errorf("bucket count = %d, want %d", n, tc.wantBuckets)
			}
			if math.Abs(total-tc.wantTotalSum) > 0.001 {
				t.Errorf("overlap sum = %v ms, want %v ms", total, tc.wantTotalSum)
			}
		})
	}
}

// referenceSeries is the pre-bounded projection of the handler: every row of
// the session, read whole through ProcessRunsForSession, rings re-sorted.
// The bounded path must aggregate to exactly what this does.
func referenceSeries(runs []store.ProcessRunRow) []procMetricSeries {
	out := make([]procMetricSeries, 0, len(runs))
	for _, r := range runs {
		samples := append([]procmodel.MetricSample(nil), r.MetricSamples...)
		sort.SliceStable(samples, func(i, j int) bool { return samples[i].T.Before(samples[j].T) })
		out = append(out, procMetricSeries{Key: r.ProcessKey, StartedAt: r.StartedAt, Exited: r.Exited, Samples: samples})
	}
	return out
}

// seedLongMetricsSession stores a session shaped like a long live one: many
// short processes that ran and exited two hours before the newest sighting,
// one with a truncated ring, a few ring-less rows, and a handful of live
// processes sampled every 2s up to now. It returns how many live ring rows it
// stored.
func seedLongMetricsSession(t *testing.T, st *store.Store, now time.Time) int {
	t.Helper()
	var runs []procmodel.ProcessRun
	old := now.Add(-2 * time.Hour)
	for i := range 400 {
		start := old.Add(time.Duration(i) * 3 * time.Second)
		r := dashProcRun(fmt.Sprintf("old-%03d", i), "", "sA", 1000+i, "git", "git status", start)
		r.LastSeenAt = start.Add(4 * time.Second)
		n := 1 + i%3 // one to three samples: the single-sample majority of a real session
		for k := range n {
			r.MetricSamples = append(r.MetricSamples, procmodel.MetricSample{
				T: start.Add(time.Duration(k) * 2 * time.Second), CPUMs: int64(k) * 300,
				WorkingSet: int64(8+i%5) << 20, ReadBytes: int64(k) * 4096,
			})
		}
		if i == 7 { // a ring that evicted its head: truncation evidence from settled history
			for k := range r.MetricSamples {
				r.MetricSamples[k].T = r.MetricSamples[k].T.Add(time.Minute)
			}
			r.LastSeenAt = r.LastSeenAt.Add(time.Minute)
		}
		if i%50 == 0 { // ring-less rows still count as processes
			r.MetricSamples = nil
		}
		runs = append(runs, r)
	}
	live := 0
	for i := range 4 {
		start := now.Add(-time.Duration(20+i*3) * time.Minute)
		r := dashProcRun(fmt.Sprintf("live-%d", i), "", "sA", 5000+i, "node", "node server.js", start)
		r.Exited = false
		r.LastSeenAt = now
		// The live ring holds the last 3 minutes at the 2s cadence, offset per
		// process so the timestamps are unaligned across the tree.
		for k := 0; k <= 90; k++ {
			ts := now.Add(-3*time.Minute + time.Duration(k)*2*time.Second + time.Duration(i)*300*time.Millisecond)
			if ts.After(now) {
				break
			}
			r.MetricSamples = append(r.MetricSamples, procmodel.MetricSample{
				T: ts, CPUMs: int64(k) * int64(500+i*250), WorkingSet: int64(100+i*10) << 20,
				ReadBytes: int64(k) * 10000, WriteBytes: int64(k) * 2000,
			})
		}
		runs = append(runs, r)
		live++
	}
	if _, err := st.PersistRuns(context.Background(), runs); err != nil {
		t.Fatalf("PersistRuns: %v", err)
	}
	return live
}

// TestLoadSessionMetricSeriesMatchesFullRead pins the bounded metrics read:
// across repeated polls of a long session, the response aggregates to exactly
// what reading every row whole did, while every poll after the first decodes
// only the unsettled tail. A bucket wide enough to reach back into the
// settled history falls back to a full read, with the same result.
func TestLoadSessionMetricSeriesMatchesFullRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		bucket time.Duration
		// tailOnly is the expected tail-only flag of polls 1, 2 and 3.
		tailOnly [3]bool
		// liveOnly: a tail-only poll decodes just the live rows.
		liveOnly bool
	}{
		{name: "derived bucket", bucket: 0, tailOnly: [3]bool{false, true, true}, liveOnly: true},
		{name: "explicit 10s bucket", bucket: 10 * time.Second, tailOnly: [3]bool{false, true, true}, liveOnly: true},
		// A 1h grid covers the whole session: the second poll finds the settled
		// rows inside the grid and re-reads everything at an age that settles
		// nothing; the third poll's (empty) mark holds, so its tail is the lot.
		{name: "1h bucket reaching into history", bucket: time.Hour, tailOnly: [3]bool{false, false, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestServer(t)
			ctx := context.Background()
			st := store.New(s.db())
			now := time.Now().UTC().Truncate(time.Second)
			live := seedLongMetricsSession(t, st, now)

			runs, err := st.ProcessRunsForSession(ctx, "sA")
			if err != nil {
				t.Fatalf("ProcessRunsForSession: %v", err)
			}
			want := aggregateProcessMetrics(referenceSeries(runs), tc.bucket)
			if len(want.Points) == 0 || !want.Series.CPU || !want.WindowTruncated {
				t.Fatalf("fixture too weak: points=%d series=%+v truncated=%v", len(want.Points), want.Series, want.WindowTruncated)
			}
			for poll := range 3 {
				in, err := loadSessionMetricSeries(ctx, s.db(), "sA", tc.bucket)
				if err != nil {
					t.Fatalf("poll %d: %v", poll+1, err)
				}
				if in.total != int64(len(runs)) {
					t.Errorf("poll %d: total = %d, want %d", poll+1, in.total, len(runs))
				}
				if in.tailOnly != tc.tailOnly[poll] {
					t.Errorf("poll %d: tailOnly = %v, want %v", poll+1, in.tailOnly, tc.tailOnly[poll])
				}
				if in.tailOnly && tc.liveOnly && len(in.series) != live {
					t.Errorf("poll %d: decoded %d series, want only the %d live ones", poll+1, len(in.series), live)
				}
				if got := aggregateWithFacts(in.series, in.facts, tc.bucket); !reflect.DeepEqual(got, want) {
					t.Errorf("poll %d: bounded aggregate differs from the full read:\n got  bucket=%d interval=%d sampled=%d rated=%d trunc=%v series=%+v points=%d from=%s\n want bucket=%d interval=%d sampled=%d rated=%d trunc=%v series=%+v points=%d from=%s",
						poll+1, got.BucketMs, got.SampleIntervalMs, got.SampledProcesses, got.RateProcesses, got.WindowTruncated, got.Series, len(got.Points), got.From,
						want.BucketMs, want.SampleIntervalMs, want.SampledProcesses, want.RateProcesses, want.WindowTruncated, want.Series, len(want.Points), want.From)
				}
			}
		})
	}
}

// TestMetricsFactsMerge pins the property the settled cache rests on: the
// facts of a whole set of series are the merge of the facts of any split of
// it, in either order.
func TestMetricsFactsMerge(t *testing.T) {
	series := []procMetricSeries{
		{Key: "a", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(0, 0, 10, 0, 0), sampleAt(10, 500, 10, 0, 0), sampleAt(20, 900, 10, 0, 0)}},
		{Key: "b", StartedAt: metricsBase.Add(-time.Minute), Samples: []procmodel.MetricSample{sampleAt(5, 0, 20, 100, 0), sampleAt(9, 0, 20, 300, 0)}},
		{Key: "c", Samples: []procmodel.MetricSample{sampleAt(40, 7, 30, 0, 0)}},
		{Key: "d"},
		{Key: "e", StartedAt: metricsBase, Samples: []procmodel.MetricSample{sampleAt(60, 0, 0, 0, 50), sampleAt(63, 0, 0, 0, 90)}},
	}
	whole := factsOf(series)
	for split := 0; split <= len(series); split++ {
		a, b := factsOf(series[:split]), factsOf(series[split:])
		if got := a.merge(b); !reflect.DeepEqual(got, whole) {
			t.Errorf("split %d: a.merge(b) = %+v, want %+v", split, got, whole)
		}
		if got := b.merge(a); !reflect.DeepEqual(got, whole) {
			t.Errorf("split %d: b.merge(a) = %+v, want %+v", split, got, whole)
		}
	}
	if !whole.truncated(whole.sampleInterval()) {
		t.Error("series b starts a minute before its first sample: want truncated")
	}
}
