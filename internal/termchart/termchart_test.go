package termchart

import (
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// golden compares got with testdata/<name>.golden (or rewrites it).
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run go test -run %s -update)", path, err, t.Name())
	}
	if string(want) != got {
		t.Errorf("%s differs\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func usd(v float64) string { return fmt.Sprintf("$%.2f", v) }

func compact(v float64) string {
	switch {
	case v >= 1e6:
		return fmt.Sprintf("%.1fM", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1fK", v/1e3)
	default:
		return fmt.Sprintf("%.0f", v)
	}
}

func pct(v float64) string { return fmt.Sprintf("%.0f%%", v*100) }

var widths = []int{40, 80, 120}

var modes = []struct {
	name string
	o    Options
}{
	{"unicode", Options{}},
	{"ascii", Options{ASCII: true}},
	{"color", Options{Color: true}},
}

func dayLabels(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("10-%02d", i+1)
	}
	return out
}

func spendValues(n int) []float64 {
	out := make([]float64, n)
	for i := range out {
		out[i] = math.Round((2+3*math.Sin(float64(i)/3)+float64(i%5))*100) / 100
		if i == 4 || i == 11 {
			out[i] = 0 // idle days
		}
	}
	return out
}

func TestBarsGolden(t *testing.T) {
	items := []Bar{
		{Label: "claude-sonnet-4-5", Value: 12_400_000, Note: "62%", Tone: 0},
		{Label: "gpt-5-codex-a-very-long-model-name-indeed", Value: 5_100_000, Note: "26%", Tone: 1},
		{Label: "claude-haiku-4-5", Value: 2_300_000, Note: "12%", Tone: 2},
		{Label: "tiny-model", Value: 900, Note: "0%", Tone: 3},
		{Label: "idle", Value: 0, Note: "0%", Tone: 4},
	}
	for _, m := range modes {
		for _, w := range widths {
			o := m.o
			o.Width = w
			t.Run(fmt.Sprintf("%s_%d", m.name, w), func(t *testing.T) {
				golden(t, fmt.Sprintf("bars_%s_%d", m.name, w), Bars(items, compact, o))
			})
		}
	}
}

func TestColumnsGolden(t *testing.T) {
	n := 30
	ai := spendValues(n)
	fees := make([]float64, n)
	for i := range fees {
		if i%7 == 3 {
			fees[i] = 1.25
		}
	}
	series := []Series{{Name: "AI spend", Values: ai}, {Name: "tool fees", Values: fees}}
	for _, m := range modes {
		for _, w := range widths {
			o := m.o
			o.Width = w
			t.Run(fmt.Sprintf("%s_%d", m.name, w), func(t *testing.T) {
				got, err := Columns(dayLabels(n), series, usd, o)
				if err != nil {
					t.Fatal(err)
				}
				golden(t, fmt.Sprintf("columns_%s_%d", m.name, w), got)
			})
		}
	}
}

func TestColumnsSingleSeriesFewPoints(t *testing.T) {
	got, err := Columns([]string{"Mon", "Tue", "Wed"}, []Series{{Name: "tokens", Values: []float64{100, 0, 250}}}, compact, Options{Width: 80, Height: 6})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "columns_few_80", got)
}

func TestLineGolden(t *testing.T) {
	n := 30
	vals := make([]float64, n)
	for i := range vals {
		vals[i] = 0.55 + 0.35*math.Sin(float64(i)/4)
	}
	vals[9], vals[10] = math.NaN(), math.NaN() // no input-side tokens: a gap
	vals[20] = 1.4                             // out of domain: clamped
	for _, m := range modes {
		for _, w := range widths {
			o := m.o
			o.Width = w
			t.Run(fmt.Sprintf("%s_%d", m.name, w), func(t *testing.T) {
				got, err := Line(dayLabels(n), vals, 0, 1, pct, o)
				if err != nil {
					t.Fatal(err)
				}
				golden(t, fmt.Sprintf("line_%s_%d", m.name, w), got)
			})
		}
	}
}

func TestSparklineGolden(t *testing.T) {
	vals := []float64{0, 1, 2, 3, 4, 5, 6, 7, 8, math.NaN(), 8, 4, 0.01, -3}
	var b strings.Builder
	for _, m := range modes {
		fmt.Fprintf(&b, "%s: [%s]\n", m.name, Sparkline(vals, m.o))
	}
	golden(t, "sparkline", b.String())
}

func TestErrors(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		tooMany bool
	}{
		{"columns too many", func() error {
			_, err := Columns(dayLabels(80), []Series{{Name: "a", Values: make([]float64, 80)}}, usd, Options{Width: 80})
			return err
		}(), true},
		{"line too many", func() error {
			_, err := Line(make([]string, 200), make([]float64, 200), 0, 1, pct, Options{Width: 80})
			return err
		}(), true},
		{"columns too many series", func() error {
			s := make([]Series, MaxShades+1)
			for i := range s {
				s[i] = Series{Values: []float64{1}}
			}
			_, err := Columns([]string{"x"}, s, usd, Options{})
			return err
		}(), false},
		{"columns length mismatch", func() error {
			_, err := Columns([]string{"x", "y"}, []Series{{Values: []float64{1}}}, usd, Options{})
			return err
		}(), false},
		{"line empty domain", func() error {
			_, err := Line([]string{"x"}, []float64{1}, 1, 1, pct, Options{})
			return err
		}(), false},
	}
	for _, c := range cases {
		if c.err == nil {
			t.Errorf("%s: want an error", c.name)
			continue
		}
		if errors.Is(c.err, ErrTooManyPoints) != c.tooMany {
			t.Errorf("%s: ErrTooManyPoints=%v want %v (%v)", c.name, !c.tooMany, c.tooMany, c.err)
		}
	}
}

// TestASCIIIsSevenBit and TestNoColorHasNoEscapes pin the fallbacks.
func TestFallbacks(t *testing.T) {
	n := 20
	series := []Series{{Name: "a", Values: spendValues(n)}, {Name: "b", Values: spendValues(n)}}
	render := func(o Options) string {
		c, err := Columns(dayLabels(n), series, usd, o)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Line(dayLabels(n), spendValues(n), 0, 10, usd, o)
		if err != nil {
			t.Fatal(err)
		}
		return c + l + Bars([]Bar{{Label: "x", Value: 3}, {Label: "y", Value: 1}}, usd, o) + Sparkline(spendValues(n), o)
	}
	ascii := render(Options{ASCII: true})
	for i, r := range ascii {
		if r > 0x7e || (r < 0x20 && r != '\n') {
			t.Fatalf("ASCII output has %q at byte %d", r, i)
		}
	}
	for _, o := range []Options{{}, {ASCII: true}} {
		if strings.Contains(render(o), "\x1b[") {
			t.Fatalf("Color=false output carries an escape (%+v)", o)
		}
	}
	if !strings.Contains(render(Options{Color: true}), "\x1b[") {
		t.Fatal("Color=true output has no escape")
	}
}

// TestWidthRespected: no line of a plain render is wider than the width.
func TestWidthRespected(t *testing.T) {
	for _, w := range []int{1, 32, 40, 57, 80, 133} {
		o := Options{Width: w}
		n := min(ColumnsCapacity(o), 25)
		c, err := Columns(dayLabels(n), []Series{{Name: "s", Values: spendValues(n)}}, usd, o)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Line(dayLabels(n), spendValues(n), 0, 10, usd, o)
		if err != nil {
			t.Fatal(err)
		}
		b := Bars([]Bar{{Label: strings.Repeat("m", 60), Value: 1e6, Note: "100%"}}, compact, o)
		for _, line := range strings.Split(c+l+b, "\n") {
			if got := cond.StringWidth(line); got > o.width() {
				t.Errorf("width %d: line is %d wide: %q", w, got, line)
			}
		}
	}
}

func TestNiceCeil(t *testing.T) {
	cases := map[float64]float64{0: 1, -5: 1, 0.7: 1, 1: 1, 1.01: 2, 2.2: 2.5, 3: 5, 7.5: 10, 12: 20, 2400: 2500, 26000: 50000}
	for in, want := range cases {
		if got := niceCeil(in); math.Abs(got-want) > 1e-9 {
			t.Errorf("niceCeil(%v)=%v want %v", in, got, want)
		}
	}
}
