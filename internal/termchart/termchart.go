package termchart

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/fatih/color"
	"github.com/mattn/go-runewidth"
)

// Options are the shared rendering options.
type Options struct {
	// Width is the total width in terminal columns, axis gutter included.
	// Zero or less means DefaultWidth; anything below MinWidth is raised to
	// MinWidth.
	Width int
	// Height is the plot height in rows for Columns and Line. Zero or less
	// means DefaultHeight; it is clamped to [MinHeight, MaxHeight].
	Height int
	// Color emits ANSI colour escapes. The caller decides (NO_COLOR unset
	// and stdout a terminal); the package never inspects the environment.
	Color bool
	// ASCII restricts every glyph to 7-bit ASCII (no block, shade, box or
	// braille characters).
	ASCII bool
}

// Size limits.
const (
	DefaultWidth  = 80
	MinWidth      = 32
	DefaultHeight = 10
	MinHeight     = 4
	MaxHeight     = 40
	// GutterWidth is the y-axis gutter of Columns and Line: an 8-column
	// right-aligned tick label and one axis column.
	GutterWidth = 9
	labelWidth  = GutterWidth - 1
)

// Format renders one value for a tick or a bar label ("$12.40", "1.2M").
// Tick labels longer than 8 columns are truncated, so it should be compact.
type Format func(float64) string

// Series is one named run of values, one per x position.
type Series struct {
	Name   string
	Values []float64
}

// ErrTooManyPoints is returned (wrapped) when a chart has more x positions
// than its width can draw one to a column (two to a column for Line).
var ErrTooManyPoints = errors.New("termchart: more points than the width can draw")

// cond is the width condition for every measurement: East Asian ambiguous
// characters as narrow, regardless of the host locale, so a golden file is
// the same on every machine.
var cond = &runewidth.Condition{EastAsianWidth: false}

func (o Options) width() int {
	w := o.Width
	if w <= 0 {
		w = DefaultWidth
	}
	if w < MinWidth {
		w = MinWidth
	}
	return w
}

func (o Options) height() int {
	h := o.Height
	if h <= 0 {
		h = DefaultHeight
	}
	return min(max(h, MinHeight), MaxHeight)
}

// ColumnsCapacity is how many x positions Columns can draw at o's width.
func ColumnsCapacity(o Options) int { return o.width() - GutterWidth }

// LineCapacity is how many x positions Line can draw at o's width (braille
// cells are two dots wide).
func LineCapacity(o Options) int { return 2 * (o.width() - GutterWidth) }

// tones is the series palette, in order.
var tones = []color.Attribute{color.FgCyan, color.FgMagenta, color.FgYellow, color.FgGreen, color.FgBlue, color.FgRed}

// paint wraps s in series tone t's colour when colour is on. t < 0 or an
// all-space s is returned as is.
func (o Options) paint(t int, s string) string {
	if !o.Color || t < 0 || strings.TrimSpace(s) == "" {
		return s
	}
	c := color.New(tones[t%len(tones)])
	c.EnableColor()
	return c.Sprint(s)
}

// cell is one character cell of a plot row and the tone it is painted in.
type cell struct {
	glyph string
	tone  int
}

// renderRow joins cells, painting each run of one tone with one escape.
func (o Options) renderRow(cells []cell) string {
	var b strings.Builder
	for i := 0; i < len(cells); {
		j := i
		var run strings.Builder
		for j < len(cells) && cells[j].tone == cells[i].tone {
			run.WriteString(cells[j].glyph)
			j++
		}
		b.WriteString(o.paint(cells[i].tone, run.String()))
		i = j
	}
	return b.String()
}

// fit truncates s to w columns (with an ellipsis) and pads it on the right.
func (o Options) fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	tail := "…"
	if o.ASCII {
		tail = "~"
	}
	if cond.StringWidth(s) > w {
		s = cond.Truncate(s, w, tail)
	}
	return cond.FillRight(s, w)
}

// fitLeft truncates s to w columns and pads it on the left (right-aligned).
func (o Options) fitLeft(s string, w int) string {
	return cond.FillLeft(strings.TrimRight(o.fit(s, w), " "), w)
}

// glyphs is the glyph set for one mode.
type glyphs struct {
	vEighths []string // 1..7 eighths of a cell, bottom-up
	hEighths []string // 1..7 eighths of a cell, left to right
	full     string
	shades   []string // full-cell fill per series in a stack
	axisV    string   // y axis
	axisTick string   // y axis at a labelled row
	axisH    string   // x axis
	corner   string   // axis origin
	spark    []string // sparkline levels, low to high
	point    string   // ASCII line-chart point
}

var unicodeGlyphs = glyphs{
	vEighths: []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇"},
	hEighths: []string{"▏", "▎", "▍", "▌", "▋", "▊", "▉"},
	full:     "█",
	shades:   []string{"█", "▓", "▒", "░"},
	axisV:    "│",
	axisTick: "┤",
	axisH:    "─",
	corner:   "└",
	spark:    []string{"▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"},
}

var asciiGlyphs = glyphs{
	full:     "#",
	shades:   []string{"#", "=", "+", ":"},
	axisV:    "|",
	axisTick: "+",
	axisH:    "-",
	corner:   "+",
	spark:    []string{"_", ".", ":", "-", "=", "+", "*", "#"},
	point:    "*",
}

func (o Options) glyphs() glyphs {
	if o.ASCII {
		return asciiGlyphs
	}
	return unicodeGlyphs
}

// MaxShades is how many stacked series Columns can tell apart without
// colour; Columns refuses more.
const MaxShades = 4

// niceCeil rounds v up to 1, 2, 2.5 or 5 times a power of ten, so the top
// tick of a zero-based axis is a round number at or above the data.
func niceCeil(v float64) float64 {
	if v <= 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return 1
	}
	exp := math.Floor(math.Log10(v))
	base := math.Pow(10, exp)
	for _, m := range []float64{1, 2, 2.5, 5, 10} {
		if c := m * base; c >= v*(1-1e-12) {
			return c
		}
	}
	return 10 * base
}

// legend renders "▇ name  ▓ other" lines wrapped to width.
func (o Options) legend(names []string, swatch func(i int) cell) []string {
	var lines []string
	var line strings.Builder
	used := 0
	for i, n := range names {
		sw := swatch(i)
		item := o.paint(sw.tone, sw.glyph) + " " + n
		w := cond.StringWidth(sw.glyph) + 1 + cond.StringWidth(n)
		sep := 0
		if used > 0 {
			sep = 2
		}
		if used > 0 && used+sep+w > o.width() {
			lines = append(lines, line.String())
			line.Reset()
			used, sep = 0, 0
		}
		if sep > 0 {
			line.WriteString("  ")
		}
		line.WriteString(item)
		used += sep + w
	}
	if used > 0 {
		lines = append(lines, line.String())
	}
	return lines
}

// xLabels places labels under the plot: the first left-aligned at its
// position, the last right-aligned at its position, and the middle one
// centred when it does not crowd either. pos gives each index's start
// column and span its width, relative to the plot.
func (o Options) xLabels(labels []string, pos func(i int) int, span int, plotWidth int) string {
	n := len(labels)
	if n == 0 {
		return ""
	}
	row := []rune(strings.Repeat(" ", plotWidth))
	occupied := make([]bool, plotWidth)
	place := func(s string, at int) bool {
		s = o.fit(s, plotWidth)
		s = strings.TrimRight(s, " ")
		rs := []rune(s)
		w := cond.StringWidth(s)
		if w != len(rs) { // a wide rune; place only when it is the sole label
			if n > 1 {
				return false
			}
		}
		at = min(max(at, 0), plotWidth-len(rs))
		lo, hi := max(at-1, 0), min(at+len(rs)+1, plotWidth)
		for k := lo; k < hi; k++ {
			if occupied[k] {
				return false
			}
		}
		for k, r := range rs {
			row[at+k] = r
			occupied[at+k] = true
		}
		return true
	}
	place(labels[0], pos(0))
	if n > 1 {
		last := labels[n-1]
		place(last, pos(n-1)+span-cond.StringWidth(last))
	}
	if n > 2 {
		mid := n / 2
		m := labels[mid]
		place(m, pos(mid)+span/2-cond.StringWidth(m)/2)
	}
	return strings.TrimRight(string(row), " ")
}

func tooMany(n, capacity int) error {
	return fmt.Errorf("%w: %d points, room for %d", ErrTooManyPoints, n, capacity)
}

// finite reports whether v is a real number.
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
