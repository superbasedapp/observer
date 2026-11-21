package termchart

import (
	"fmt"
	"math"
	"strings"
)

// maxColumnWidth caps a column so a short window does not draw slabs.
const maxColumnWidth = 6

// Columns renders stacked vertical columns, one per x position (labels[i]),
// stacking series bottom-up in order. The y axis starts at zero and tops
// out at a round number at or above the largest stack, with tick labels at
// the top, the middle and zero. Without colour each series fills its cells
// with its own shade, so at most MaxShades series are accepted. Negative
// and non-finite values count as zero. A legend follows when there is more
// than one series.
func Columns(labels []string, series []Series, f Format, o Options) (string, error) {
	n := len(labels)
	if n == 0 {
		return "", nil
	}
	if err := checkColumns(n, series, o); err != nil {
		return "", err
	}
	g := o.glyphs()
	h := o.height()
	cw := min(ColumnsCapacity(o)/n, maxColumnWidth)
	bw := cw
	if cw >= 2 {
		bw = cw - 1 // one blank column between bars
	}
	plotW := cw * n

	totals := make([]float64, n)
	maxT := 0.0
	for i := range n {
		for _, s := range series {
			totals[i] += positive(s.Values[i])
		}
		maxT = max(maxT, totals[i])
	}
	top := niceCeil(maxT)

	grid := make([][]cell, h) // grid[0] is the top row
	for r := range grid {
		grid[r] = make([]cell, plotW)
		for c := range grid[r] {
			grid[r][c] = cell{glyph: " ", tone: -1}
		}
	}
	for i := range n {
		stack := o.stackCells(series, i, totals[i], top, h)
		for j, c := range stack { // j counts rows from the bottom
			for k := range bw {
				grid[h-1-j][i*cw+k] = c
			}
		}
	}

	var b strings.Builder
	mid := h / 2
	for r := range h {
		label, axis := "", g.axisV
		switch r {
		case 0:
			label, axis = f(top), g.axisTick
		case mid:
			label, axis = f(top*float64(h-mid)/float64(h)), g.axisTick
		}
		b.WriteString(o.fitLeft(label, labelWidth))
		b.WriteString(axis)
		b.WriteString(o.renderRow(grid[r]))
		b.WriteString("\n")
	}
	b.WriteString(o.fitLeft(f(0), labelWidth))
	b.WriteString(g.corner)
	b.WriteString(strings.Repeat(g.axisH, plotW))
	b.WriteString("\n")
	if xl := o.xLabels(labels, func(i int) int { return i * cw }, bw, plotW); xl != "" {
		b.WriteString(strings.Repeat(" ", GutterWidth))
		b.WriteString(xl)
		b.WriteString("\n")
	}
	if len(series) > 1 {
		names := make([]string, len(series))
		for i, s := range series {
			names[i] = s.Name
		}
		for _, l := range o.legend(names, func(i int) cell { return cell{glyph: g.shades[i], tone: i} }) {
			b.WriteString(l)
			b.WriteString("\n")
		}
	}
	return trimRows(b.String()), nil
}

func checkColumns(n int, series []Series, o Options) error {
	if len(series) == 0 {
		return fmt.Errorf("termchart.Columns: no series")
	}
	if len(series) > MaxShades {
		return fmt.Errorf("termchart.Columns: %d series, at most %d can be told apart", len(series), MaxShades)
	}
	for _, s := range series {
		if len(s.Values) != n {
			return fmt.Errorf("termchart.Columns: series %q has %d values for %d labels", s.Name, len(s.Values), n)
		}
	}
	if capacity := ColumnsCapacity(o); n > capacity {
		return tooMany(n, capacity)
	}
	return nil
}

func positive(v float64) float64 {
	if finite(v) && v > 0 {
		return v
	}
	return 0
}

// stackCells returns column i's cells bottom-up (one per filled row). A
// full cell takes the shade of the series whose segment covers the cell's
// midpoint; the partial top cell is an eighth block in the top series'
// tone. ASCII rounds the stack to whole cells. A positive stack too small
// to see is drawn as a sliver, never mistaken for zero.
func (o Options) stackCells(series []Series, i int, total, top float64, h int) []cell {
	g := o.glyphs()
	units := float64(h * 8)
	bounds := make([]int, len(series)) // cumulative boundaries, in eighths
	cum := 0.0
	topSeries := -1
	for s, se := range series {
		if v := positive(se.Values[i]); v > 0 {
			cum += v
			topSeries = s
		}
		bounds[s] = int(math.Round(cum / top * units))
	}
	eighths := int(math.Round(total / top * units))
	if o.ASCII {
		eighths = int(math.Round(float64(eighths)/8)) * 8
	}
	if eighths == 0 && total > 0 {
		eighths = 1
		if o.ASCII {
			eighths = 8
		}
	}
	var out []cell
	for j := 0; j < h && eighths > j*8; j++ {
		lo := j * 8
		if eighths < lo+8 {
			out = append(out, cell{glyph: g.vEighths[eighths-lo-1], tone: topSeries})
			break
		}
		mid, s := lo+4, topSeries
		for k, bd := range bounds {
			if bd > mid {
				s = k
				break
			}
		}
		out = append(out, cell{glyph: g.shades[s], tone: s})
	}
	return out
}
