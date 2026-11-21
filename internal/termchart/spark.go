package termchart

import (
	"math"
	"strings"
)

// Sparkline renders values as one row of level glyphs, one per value,
// scaled from zero to the largest value. Zero, negative and NaN values are
// a space (no activity and no data both read as blank, the point of a
// sparkline being the shape). It is not width-aware beyond truncating to
// o's width: the caller passes as many values as it wants drawn.
func Sparkline(values []float64, o Options) string {
	g := o.glyphs()
	maxV := 0.0
	for _, v := range values {
		if finite(v) && v > maxV {
			maxV = v
		}
	}
	if len(values) > o.width() {
		values = values[:o.width()]
	}
	cells := make([]cell, len(values))
	levels := len(g.spark)
	for i, v := range values {
		cells[i] = cell{glyph: " ", tone: -1}
		if !finite(v) || v <= 0 || maxV <= 0 {
			continue
		}
		idx := int(math.Ceil(v/maxV*float64(levels))) - 1
		idx = min(max(idx, 0), levels-1)
		cells[i] = cell{glyph: g.spark[idx], tone: 0}
	}
	return strings.TrimRight(o.renderRow(cells), " ")
}
