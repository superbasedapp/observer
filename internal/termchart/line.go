package termchart

import (
	"fmt"
	"math"
	"strings"
)

// braille dot bits, [x][y] within a 2x4 cell (y from the top).
var brailleBits = [2][4]rune{{0x01, 0x02, 0x04, 0x40}, {0x08, 0x10, 0x20, 0x80}}

// Line renders one series as a braille line chart over the fixed domain
// [lo, hi] (the caller chooses it: a rate is drawn on 0..1, never stretched
// to the data). Points are spread evenly across the width, two to a cell;
// consecutive points are joined; a NaN value is a gap, and the line breaks
// there rather than dropping to zero. Values outside the domain are clamped
// to its edge. Tick labels mark the top (hi) and bottom (lo) rows. With
// ASCII each point is a '*' at cell resolution and points are not joined.
func Line(labels []string, values []float64, lo, hi float64, f Format, o Options) (string, error) {
	n := len(values)
	if n == 0 {
		return "", nil
	}
	if len(labels) != n {
		return "", fmt.Errorf("termchart.Line: %d labels for %d values", len(labels), n)
	}
	if !finite(lo) || !finite(hi) || hi <= lo {
		return "", fmt.Errorf("termchart.Line: domain [%v, %v] is empty", lo, hi)
	}
	capacity := LineCapacity(o)
	if n > capacity {
		return "", tooMany(n, capacity)
	}
	g := o.glyphs()
	h := o.height()
	plotW := ColumnsCapacity(o)
	dw, dh := plotW*2, h*4

	// Dot coordinates of each point; ok=false for a gap.
	type dot struct {
		x, y int
		ok   bool
	}
	dots := make([]dot, n)
	for i, v := range values {
		x := 0
		if n > 1 {
			x = int(math.Round(float64(i) * float64(dw-1) / float64(n-1)))
		}
		if !finite(v) {
			dots[i] = dot{x: x}
			continue
		}
		frac := min(max((v-lo)/(hi-lo), 0), 1)
		y := dh - 1 - int(math.Round(frac*float64(dh-1)))
		dots[i] = dot{x: x, y: y, ok: true}
	}

	set := make([][]bool, dh)
	for y := range set {
		set[y] = make([]bool, dw)
	}
	mark := func(x, y int) { set[y][x] = true }
	for i, d := range dots {
		if !d.ok {
			continue
		}
		mark(d.x, d.y)
		if !o.ASCII && i > 0 && dots[i-1].ok {
			drawSegment(dots[i-1].x, dots[i-1].y, d.x, d.y, mark)
		}
	}

	var b strings.Builder
	for r := range h {
		label, axis := "", g.axisV
		switch r {
		case 0:
			label, axis = f(hi), g.axisTick
		case h - 1:
			label, axis = f(lo), g.axisTick
		}
		cells := make([]cell, plotW)
		for c := range plotW {
			cells[c] = cell{glyph: " ", tone: -1}
			if o.ASCII {
				for dy := range 4 {
					for dx := range 2 {
						if set[r*4+dy][c*2+dx] {
							cells[c] = cell{glyph: g.point, tone: 0}
						}
					}
				}
				continue
			}
			var bits rune
			for dx := range 2 {
				for dy := range 4 {
					if set[r*4+dy][c*2+dx] {
						bits |= brailleBits[dx][dy]
					}
				}
			}
			if bits != 0 {
				cells[c] = cell{glyph: string(0x2800 + bits), tone: 0}
			}
		}
		b.WriteString(o.fitLeft(label, labelWidth))
		b.WriteString(axis)
		b.WriteString(o.renderRow(cells))
		b.WriteString("\n")
	}
	b.WriteString(strings.Repeat(" ", labelWidth))
	b.WriteString(g.corner)
	b.WriteString(strings.Repeat(g.axisH, plotW))
	b.WriteString("\n")
	colOf := func(i int) int { return dots[i].x / 2 }
	if xl := o.xLabels(labels, colOf, 1, plotW); xl != "" {
		b.WriteString(strings.Repeat(" ", GutterWidth))
		b.WriteString(xl)
		b.WriteString("\n")
	}
	return trimRows(b.String()), nil
}

// drawSegment walks the dots from (x0, y0) to (x1, y1) (Bresenham).
func drawSegment(x0, y0, x1, y1 int, mark func(x, y int)) {
	dx, dy := abs(x1-x0), -abs(y1-y0)
	sx, sy := 1, 1
	if x0 > x1 {
		sx = -1
	}
	if y0 > y1 {
		sy = -1
	}
	e := dx + dy
	for {
		mark(x0, y0)
		if x0 == x1 && y0 == y1 {
			return
		}
		e2 := 2 * e
		if e2 >= dy {
			e += dy
			x0 += sx
		}
		if e2 <= dx {
			e += dx
			y0 += sy
		}
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
