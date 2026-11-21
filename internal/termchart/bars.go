package termchart

import (
	"math"
	"strings"
)

// Bar is one row of a horizontal bar chart.
type Bar struct {
	// Label names the row (a model id). Truncated to fit.
	Label string
	// Value is the bar's length, measured from zero. Negative and non-finite
	// values draw no bar.
	Value float64
	// Note is an optional trailing column ("41%").
	Note string
	// Tone is the palette index the bar is painted in when colour is on.
	Tone int
}

// maxBarLabel caps the label column so a long model id cannot starve the
// bars.
const maxBarLabel = 28

// Bars renders one row per item: label, a bar scaled so the largest value
// spans the bar area, the formatted value, and the note. Bars start at
// zero; a positive value too small to see still draws the thinnest sliver,
// so "small" and "none" never look alike. Rows keep the caller's order.
func Bars(items []Bar, f Format, o Options) string {
	if len(items) == 0 {
		return ""
	}
	g := o.glyphs()
	width := o.width()
	labelW, valueW, noteW := 0, 0, 0
	values := make([]string, len(items))
	maxV := 0.0
	for i, it := range items {
		labelW = max(labelW, cond.StringWidth(it.Label))
		values[i] = f(it.Value)
		valueW = max(valueW, cond.StringWidth(values[i]))
		noteW = max(noteW, cond.StringWidth(it.Note))
		if finite(it.Value) && it.Value > maxV {
			maxV = it.Value
		}
	}
	labelW = min(labelW, maxBarLabel, width/3)
	fixed := labelW + 1 + 1 + valueW
	if noteW > 0 {
		fixed += 1 + noteW
	}
	barW := max(width-fixed, 1)
	var b strings.Builder
	for i, it := range items {
		cells := make([]cell, barW)
		for k := range cells {
			cells[k] = cell{glyph: " ", tone: -1}
		}
		if finite(it.Value) && it.Value > 0 && maxV > 0 {
			eighths := int(math.Round(it.Value / maxV * float64(barW*8)))
			if o.ASCII {
				eighths = int(math.Round(float64(eighths)/8)) * 8
			}
			if eighths == 0 {
				// Visible, never mistaken for zero.
				tiny := ""
				if o.ASCII {
					tiny = "."
				} else {
					tiny = g.hEighths[0]
				}
				cells[0] = cell{glyph: tiny, tone: it.Tone}
			}
			for k := 0; k < barW && eighths > 0; k++ {
				switch {
				case eighths >= 8:
					cells[k] = cell{glyph: g.full, tone: it.Tone}
					eighths -= 8
				default:
					cells[k] = cell{glyph: g.hEighths[eighths-1], tone: it.Tone}
					eighths = 0
				}
			}
		}
		b.WriteString(o.fit(it.Label, labelW))
		b.WriteString(" ")
		b.WriteString(o.renderRow(cells))
		b.WriteString(" ")
		b.WriteString(cond.FillLeft(values[i], valueW))
		if noteW > 0 {
			b.WriteString(" ")
			b.WriteString(cond.FillLeft(it.Note, noteW))
		}
		b.WriteString("\n")
	}
	return trimRows(b.String())
}

// trimRows strips trailing spaces from every line (a golden file and a
// copied block then carry no invisible padding). Escapes are kept.
func trimRows(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " ")
	}
	return strings.Join(lines, "\n")
}
