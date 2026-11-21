// Package termchart draws charts as plain text for a terminal: horizontal
// bars (Bars), stacked vertical columns (Columns), a braille line chart
// (Line) and a sparkline (Sparkline). It is the renderer behind
// `observer chart` (docs/cli-chart.md); the numbers come from the caller.
//
// Rules every renderer keeps:
//
//   - Width-aware: the caller passes the terminal width in columns; labels
//     are measured and truncated with go-runewidth under a fixed,
//     locale-independent condition, so output is the same on every host.
//   - Honest axes: bars and columns always start at zero; a line chart
//     takes an explicit [min, max] domain from the caller (a rate is drawn
//     on 0..100%, never stretched to the data); a missing value (NaN) is a
//     gap, never a zero.
//   - Colour only on request (Options.Color, decided by the caller from
//     NO_COLOR and whether stdout is a terminal), through fatih/color with
//     colour forced per call, so the package never reads the process's
//     environment or TTY state. Without colour, stacked series are told
//     apart by shade glyphs; with Options.ASCII every glyph is 7-bit ASCII.
//   - Too many points for the width is an error the caller reports (pick a
//     coarser bucket or a wider terminal), never silent resampling.
//
// Pure: no database/sql, net/http, fsnotify, os or os/exec (pinned by
// imports_test.go). No CGO.
package termchart
