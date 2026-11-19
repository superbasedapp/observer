package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/budgetwarn"
	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
)

// budgetStatusPathInDir is the status file path in a DB directory.
func budgetStatusPathInDir(dbDir string) string {
	return filepath.Join(dbDir, budgetwarnfile.StatusFilename)
}

// budgetStatusDisplay returns the developer cost display the daemon last
// recorded in the budget-status file ("" when the file is absent or
// unreadable, which every caller reads as dollars).
func budgetStatusDisplay(statusPath string) string {
	file, err := budgetwarnfile.Read(statusPath)
	if err != nil || file == nil {
		return ""
	}
	return file.Display
}

// budgetStatuslineLabel renders the statusline's "budget" segment from the
// daemon's budget-status file (2026-10-02 budget-latency arc): the highest
// org window at a warn rung this period, e.g. "budget 168% of $0.75/day".
// "" when the file is absent, unreadable, or no window is at a rung - the
// segment is then omitted, never zeroed.
//
// display is the developer cost display to render in ("usd" / "tokens"; in
// tokens a dollar cap reads "budget 168%"). "" falls back to the display the
// daemon recorded in the file.
func budgetStatuslineLabel(statusPath, display string) string {
	file, err := budgetwarnfile.Read(statusPath)
	if err != nil || file == nil {
		return ""
	}
	var best *budgetwarnfile.Window
	for i := range file.Windows {
		w := &file.Windows[i]
		if w.Crossed <= 0 {
			continue
		}
		if best == nil || w.Ratio > best.Ratio {
			best = w
		}
	}
	if best == nil {
		return ""
	}
	if display == "" {
		display = file.Display
	}
	label := budgetwarn.StatusLabel(budgetwarn.WindowStatus{
		Window: best.Window, Unit: best.Unit, Cap: best.Cap, Ratio: best.Ratio,
		Enforcement: best.Enforcement, Crossed: best.Crossed, Effect: best.Effect, Blocked: best.Blocked,
	}, display)
	if best.Subject != "" {
		// A per-tool / per-model cap (Sol A5-04): say which, so "(blocked)"
		// is never read as the whole node being blocked.
		label += " - " + budgetwarn.SubjectLabel(best.Subject)
	}
	return label
}
