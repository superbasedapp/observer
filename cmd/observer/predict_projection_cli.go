package main

import (
	"fmt"
	"io"
	"math"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/predictsvc"
)

// predict_projection_cli.go prints the run-out projection of `observer
// predict`: the same predictsvc.Build result GET /api/session/<id>/predict
// returns and the dashboard's Cost & limits tab renders. Nothing here
// derives a number; it only words the projection's own fields.

// projectionNoteWords words the projection's closed note vocabulary. The
// notes a line already states (no rate yet, used up, window reset) are not
// repeated.
var projectionNoteWords = map[predict.ProjectionNote]string{
	predict.NoteCapacityTooSmall:  "too little used to estimate the whole limit",
	predict.NoteCarriedForward:    "the share is the last reading carried forward by the usage captured since",
	predict.NoteLocalOnly:         "token and dollar figures count this machine only",
	predict.NoteReadingStale:      "the reading is more than 6 hours old",
	predict.NoteWindowInferred:    "the current window's start is inferred from the last reset",
	predict.NoteUnpriced:          "some usage has no price, so dollars are a lower bound",
	predict.NoteTimezoneAssumed:   "the budget's timezone is not known here, so UTC is assumed",
	predict.NoteOtherMachines:     "the spend includes your other machines, the usage figures do not",
	predict.NoteNoMessageEstimate: "no next-message estimate to count prompts in",
}

// projectionPaceWords words the pace verdict.
var projectionPaceWords = map[string]string{
	"ahead":   "ahead of an even pace",
	"on_pace": "on an even pace",
	"behind":  "behind an even pace",
}

// printProjection prints the projection block.
func printProjection(w io.Writer, proj predictsvc.Projection, tokens bool, now time.Time) {
	fmt.Fprintln(w, "\nRun-out projection:")
	if len(proj.Limits) == 0 && len(proj.Budgets) == 0 {
		fmt.Fprintln(w, "  no limit reading and no budget in force.")
		return
	}
	for _, p := range proj.Limits {
		printProjectionRow(w, p, tokens, now)
	}
	if len(proj.Limits) > 0 && len(proj.CountedTools) > 1 {
		fmt.Fprintf(w, "  the limits count every session of: %s\n", strings.Join(proj.CountedTools, ", "))
	}
	for _, p := range proj.Budgets {
		printProjectionRow(w, p, tokens, now)
	}
}

// printProjectionRow prints one window: a headline and its notes.
func printProjectionRow(w io.Writer, p predict.Projection, tokens bool, now time.Time) {
	fmt.Fprintf(w, "  %s: %s\n", projectionLabel(p), strings.Join(projectionFacts(p, tokens, now), " · "))
	var notes []string
	for _, n := range p.Notes {
		if words, ok := projectionNoteWords[n]; ok {
			notes = append(notes, words)
		}
	}
	if len(notes) > 0 {
		fmt.Fprintf(w, "    notes: %s\n", strings.Join(notes, "; "))
	}
}

// projectionLabel names the window.
func projectionLabel(p predict.Projection) string {
	if p.Kind == "limit" {
		if p.Key == "5h" {
			return "5-hour limit"
		}
		return p.Key + " limit"
	}
	label := p.Origin + " " + p.Key + " budget"
	var detail []string
	if p.Scope != "" {
		detail = append(detail, p.Scope)
	}
	if p.Subject != "" {
		detail = append(detail, p.Subject)
	}
	if p.Enforcement != "" {
		detail = append(detail, p.Enforcement)
	}
	if len(detail) > 0 {
		label += " (" + strings.Join(detail, ", ") + ")"
	}
	return label
}

// projectionFacts is the headline's facts, in reading order.
func projectionFacts(p predict.Projection, tokens bool, now time.Time) []string {
	switch p.State {
	case predict.StateNoResetTime:
		f := []string{"the reading has no reset time, so nothing is projected"}
		if p.UsedFrac != nil {
			f = append([]string{projPct(*p.UsedFrac) + " used"}, f...)
		}
		return f
	case predict.StateReset:
		return []string{"the window reset since the last reading, so nothing is projected"}
	case predict.StateResetInferred:
		f := []string{"the window reset since the last reading", fmtTokens(p.Used.Tokens) + " tokens captured since it restarted"}
		return append(f, projResetFact(p, now)...)
	}
	var f []string
	if p.UsedFracEst != nil && p.LeftFrac != nil {
		used := projPct(*p.UsedFracEst)
		if p.UsedFracIsEstimate {
			used = "about " + used
		}
		f = append(f, used+" used, "+projPct(*p.LeftFrac)+" left")
	}
	if left := projLeftAmount(p, tokens); left != "" {
		f = append(f, left)
	}
	f = append(f, projResetFact(p, now)...)
	f = append(f, projRunOutFacts(p, tokens, now)...)
	if p.Pace != nil {
		if words, ok := projectionPaceWords[p.Pace.Verdict]; ok {
			f = append(f, words)
		}
	}
	if m := p.MorePrompts; m != nil && m.Mid > 0 {
		f = append(f, fmt.Sprintf("about %s more typical prompts", projNum(m.Mid)))
	}
	if p.Confidence != "" {
		f = append(f, "confidence "+p.Confidence)
	}
	return f
}

// projResetFact says when the window resets (or that it does not).
func projResetFact(p predict.Projection, now time.Time) []string {
	switch {
	case p.State == predict.StateRolling:
		return []string{"rolling window"}
	case p.State == predict.StateSession:
		return []string{"this session"}
	case p.ResetsAtUnix != nil:
		d := time.Unix(*p.ResetsAtUnix, 0).Sub(now)
		if d <= 0 {
			return []string{"resets now"}
		}
		return []string{"resets in " + humanizeCLIAge(d)}
	}
	return nil
}

// projRunOutFacts is the projection at the current rate.
func projRunOutFacts(p predict.Projection, tokens bool, now time.Time) []string {
	ro := p.RunOut
	if ro == nil {
		if p.State != predict.StateSession && p.UsedFrac != nil {
			return []string{"too early for a rate"}
		}
		return nil
	}
	var f []string
	switch {
	case ro.Exhausted:
		f = append(f, "used up")
	case ro.RunsOutAtUnix != nil:
		d := time.Unix(*ro.RunsOutAtUnix, 0).Sub(now)
		f = append(f, "runs out in "+humanizeCLIAge(d)+" at this rate")
	case ro.LastsUntilReset && ro.ProjectedLeftAtResetFrac != nil:
		f = append(f, "lasts to the reset with "+projPct(*ro.ProjectedLeftAtResetFrac)+" left at this rate")
	}
	if allowance := projSafeAllowance(p, tokens); allowance != "" {
		f = append(f, allowance)
	}
	return f
}

// projSafeAllowance is the even rate that still lasts: per day for a rolling
// window, per hour otherwise.
func projSafeAllowance(p predict.Projection, tokens bool) string {
	ro := p.RunOut
	if ro == nil || ro.Exhausted {
		return ""
	}
	if p.State == predict.StateRolling {
		switch {
		case !tokens && ro.SafePerDayUSD != nil:
			return "steady rate " + projUSD(*ro.SafePerDayUSD) + "/day"
		case ro.SafePerDayTokens != nil:
			return "steady rate " + fmtTokens(int64(math.Round(*ro.SafePerDayTokens))) + " tokens/day"
		case ro.SafePerDayFrac != nil:
			return "steady rate " + projPct(*ro.SafePerDayFrac) + "/day"
		}
		return ""
	}
	switch {
	case !tokens && ro.SafePerHourUSD != nil:
		return "safe " + projUSD(*ro.SafePerHourUSD) + "/h"
	case ro.SafePerHourTokens != nil:
		return "safe " + fmtTokens(int64(math.Round(*ro.SafePerHourTokens))) + " tokens/h"
	case ro.SafePerHourFrac != nil:
		return "safe " + projPct(*ro.SafePerHourFrac) + "/h"
	}
	return ""
}

// projLeftAmount is what is left in tokens or dollars. Under the token-usage
// developer cost display a dollar figure is left out (the share says it).
func projLeftAmount(p predict.Projection, tokens bool) string {
	approx := func(est bool) string {
		if est {
			return "about "
		}
		return ""
	}
	switch {
	case p.LeftUSD != nil && !tokens && (p.Unit == "usd" || p.LeftTokens == nil):
		return approx(p.LeftUSDIsEstimate) + projUSD(*p.LeftUSD) + " left"
	case p.LeftTokens != nil:
		return approx(p.LeftTokensIsEstimate) + fmtTokens(int64(math.Round(*p.LeftTokens))) + " tokens left"
	}
	return ""
}

func projPct(frac float64) string { return fmt.Sprintf("%d%%", int(math.Round(frac*100))) }

// projUSD renders a dollar figure. no-bare-usd:allow (callers skip it under
// the token-usage display)
func projUSD(v float64) string { return fmt.Sprintf("$%.2f", v) }

func projNum(v float64) string {
	if v == math.Trunc(v) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.1f", v)
}
