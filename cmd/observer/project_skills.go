package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer project <id|root> --skills` (S10-SKILLS): the CLI face of the
// Projects-page Skills tab, composed through the same
// dashboard.ComposeProjectSkills seam GET /api/project/{id}/skills uses.
// Three facts are printed side by side and never merged: what a hook
// snapshot observed on disk at session start, what the commit HEAD was on
// held (from the reflog), and what was invoked.

func runProjectSkills(cmd *cobra.Command, st *store.Store, skewSeconds int, projectID int64, days int, since, until time.Time, jsonOut bool) error {
	skew := time.Duration(0)
	if skewSeconds > 0 {
		skew = time.Duration(skewSeconds) * time.Second
	}
	out, err := dashboard.ComposeProjectSkills(cmd.Context(), st, dashboard.ProjectSkillsInput{
		ProjectID: projectID, Days: days, Since: since, Until: until, SkewMargin: skew,
	})
	if err != nil {
		return fmt.Errorf("compose project skills: %w", err)
	}
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	printProjectSkills(cmd.OutOrStdout(), out)
	return nil
}

// Label tables: one row per state, never a ladder (CLAUDE.md rule #5).
var (
	cliObservedLabels = map[string]string{
		"n/a":                    "-",
		"not_measurable":         "not measurable",
		"not_captured":           "not captured",
		"absent":                 "not present",
		"unknown":                "unknown",
		"home_unresolved":        "unknown (home not resolved)",
		"unreadable":             "unreadable",
		"observed_after_start":   "",
		"observed":               "",
		"changed_during_session": "",
	}
	cliHeadLabels = map[string]string{
		"n/a":                   "-",
		"not_in_project_git":    "not in project git",
		"git_unavailable":       "git history unavailable",
		"reflog_unavailable":    "unknown (no reflog)",
		"head_moved_near_start": "HEAD moved near start",
		"pending":               "pending",
		"commit_unavailable":    "commit gone",
		"absent_in_commit":      "not in that commit",
		"committed":             "",
	}
	cliInGitLabels = map[string]string{
		"committed":          "committed",
		"removed":            "removed",
		"not_committed":      "not in git",
		"not_in_project_git": "home directory",
		"unknown":            "unknown",
	}
)

// versionIndex maps skill key -> version id -> "#<ordinal> <id>".
func versionIndex(p dashboard.ProjectSkills) map[string]map[string]string {
	idx := map[string]map[string]string{}
	for _, s := range p.Skills {
		m := map[string]string{}
		for _, v := range s.Versions {
			m[v.ID] = fmt.Sprintf("#%d %s", v.Ordinal, v.ID)
		}
		idx[s.Key] = m
	}
	return idx
}

func versionText(idx map[string]map[string]string, key, id string) string {
	if id == "" {
		return ""
	}
	if l, ok := idx[key][id]; ok {
		return l
	}
	return id
}

func cliObserved(idx map[string]map[string]string, key string, state, version, source, reason string, changed []string) string {
	switch state {
	case "observed":
		return versionText(idx, key, version)
	case "observed_after_start":
		// Never "at start": the first snapshot came from a later re-fire.
		seen := versionText(idx, key, version)
		if seen == "" {
			seen = "not present"
		}
		return "not captured at start (seen at " + skillDash(source) + ": " + seen + ")"
	case "not_captured":
		if reason == "subagent" {
			return "not captured (sub-agent: see parent session)"
		}
	case "changed_during_session":
		parts := make([]string, len(changed))
		for i, c := range changed {
			if l, ok := idx[key][c]; ok {
				parts[i] = l
			} else if lbl, ok := cliObservedLabels[c]; ok && lbl != "" {
				parts[i] = lbl
			} else {
				parts[i] = c
			}
		}
		return "changed: " + strings.Join(parts, " -> ")
	}
	if l, ok := cliObservedLabels[state]; ok {
		return l
	}
	return state
}

func cliHead(idx map[string]map[string]string, key, state, version, reason string, candidates []string) string {
	switch state {
	case "committed":
		return versionText(idx, key, version)
	case "head_moved_near_start":
		if reason == "same_second" {
			return "HEAD moved several times in one second (" + strings.Join(candidates, ", ") + ")"
		}
		return cliHeadLabels[state] + " (" + strings.Join(candidates, ", ") + ")"
	}
	if l, ok := cliHeadLabels[state]; ok {
		return l
	}
	return state
}

func cliCurrent(s dashboard.ProjectSkills, i int) string {
	sk := s.Skills[i]
	txt := cliInGitLabels[sk.Current.InGit]
	if txt == "" {
		txt = sk.Current.InGit
	}
	if sk.Current.Worktree != "" {
		switch sk.Current.Worktree {
		case "modified", "deleted", "renamed_away", "unmerged":
			txt += ", uncommitted changes"
		case "added", "renamed":
			txt += " (staged, not committed)"
		default:
			txt += " (" + sk.Current.Worktree + ")"
		}
	}
	if sk.Current.CannotMatch != "" {
		txt += " [cannot match: " + sk.Current.CannotMatch + "]"
	}
	return txt
}

func printProjectSkills(w io.Writer, p dashboard.ProjectSkills) {
	idx := versionIndex(p)
	fmt.Fprintf(w, "Skills for %s (last %d days)\n", p.RootPath, p.WindowDays)
	if p.Capture.ObservedSince != "" {
		fmt.Fprintf(w, "  Observed (hook snapshots) since: %s\n", p.Capture.ObservedSince)
	} else {
		fmt.Fprintln(w, "  Observed: no skill snapshots yet - sessions before capture read \"not captured\", never a guessed version")
	}
	switch p.Capture.Git.State {
	case "ok":
		fmt.Fprintf(w, "  Git: HEAD reflog captured since %s\n", skillDash(p.Capture.Git.ReflogSince))
	case "partial":
		fmt.Fprintf(w, "  Git: partial - %s\n", p.Capture.Git.Error)
	default:
		fmt.Fprintln(w, "  Git: history not scanned yet (or not a git repository)")
	}
	if len(p.Capture.Git.ProbeUnknown) > 0 {
		fmt.Fprintf(w, "  Repository probes unknown: %s\n", strings.Join(p.Capture.Git.ProbeUnknown, ", "))
	}
	if p.Capture.Git.Shallow {
		fmt.Fprintln(w, "  Git: shallow clone - older history unavailable")
	}
	if len(p.Skills) == 0 {
		fmt.Fprintln(w, "\nNo skills found (.claude/skills/<name>/SKILL.md or ~/.claude/skills).")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "\nSKILL\tSCOPE\tGIT\tHEAD VERSION\tVERSIONS\tCOMMITS\tINVOCATIONS")
	for i, s := range p.Skills {
		inv := "not measurable"
		if s.Invocations.Measurable {
			inv = fmt.Sprintf("%d", s.Invocations.Count)
			if s.Invocations.Count == 0 {
				inv = "none captured"
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n", s.Name, s.Scope, cliCurrent(p, i),
			skillDash(versionText(idx, s.Key, s.Current.HeadVersion)), len(s.Versions), len(s.Commits), inv)
	}
	_ = tw.Flush()

	for _, s := range p.Skills {
		if len(s.Commits) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s: commits\n", s.Name)
		for _, c := range s.Commits {
			flags := ""
			if !c.SkillMDChanged {
				flags += " [SKILL.md unchanged]"
			}
			if !c.Reachable {
				flags += " [unreachable]"
			}
			fmt.Fprintf(w, "  %s %s %-1s %-12s %s%s\n", skillShortID(c.SHA), c.CommittedAt, c.Status,
				versionText(idx, s.Key, c.Version), c.Subject, flags)
		}
	}

	if len(p.Spans) > 0 {
		fmt.Fprintln(w, "\nSessions (runs of consecutive sessions with the same state; AVAILABLE = hook snapshot at start, HEAD = committed content at start):")
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "SKILL\tFROM\tTO\tSESSIONS\tAVAILABLE\tHEAD")
		for _, sp := range p.Spans {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", skillName(p, sp.SkillKey), sp.From, sp.To, sp.Sessions,
				cliObserved(idx, sp.SkillKey, sp.Observed.State, sp.Observed.Version, sp.Observed.Source, sp.Observed.Reason, sp.Observed.Changed),
				cliHead(idx, sp.SkillKey, sp.Head.State, sp.Head.Version, sp.Head.Reason, sp.Head.Candidates))
		}
		_ = tw.Flush()
	}
	if len(p.Cells) > 0 {
		fmt.Fprintln(w, "\nNotable sessions:")
		for _, c := range p.Cells {
			var invs []string
			for _, iv := range c.Invoked {
				v := versionText(idx, c.SkillKey, iv.Version)
				if iv.State != "version" {
					v = strings.ReplaceAll(iv.State, "_", " ")
				}
				invs = append(invs, iv.At+" "+v)
			}
			line := fmt.Sprintf("  %s %s  available: %s  HEAD: %s", skillShortID(c.SessionID), skillName(p, c.SkillKey),
				cliObserved(idx, c.SkillKey, c.Observed.State, c.Observed.Version, c.Observed.Source, c.Observed.Reason, c.Observed.Changed),
				cliHead(idx, c.SkillKey, c.Head.State, c.Head.Version, c.Head.Reason, c.Head.Candidates))
			if len(invs) > 0 {
				line += "  invoked: " + strings.Join(invs, "; ")
			}
			fmt.Fprintln(w, line)
		}
	}
	if len(p.UnmatchedInvocations) > 0 {
		fmt.Fprintln(w, "\nInvoked but not a project or home skill (e.g. plugin skills):")
		for _, u := range p.UnmatchedInvocations {
			fmt.Fprintf(w, "  %s  %s x%d\n", u.Tool, u.Name, u.Count)
		}
	}
	if len(p.AmbiguousInvocations) > 0 {
		fmt.Fprintln(w, "\nName matches more than one skill; not attributed:")
		for _, a := range p.AmbiguousInvocations {
			fmt.Fprintf(w, "  %s  %s x%d (%s)\n", a.Tool, a.Name, a.Count, strings.Join(a.Candidates, ", "))
		}
	}
	if p.Truncated {
		fmt.Fprintln(w, "\nNote: capped - only the newest sessions / first notable cells are shown.")
	}
}

func skillName(p dashboard.ProjectSkills, key string) string {
	for _, s := range p.Skills {
		if s.Key == key {
			return s.Name
		}
	}
	return key
}

func skillShortID(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func skillDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
