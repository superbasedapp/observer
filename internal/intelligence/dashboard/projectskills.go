package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guidance"
	"github.com/marmutapp/superbased-observer/internal/skillhistory"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// projectskills.go is the ONE composition seam for the Projects-page Skills
// tab (S10-SKILLS; docs/projects-page.md "Skills: versions across commits
// and sessions"): GET /api/project/{id}/skills (handleProjectSkills) and
// `observer project --skills` (cmd/observer/project.go) both call
// ComposeProjectSkills, so the tab and the CLI can never disagree. It is a
// SEPARATE composition from ComposeProjectDetail on purpose: the detail
// payload stays byte-identical (pinned by
// TestSkillHistoryLeavesExistingEndpointsByteIdentical).
//
// The read is SQL + the pure internal/skillhistory derivation: no git and
// no filesystem walk on a page load.

// skillSnapshotEmitters is the capability table for the Observed column:
// which tools' hooks snapshot SKILL.md content at session start and skill
// invocation (cmd/observer/hook_skillsnap.go). A tool absent here renders
// "not measurable", never "not captured" - the zero value is the honest
// one. Same shape and rule as guidanceToolsMeasurable (guidance.go).
var skillSnapshotEmitters = map[string]bool{
	"claude-code": true,
}

// ProjectSkillsInput is what ComposeProjectSkills needs beyond the store.
type ProjectSkillsInput struct {
	ProjectID  int64
	Days       int
	Since      time.Time
	Until      time.Time
	SkewMargin time.Duration
}

// ProjectSkills is the exported alias for the /api/project/{id}/skills wire
// shape, so the CLI can range over it and marshal it unchanged.
type ProjectSkills = apiProjectSkills

type apiProjectSkills struct {
	ProjectID            int64                     `json:"project_id"`
	RootPath             string                    `json:"root_path"`
	WindowDays           int                       `json:"window_days"`
	Truncated            bool                      `json:"truncated"`
	Capture              apiSkillCapture           `json:"capture"`
	Skills               []apiSkill                `json:"skills"`
	Sessions             []apiSkillSession         `json:"sessions"`
	Spans                []apiSkillSpan            `json:"spans"`
	Cells                []apiSkillCell            `json:"cells"`
	UnmatchedInvocations []apiSkillNamedCount      `json:"unmatched_invocations"`
	AmbiguousInvocations []apiSkillAmbiguousInvoke `json:"ambiguous_invocations"`
}

type apiSkillCapture struct {
	// ObservedSince is the first hook snapshot among the loaded sessions
	// ("" = no snapshot yet: every Observed cell reads "not captured").
	ObservedSince string `json:"observed_since"`
	// SnapshotCapable / InvocationsMeasurable are keyed by the tools that
	// have a session in the window.
	SnapshotCapable       map[string]bool `json:"snapshot_capable"`
	InvocationsMeasurable map[string]bool `json:"invocations_measurable"`
	Git                   apiSkillGit     `json:"git"`
}

type apiSkillGit struct {
	// State: "not_scanned" (not a repository, git missing, or the step has
	// not reached this project yet), "ok", or "partial" (the last step hit
	// an error; captured history still renders, Error says what).
	State        string `json:"state"`
	ScannedAt    string `json:"scanned_at"`
	ReflogSince  string `json:"reflog_since"`
	Shallow      bool   `json:"shallow"`
	IgnoreCase   bool   `json:"ignore_case"`
	ObjectFormat string `json:"object_format"`
	Error        string `json:"error"`
	// ProbeUnknown names repository probes whose answer is unknown (the
	// probe failed with no earlier answer): shallow/ignore_case/
	// object_format above then read as their zero value, not a fact.
	ProbeUnknown []string `json:"probe_unknown"`
}

type apiSkill struct {
	Key         string                `json:"key"`
	Scope       string                `json:"scope"`
	Dir         string                `json:"dir"`
	Name        string                `json:"name"`
	Names       []string              `json:"names"`
	Present     bool                  `json:"present"`
	Tools       []string              `json:"tools"`
	Ambiguous   bool                  `json:"ambiguous"`
	Current     apiSkillCurrent       `json:"current"`
	MovedFrom   *apiSkillMove         `json:"moved_from"`
	Versions    []apiSkillVersion     `json:"versions"`
	Commits     []apiSkillCommit      `json:"commits"`
	Invocations apiSkillInvocationSum `json:"invocations"`
}

type apiSkillCurrent struct {
	InGit       string `json:"in_git"`
	Worktree    string `json:"worktree"`
	HeadVersion string `json:"head_version"`
	CannotMatch string `json:"cannot_match"`
}

type apiSkillMove struct {
	FromDir string `json:"from_dir"`
	SHA     string `json:"sha"`
}

type apiSkillVersion struct {
	ID                string          `json:"id"`
	BlobOID           string          `json:"blob_oid"`
	Ordinal           int             `json:"ordinal"`
	FirstSeen         string          `json:"first_seen"`
	IntroducedBy      *apiSkillCommit `json:"introduced_by"`
	ReintroducedIn    []string        `json:"reintroduced_in"`
	InCommits         bool            `json:"in_commits"`
	ObservedFirst     string          `json:"observed_first"`
	ObservedLast      string          `json:"observed_last"`
	SessionsAvailable int             `json:"sessions_available"`
	Invocations       int             `json:"invocations"`
}

type apiSkillCommit struct {
	SHA            string `json:"sha"`
	CommittedAt    string `json:"committed_at"`
	Subject        string `json:"subject"`
	Reachable      bool   `json:"reachable"`
	IsMerge        bool   `json:"is_merge"`
	Status         string `json:"status"`
	SkillMDChanged bool   `json:"skill_md_changed"`
	Files          int    `json:"files"`
	Version        string `json:"version"`
}

type apiSkillInvocationSum struct {
	Measurable bool   `json:"measurable"`
	Count      int    `json:"count"`
	Last       string `json:"last"`
}

type apiSkillSession struct {
	ID             string `json:"id"`
	Tool           string `json:"tool"`
	StartedAt      string `json:"started_at"`
	Relation       string `json:"relation"`
	ParentID       string `json:"parent_id"`
	ParentInWindow bool   `json:"parent_in_window"`
}

type apiSkillObserved struct {
	State       string   `json:"state"`
	Version     string   `json:"version"`
	Changed     []string `json:"changed"`
	LineEndings bool     `json:"line_endings"`
	// Source is the first snapshot's SessionStart source when State is
	// "observed_after_start" (resume, compact).
	Source string `json:"source"`
	// Reason qualifies a state ("subagent" on not_captured).
	Reason string `json:"reason"`
}

type apiSkillHead struct {
	State      string   `json:"state"`
	Version    string   `json:"version"`
	SHA        string   `json:"sha"`
	Candidates []string `json:"candidates"`
	Reason     string   `json:"reason"`
}

type apiSkillInvoked struct {
	At      string `json:"at"`
	State   string `json:"state"`
	Version string `json:"version"`
}

type apiSkillSpan struct {
	SkillKey    string           `json:"skill_key"`
	FromSession string           `json:"from_session"`
	ToSession   string           `json:"to_session"`
	From        string           `json:"from"`
	To          string           `json:"to"`
	Sessions    int              `json:"sessions"`
	Observed    apiSkillObserved `json:"observed"`
	Head        apiSkillHead     `json:"head"`
}

type apiSkillCell struct {
	SkillKey  string            `json:"skill_key"`
	SessionID string            `json:"session_id"`
	Observed  apiSkillObserved  `json:"observed"`
	Head      apiSkillHead      `json:"head"`
	Invoked   []apiSkillInvoked `json:"invoked"`
}

type apiSkillNamedCount struct {
	Tool  string `json:"tool"`
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type apiSkillAmbiguousInvoke struct {
	Tool       string   `json:"tool"`
	Name       string   `json:"name"`
	Count      int      `json:"count"`
	Candidates []string `json:"candidates"`
}

// ComposeProjectSkills loads a project's skills history and resolves it
// through internal/skillhistory. The caller resolves the project first
// (the handler's requireProject, the CLI's resolveProjectArg); an unknown
// id is an error here.
func ComposeProjectSkills(ctx context.Context, st *store.Store, in ProjectSkillsInput) (ProjectSkills, error) {
	meta, ok, err := st.LoadProjectMeta(ctx, in.ProjectID)
	if err != nil {
		return ProjectSkills{}, fmt.Errorf("dashboard.ComposeProjectSkills: load project meta: %w", err)
	}
	if !ok {
		return ProjectSkills{}, fmt.Errorf("dashboard.ComposeProjectSkills: project %d not found", in.ProjectID)
	}
	rules := guidance.Rules()
	hin, err := st.LoadSkillHistoryInput(ctx, in.ProjectID, meta.RootPath, in.Since, in.Until, skillhistory.Pathspecs(rules))
	if err != nil {
		return ProjectSkills{}, fmt.Errorf("dashboard.ComposeProjectSkills: load: %w", err)
	}
	hin.Rules = rules
	hin.SnapshotEmitters = skillSnapshotEmitters
	hin.InvocationMeasurable = guidanceToolsMeasurable
	hin.SkewMargin = in.SkewMargin
	res := skillhistory.Build(hin)

	out := apiProjectSkills{
		ProjectID: in.ProjectID, RootPath: meta.RootPath, WindowDays: in.Days, Truncated: res.Truncated,
		Capture: apiSkillCapture{
			ObservedSince:         fmtProjectTime(res.ObservedSince),
			SnapshotCapable:       map[string]bool{},
			InvocationsMeasurable: map[string]bool{},
			Git:                   skillGitOut(hin.Git),
		},
		Skills:               make([]apiSkill, 0, len(res.Skills)),
		Sessions:             make([]apiSkillSession, 0, len(res.Sessions)),
		Spans:                make([]apiSkillSpan, 0, len(res.Spans)),
		Cells:                make([]apiSkillCell, 0, len(res.Cells)),
		UnmatchedInvocations: make([]apiSkillNamedCount, 0, len(res.Unmatched)),
		AmbiguousInvocations: make([]apiSkillAmbiguousInvoke, 0, len(res.Ambiguous)),
	}
	for tool, capable := range res.SnapshotCapabilities {
		out.Capture.SnapshotCapable[tool] = capable
		out.Capture.InvocationsMeasurable[tool] = guidanceToolsMeasurable[tool]
	}
	for _, s := range res.Skills {
		out.Skills = append(out.Skills, skillOut(s))
	}
	for _, s := range res.Sessions {
		out.Sessions = append(out.Sessions, apiSkillSession{
			ID: s.ID, Tool: s.Tool, StartedAt: fmtProjectTime(s.StartedAt), Relation: s.Relation,
			ParentID: s.ParentID, ParentInWindow: s.ParentInWindow,
		})
	}
	for _, sp := range res.Spans {
		out.Spans = append(out.Spans, apiSkillSpan{
			SkillKey: sp.SkillKey, FromSession: sp.FromSession, ToSession: sp.ToSession,
			From: fmtProjectTime(sp.From), To: fmtProjectTime(sp.To), Sessions: sp.Sessions,
			Observed: observedOut(sp.Observed), Head: headOut(sp.Head),
		})
	}
	for _, c := range res.Cells {
		cell := apiSkillCell{
			SkillKey: c.SkillKey, SessionID: c.SessionID,
			Observed: observedOut(c.Observed), Head: headOut(c.Head), Invoked: []apiSkillInvoked{},
		}
		for _, inv := range c.Invoked {
			cell.Invoked = append(cell.Invoked, apiSkillInvoked{At: fmtProjectTime(inv.At), State: inv.State, Version: inv.Version})
		}
		out.Cells = append(out.Cells, cell)
	}
	for _, u := range res.Unmatched {
		out.UnmatchedInvocations = append(out.UnmatchedInvocations, apiSkillNamedCount{Tool: u.Tool, Name: u.Name, Count: u.Count})
	}
	for _, a := range res.Ambiguous {
		out.AmbiguousInvocations = append(out.AmbiguousInvocations, apiSkillAmbiguousInvoke{
			Tool: a.Tool, Name: a.Name, Count: a.Count, Candidates: nonNil(a.Candidates),
		})
	}
	return out, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func skillGitOut(g skillhistory.GitState) apiSkillGit {
	out := apiSkillGit{
		State: "not_scanned", ScannedAt: fmtProjectTime(g.LastScanAt), ReflogSince: fmtProjectTime(g.ReflogSince),
		Shallow: g.Shallow, IgnoreCase: g.IgnoreCase, ObjectFormat: g.ObjectFormat, Error: g.LastError,
		ProbeUnknown: nonNil(g.ProbeUnknown),
	}
	switch {
	case g.Scanned && g.LastError != "":
		out.State = "partial"
	case g.Scanned:
		out.State = "ok"
	}
	return out
}

func skillOut(s skillhistory.Skill) apiSkill {
	out := apiSkill{
		Key: s.Key, Scope: s.Scope, Dir: s.Dir, Name: s.Name, Names: nonNil(s.Names),
		Present: s.Present, Tools: nonNil(s.Tools), Ambiguous: s.Ambiguous,
		Current: apiSkillCurrent{
			InGit: s.Current.InGit, Worktree: s.Current.Worktree,
			HeadVersion: s.Current.HeadVersion, CannotMatch: s.Current.CannotMatch,
		},
		Versions: make([]apiSkillVersion, 0, len(s.Versions)),
		Commits:  make([]apiSkillCommit, 0, len(s.Commits)),
		Invocations: apiSkillInvocationSum{
			Measurable: s.Invocations.Measurable, Count: s.Invocations.Count, Last: fmtProjectTime(s.Invocations.Last),
		},
	}
	if s.MovedFrom != nil {
		out.MovedFrom = &apiSkillMove{FromDir: s.MovedFrom.FromDir, SHA: s.MovedFrom.SHA}
	}
	for _, v := range s.Versions {
		av := apiSkillVersion{
			ID: v.ID, BlobOID: v.BlobOID, Ordinal: v.Ordinal, FirstSeen: fmtProjectTime(v.FirstSeen),
			ReintroducedIn: nonNil(v.ReintroducedIn), InCommits: v.InCommits,
			ObservedFirst: fmtProjectTime(v.ObservedFirst), ObservedLast: fmtProjectTime(v.ObservedLast),
			SessionsAvailable: v.SessionsAvailable, Invocations: v.Invocations,
		}
		if v.IntroducedBy != nil {
			av.IntroducedBy = &apiSkillCommit{
				SHA: v.IntroducedBy.SHA, CommittedAt: fmtProjectTime(v.IntroducedBy.CommittedAt),
				Subject: v.IntroducedBy.Subject, Reachable: v.IntroducedBy.Reachable,
			}
		}
		out.Versions = append(out.Versions, av)
	}
	for _, c := range s.Commits {
		out.Commits = append(out.Commits, apiSkillCommit{
			SHA: c.SHA, CommittedAt: fmtProjectTime(c.CommittedAt), Subject: c.Subject,
			Reachable: c.Reachable, IsMerge: c.IsMerge, Status: c.Status,
			SkillMDChanged: c.SkillMDChanged, Files: c.Files, Version: c.Version,
		})
	}
	return out
}

func observedOut(o skillhistory.ObservedCell) apiSkillObserved {
	return apiSkillObserved{State: o.State, Version: o.Version, Changed: nonNil(o.Changed), LineEndings: o.LineEndings, Source: o.Source, Reason: o.Reason}
}

func headOut(h skillhistory.HeadCell) apiSkillHead {
	return apiSkillHead{State: h.State, Version: h.Version, SHA: h.SHA, Candidates: nonNil(h.Candidates), Reason: h.Reason}
}

// skillSkewMargin resolves [projects].skill_history_skew_seconds (0 ->
// the derivation's default).
func (s *Server) skillSkewMargin() time.Duration {
	if s.opts.Projects.SkillHistorySkewSeconds <= 0 {
		return 0
	}
	return time.Duration(s.opts.Projects.SkillHistorySkewSeconds) * time.Second
}

// handleProjectSkills serves GET /api/project/{id}/skills?days=N - the
// Skills tab (S10-SKILLS). Same project resolution and window as the
// sibling tab endpoints.
func (s *Server) handleProjectSkills(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, days := projectDetailWindow(r)
	out, err := ComposeProjectSkills(ctx, st, ProjectSkillsInput{
		ProjectID: projectID, Days: days, Since: since, Until: until, SkewMargin: s.skillSkewMargin(),
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, out)
}
