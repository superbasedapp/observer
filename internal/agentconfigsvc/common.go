package agentconfigsvc

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// The common form: one canonical value fanned out to every installed tool,
// all files under one plan. Without a project it is the developer's L1
// all-adapters value in each tool's user-scope file; with a project it is a
// project-level common value in each tool's project file of that clone
// (T-429, D-106: all adapters -> per adapter -> project), shown at the
// project rank.

// commonTools are the tools the common view reads (catalogued, with a
// local surface).
func commonTools() []string {
	var out []string
	for _, c := range agentconfig.Coverage() {
		if c.Status == agentconfig.CoverageGenerated || c.Status == agentconfig.CoverageAuthored {
			out = append(out, c.Tool)
		}
	}
	return out
}

// CommonView reads every tool and projects it onto the common vocabulary.
func (s *Service) CommonView(ctx context.Context, project string) ([]agentconfig.CommonKeyView, error) {
	views := map[string]agentconfig.ToolView{}
	for _, t := range commonTools() {
		v, err := s.Inspect(ctx, t, project)
		if err != nil {
			return nil, err
		}
		views[t] = v
	}
	return agentconfig.CommonView(views), nil
}

// CommonRequest is a write of one common key: L1 (every tool's user file)
// or, with Project, the project rank (every tool's project file there).
type CommonRequest struct {
	Key   agentconfig.CommonKey `json:"key"`
	Value any                   `json:"value,omitempty"`
	// Project is a project root Observer knows (the dashboard validates it);
	// empty means the user-scope files.
	Project string `json:"project,omitempty"`
	// Placement is local_only (the default: each tool's personal project
	// file, git-excluded when created) or shared (the file a commit
	// carries). Ignored without a project.
	Placement string `json:"placement,omitempty"`
	// Clear deletes the key's native settings instead of setting them.
	Clear       bool   `json:"clear,omitempty"`
	PreviewEtag string `json:"preview_etag,omitempty"`
	Confirm     bool   `json:"confirm,omitempty"`
}

// CommonTarget is one tool's part of an L1 write, with its file preview.
type CommonTarget struct {
	agentconfig.FanOutTarget
	Path    string   `json:"path,omitempty"`
	Preview *Preview `json:"preview,omitempty"`
}

// CommonPreview is a planned L1 write across tools.
type CommonPreview struct {
	Key          agentconfig.CommonKey `json:"key"`
	OK           bool                  `json:"ok"`
	NeedsConfirm bool                  `json:"needs_confirm"`
	// Danger: the canonical value is in the key's dangerous set.
	Danger      bool           `json:"danger,omitempty"`
	Writes      int            `json:"writes"`
	Targets     []CommonTarget `json:"targets"`
	PreviewEtag string         `json:"preview_etag"`
}

// Common placements of a project-level write.
const (
	CommonPlacementLocalOnly = "local_only"
	CommonPlacementShared    = "shared"
)

// commonScope resolves a request's fan-out scope.
func commonScope(req CommonRequest) (agentconfig.FanOutScope, error) {
	if req.Project == "" {
		return agentconfig.FanOutScope{}, nil
	}
	switch req.Placement {
	case "", CommonPlacementLocalOnly:
		return agentconfig.FanOutScope{Project: true, LocalOnly: true}, nil
	case CommonPlacementShared:
		return agentconfig.FanOutScope{Project: true}, nil
	}
	return agentconfig.FanOutScope{}, fmt.Errorf("%w: placement must be local_only or shared", ErrBadTarget)
}

// commonLayer is the developer layer a common write authors.
func commonLayer(req CommonRequest) agentconfig.ValueLayer {
	if req.Project != "" {
		return agentconfig.ValueL3
	}
	return agentconfig.ValueL1
}

// planCommon builds every target's file plan.
func (s *Service) planCommon(ctx context.Context, req CommonRequest) (CommonPreview, error) {
	scope, err := commonScope(req)
	if err != nil {
		return CommonPreview{}, err
	}
	targets, err := agentconfig.PlanFanOutAt(req.Key, req.Value, req.Clear, s.Installed, scope)
	if err != nil {
		return CommonPreview{}, err
	}
	cp := CommonPreview{Key: req.Key, OK: true, Danger: !req.Clear && agentconfig.CommonDanger(req.Key, req.Value)}
	cp.NeedsConfirm = cp.Danger
	var etags []string
	for _, t := range targets {
		ct := CommonTarget{FanOutTarget: t}
		if t.Status == agentconfig.FanOutWrite {
			p, err := s.plan(ctx, SaveRequest{Target: Target{Tool: t.Tool, FileID: t.FileID, Project: req.Project}, Edits: t.Edits})
			if err != nil {
				ct.Status, ct.Reason = agentconfig.FanOutNotWritable, err.Error()
			} else {
				ct.Path, ct.Preview = p.Path, &p
				if !p.NoChange {
					cp.Writes++
				}
				if !p.OK {
					cp.OK = false
				}
				if p.NeedsConfirm {
					cp.NeedsConfirm = true
				}
				etags = append(etags, t.Tool+"="+p.PreviewEtag)
			}
		}
		cp.Targets = append(cp.Targets, ct)
	}
	sort.Strings(etags)
	cp.PreviewEtag = fingerprint(append([]string{string(req.Key), req.Project, req.Placement}, etags...)...)
	return cp, nil
}

// CommonPreview plans an L1 write without writing.
func (s *Service) CommonPreview(ctx context.Context, req CommonRequest) (CommonPreview, error) {
	return s.planCommon(ctx, req)
}

// CommonSaveError carries the preview a refused L1 write was judged on.
type CommonSaveError struct {
	Err     error
	Preview CommonPreview
}

func (e *CommonSaveError) Error() string { return e.Err.Error() }
func (e *CommonSaveError) Unwrap() error { return e.Err }

// CommonOutcome is a completed L1 write.
type CommonOutcome struct {
	Saved   bool          `json:"saved"`
	Written []SaveOutcome `json:"written"`
}

// CommonSave writes an L1 value to every target file. Every file is
// locked (sorted order), re-planned and checked against the preview etag
// before the first write; a failure after some writes restores the files
// already written, so the fan-out lands whole or not at all.
func (s *Service) CommonSave(ctx context.Context, req CommonRequest) (CommonOutcome, error) {
	first, err := s.planCommon(ctx, req)
	if err != nil {
		return CommonOutcome{}, err
	}
	var paths []string
	seen := map[string]bool{}
	for _, t := range first.Targets {
		if t.Preview != nil && !seen[t.Path] {
			seen[t.Path] = true
			paths = append(paths, t.Path)
		}
	}
	sort.Strings(paths)
	var unlocks []func()
	defer func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}()
	for _, p := range paths {
		u, err := s.lock(p)
		if err != nil {
			return CommonOutcome{}, err
		}
		unlocks = append(unlocks, u)
	}
	cp, err := s.planCommon(ctx, req)
	if err != nil {
		return CommonOutcome{}, err
	}
	switch {
	case !cp.OK:
		return CommonOutcome{}, &CommonSaveError{Err: ErrBlocked, Preview: cp}
	case req.PreviewEtag == "" || req.PreviewEtag != cp.PreviewEtag:
		return CommonOutcome{}, &CommonSaveError{Err: ErrStale, Preview: cp}
	case cp.NeedsConfirm && !req.Confirm:
		return CommonOutcome{}, &CommonSaveError{Err: ErrConfirm, Preview: cp}
	}
	commit := s.commitFile
	if s.commitHook != nil {
		commit = s.commitHook
	}
	type committed struct {
		t CommonTarget
		w written
	}
	var done []committed
	for _, t := range cp.Targets {
		if t.Preview == nil || t.Preview.NoChange {
			continue
		}
		w, err := commit(pinTarget(t.Path), *t.Preview)
		if err != nil {
			ws := make([]written, 0, len(done))
			for _, d := range done {
				ws = append(ws, d.w)
			}
			return CommonOutcome{}, fmt.Errorf("agentconfigsvc: %s: %w (%s)", t.Tool, err, s.rollbackAll(ws))
		}
		done = append(done, committed{t: t, w: w})
	}
	// History and layer rows are written only once the WHOLE fan-out is on
	// disk (review M3-08): a fan-out that rolled back records nothing, so
	// history never lists a save that is not on disk.
	var out CommonOutcome
	for _, d := range done {
		row, _ := fileRow(d.t.FileID)
		so := SaveOutcome{
			Saved: true, FileID: d.t.FileID, Path: d.t.Path, BackupPath: d.w.backup, Created: d.w.created,
			Etag: d.t.Preview.AfterEtag, Changes: d.t.Preview.Changes, Findings: d.t.Preview.Findings,
		}
		if d.t.Preview.AddExclude && req.Project != "" {
			so.Excluded = s.addGitExclude(req.Project, d.t.Path)
		}
		s.record(ctx, row, d.t.Path, req.Project, *d.t.Preview, d.w, string(commonLayer(req)), string(req.Key), "common")
		out.Written = append(out.Written, so)
	}
	out.Saved = len(out.Written) > 0
	return out, nil
}

// rollbackAll restores the files a failed fan-out already wrote, newest
// first, and says honestly what happened: every file restored, or which ones
// could not be (their backups are kept beside them).
func (s *Service) rollbackAll(done []written) string {
	var failed []string
	for i := len(done) - 1; i >= 0; i-- {
		if err := s.rollback(done[i]); err != nil {
			failed = append(failed, done[i].path)
		}
	}
	if len(failed) == 0 {
		return "every file written before it was restored"
	}
	sort.Strings(failed)
	return "could not restore " + strings.Join(failed, ", ") + "; the backup written beside each holds its previous content"
}
