//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// security_assess_fix.go is the fix route of the Security assessments module
// (docs/plans/security-assessments-depth-plan-2026-11-14.md, W6b; decision D24):
// one checked threat or pen test finding becomes the task of a coding agent in a
// dashboard terminal.
//
//	GET  /api/security/assessments/fix?run=&item=  the task the agent would get,
//	                                              built from the stored, checked
//	                                              copy; mints the confirm token
//	POST /api/security/assessments/fix            starts it through
//	                                              startFreshTerminal
//
// It is a write-capable agent in the live working tree, so the POST is a row of
// agentLaunchRoutes (held for a human when an agent asks, R-168 asks about it).
// The prompt is built by secassess.BuildFixPrompt from Observer's own tables,
// the ids and the places Observer found: nothing the assessment's agent wrote as
// prose is in it, and a place is named only when its file name passes
// secassess.FixPathRefusal.
//
// The launch starts the prompt the caller read, and only that: it requires the
// digest of the task (prompt_sha256) and refuses a task that now builds to
// another (409 plan_changed). A held launch pins that rule: the hold computes
// the task the card shows, puts its digest into the body the confirm replays
// (replacing whatever the agent sent), and the card shows the prompt and the
// digest under labels no body member can wear (securityAssessFixHeld). The New
// terminal dialog's own sandbox and workspace controls apply, as for the
// Findings tab's fix; a launch without sandbox says "unsandboxed" on the card.

// Machine codes of a refused fix.
const (
	// codeUnknownItem: the stored model holds no such threat or finding.
	codeUnknownItem = "unknown_item"
	// codeNoLocation: the item cites no place Observer found and may print, so
	// the task would have nothing to point at.
	codeNoLocation = "no_location"
	// codeFixTooLarge: not even one place fits the task's size limit.
	codeFixTooLarge = "fix_too_large"
	// codeDigestRequired: the launch names no digest of the task the developer
	// read.
	codeDigestRequired = "prompt_digest_required"
)

type securityAssessFixProjectJS struct {
	Name     string `json:"name"`
	RootPath string `json:"root_path"`
	OnDisk   bool   `json:"on_disk"`
}

// securityAssessFixPlanJS is the GET answer: the task and what the dialog shows
// beside it.
type securityAssessFixPlanJS struct {
	ConfirmToken string                     `json:"confirm_token"`
	Run          string                     `json:"run"`
	Item         string                     `json:"item"`
	Project      securityAssessFixProjectJS `json:"project"`
	secassess.FixTask
	PromptSHA256 string            `json:"prompt_sha256"`
	Seeds        map[string]string `json:"seeds"`
}

// securityAssessFixRequest is the POST body: the item, the digest of the prompt
// the developer read, and the New terminal dialog's own launch fields
// (project_root excluded: it is the run's project).
type securityAssessFixRequest struct {
	Run  string `json:"run"`
	Item string `json:"item"`
	// PromptSHA256 is the digest of the prompt the developer read, required: a
	// launch that rebuilds a different prompt is refused (plan_changed), and a
	// launch that names none is refused (prompt_digest_required).
	PromptSHA256 string `json:"prompt_sha256"`
	terminalLaunchRequest
}

type securityAssessFixLaunchJS struct {
	terminalLaunchResponse
	Seeded bool   `json:"seeded"`
	Prompt string `json:"prompt,omitempty"`
	Run    string `json:"run"`
	Item   string `json:"item"`
}

// securityAssessFixRefusal is a refused fix, as the route answers it. err is
// set instead of code for a failure that is not the developer's to fix.
type securityAssessFixRefusal struct {
	status int
	code   string
	msg    string
	err    error
}

// securityAssessFixResolved is a fix task built from a run's stored copy.
type securityAssessFixResolved struct {
	run  secassesssvc.Run
	root string
	task secassess.FixTask
}

// securityAssessFixRefusals are the refusals the resolution can make, one row
// each, in the order the checks run.
var securityAssessFixRefusals = struct {
	unknownRun, projectGone, notEnded, noModel, unknownItem, noLocation, tooLarge, digestRequired securityAssessFixRefusal
}{
	unknownRun:  securityAssessFixRefusal{status: http.StatusNotFound, msg: "unknown run"},
	projectGone: securityAssessFixRefusal{status: http.StatusConflict, code: codeProjectGone, msg: "the project's folder is no longer on this machine"},
	notEnded: securityAssessFixRefusal{
		status: http.StatusConflict, code: codeRunStillRunning,
		msg: "the run has not ended, and a fix would change files the run's git check is watching; wait for it to end, or stop it, then try again",
	},
	noModel: securityAssessFixRefusal{status: http.StatusNotFound, code: "no_stored_model", msg: "no stored model for this run"},
	unknownItem: securityAssessFixRefusal{
		status: http.StatusNotFound, code: codeUnknownItem,
		msg: "the stored model holds no such threat or finding",
	},
	noLocation: securityAssessFixRefusal{
		status: http.StatusConflict, code: codeNoLocation,
		msg: "this item cites no place that Observer found in the project and can name in a task, so there is nothing to point a fix at",
	},
	tooLarge: securityAssessFixRefusal{
		status: http.StatusConflict, code: codeFixTooLarge,
		msg: "this item's task does not fit the size limit for a task, so it cannot be started from here",
	},
	digestRequired: securityAssessFixRefusal{
		status: http.StatusBadRequest, code: codeDigestRequired,
		msg: "send prompt_sha256, the digest of the task you read (read it with GET first), so that what starts is what you read",
	},
}

// write answers the refusal through w.
func (f securityAssessFixRefusal) write(s *Server, w http.ResponseWriter) {
	switch {
	case f.err != nil:
		s.writeSecurityAssessRunErr(w, f.err)
	case f.code == "":
		http.Error(w, f.msg, f.status)
	default:
		writeJSONStatus(w, f.status, map[string]string{"error": f.msg, "code": f.code})
	}
}

// securityAssessFixStaleNote is Observer's sentence when the agent's model file
// changed after the check.
const securityAssessFixStaleNote = "The agent's model file changed after this check. The task is built from the checked copy, which may not match the file now."

// securityAssessFixResolve builds the fix task of one item of a run's stored,
// checked model. It reads; it writes nothing.
func (s *Server) securityAssessFixResolve(ctx context.Context, runID, item string) (securityAssessFixResolved, *securityAssessFixRefusal) {
	refusals := securityAssessFixRefusals
	run, root, found, err := s.securityAssessRunRoot(ctx, runID)
	switch {
	case err != nil:
		return securityAssessFixResolved{}, &securityAssessFixRefusal{err: err}
	case !found:
		return securityAssessFixResolved{}, &refusals.unknownRun
	case !securityFixOnDisk(root):
		// Not in the project index, or indexed and gone from the disk.
		return securityAssessFixResolved{}, &refusals.projectGone
	case run.EndedAt.IsZero():
		return securityAssessFixResolved{}, &refusals.notEnded
	}
	rec, ok := secassesssvc.ReadModel(secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Side(), run.ID)
	if !ok {
		return securityAssessFixResolved{}, &refusals.noModel
	}
	rep, driftErr := secassesssvc.StampsDriftReport(root, rec.Files, securityAssessRefBudget(s.securityAssessConfig().Security.Assessments))
	task, err := secassess.BuildFixPrompt(secassess.FixInput{
		RunID: run.ID, Kind: secassess.ID(run.Kind), Project: run.ProjectName,
		TM: rec.Result.TM, PT: rec.Result.PT, Item: item,
		Drift: rep.Changed, DriftUnread: driftErr != nil || len(rep.Unread) > 0,
	})
	switch {
	case errors.Is(err, secassess.ErrFixNoLocation):
		return securityAssessFixResolved{}, &refusals.noLocation
	case errors.Is(err, secassess.ErrFixUnknownItem):
		return securityAssessFixResolved{}, &refusals.unknownItem
	case errors.Is(err, secassess.ErrFixNoModel):
		// A stored copy that kept only its report (truncated, or a refused file).
		return securityAssessFixResolved{}, &refusals.noModel
	case errors.Is(err, secassess.ErrFixTooLarge):
		return securityAssessFixResolved{}, &refusals.tooLarge
	case err != nil:
		return securityAssessFixResolved{}, &securityAssessFixRefusal{status: http.StatusInternalServerError, msg: err.Error()}
	}
	if secassesssvc.Describe(root, run).ModelStale {
		task.Notes = append([]string{securityAssessFixStaleNote}, task.Notes...)
	}
	return securityAssessFixResolved{run: run, root: root, task: task}, nil
}

// handleSecurityAssessFix serves GET and POST /api/security/assessments/fix.
func (s *Server) handleSecurityAssessFix(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.securityAssessFixPlan(w, r)
	case http.MethodPost:
		s.securityAssessFixLaunch(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// securityAssessFixPlan answers the GET: the task and its digest.
func (s *Server) securityAssessFixPlan(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res, refusal := s.securityAssessFixResolve(r.Context(), q.Get("run"), q.Get("item"))
	if refusal != nil {
		refusal.write(s, w)
		return
	}
	if res.task.Places == nil {
		res.task.Places = []secassess.FixPlace{}
	}
	writeJSON(w, securityAssessFixPlanJS{
		ConfirmToken: setConfirmCookie(w, r), Run: res.run.ID, Item: q.Get("item"),
		Project:      securityAssessFixProjectJS{Name: res.run.ProjectName, RootPath: res.root, OnDisk: securityFixOnDisk(res.root)},
		FixTask:      res.task,
		PromptSHA256: secassess.PromptSHA256(res.task.Prompt),
		Seeds:        securityFixSeeds(),
	})
}

// securityAssessFixLaunch answers the POST: it rebuilds the task, checks the
// digest the developer read and starts the terminal.
func (s *Server) securityAssessFixLaunch(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "launch unavailable - this dashboard runs without the embedded-terminal launcher (run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	var body securityAssessFixRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityAssessBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	// A fix task runs an agent in a terminal: never a GUI app, a plain shell or
	// a client-chosen folder.
	if k := strings.TrimSpace(body.Kind); k != "" && integration.LaunchKind(k) != integration.LaunchKindTerminal {
		http.Error(w, "a fix task starts a terminal agent", http.StatusBadRequest)
		return
	}
	if _, ok := launchSubcommand(body.Tool); !ok {
		http.Error(w, "tool "+body.Tool+" is not launchable in the embedded terminal", http.StatusBadRequest)
		return
	}
	if s.opts.TerminalFeatureGate != nil {
		if allowed, reason := s.opts.TerminalFeatureGate(body.Sandbox); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	res, refusal := s.securityAssessFixResolve(r.Context(), body.Run, body.Item)
	if refusal != nil {
		refusal.write(s, w)
		return
	}
	// The developer launches the prompt they read: with no digest nothing starts,
	// and when the digest differs from the task as built now nothing starts and
	// the new prompt is handed back.
	switch want := strings.TrimSpace(body.PromptSHA256); {
	case want == "":
		refusals := securityAssessFixRefusals
		refusals.digestRequired.write(s, w)
		return
	case want != secassess.PromptSHA256(res.task.Prompt):
		writePlanChanged(w, res.task.Prompt)
		return
	}
	seeded := integration.TaskSeedFor(body.Tool).Seeds()
	arg := ""
	if seeded {
		arg = res.task.Prompt
	}
	launch := body.terminalLaunchRequest
	launch.Kind, launch.ProjectRoot = "", res.root
	resp, ok := s.startFreshTerminal(w, r, launch, arg)
	if !ok {
		return
	}
	out := securityAssessFixLaunchJS{terminalLaunchResponse: resp, Seeded: seeded, Run: res.run.ID, Item: body.Item}
	if !seeded {
		out.Prompt = res.task.Prompt
	}
	writeJSON(w, out)
	s.kickWatchRootsRefresh()
}

// The labels of the rows the held card of a fix launch adds. Observer computes
// them; the body members the agent sent are shown under their own names, and a
// member that would wear one of these labels is taken out of the replayed body
// (securityAssessFixPin), so no row of the card under these names is the
// agent's.
const (
	fixHeldPromptLabel   = "task prompt (Observer built this)"
	fixHeldDigestLabel   = "task digest (Observer built this)"
	fixHeldReplacedLabel = "members Observer replaced"
)

// The bounds of fix launches held at once: for one run, and in all. A request
// past a bound is refused before the task is built, so a loop of requests
// cannot make the daemon re-read a project's files for each one.
const (
	maxHeldFixesPerRun = 6
	maxHeldFixesTotal  = 12
)

// securityAssessHeldFixes counts the fix launches waiting for a human: those of
// the run, and all of them.
func (s *Server) securityAssessHeldFixes(runID string) (forRun, all int) {
	row, ok := launchRouteFor("/api/security/assessments/fix")
	if !ok || s.opts.PendingLaunches == nil {
		return 0, 0
	}
	runKey := jsonFoldKey("run")
	for _, p := range s.opts.PendingLaunches.List() {
		if !strings.HasPrefix(p.What, row.what) {
			continue
		}
		all++
		for _, d := range p.Details {
			if jsonFoldKey(d.Label) == runKey && d.Value == runID {
				forRun++
				break
			}
		}
	}
	return forRun, all
}

// securityAssessFixHeld is the hold hook of the fix route (heldExtras). For an
// agent's request it builds the task the confirm would start, once, and
//
//   - refuses the request, as the route itself would, when the task cannot be
//     built (nothing is held that a confirm would only refuse);
//   - shows the exact prompt and its digest first on the card, under labels the
//     body cannot wear;
//   - returns the body the confirm replays: the agent's body with prompt_sha256
//     set to that digest and project_root to the run's folder (whatever the
//     agent sent for either is replaced, a member named prompt or like a label
//     is dropped; the handler ignores unknown members, so no launch changes),
//     so a stored model that changes between the hold and the confirm is a 409
//     plan_changed and starts nothing.
func (s *Server) securityAssessFixHeld(r *http.Request, body []byte) heldExtra {
	refuse := func(f func(w http.ResponseWriter)) heldExtra { return heldExtra{Refuse: f} }
	var req securityAssessFixRequest
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&req); err != nil {
		return refuse(func(w http.ResponseWriter) { http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest) })
	}
	if forRun, all := s.securityAssessHeldFixes(req.Run); forRun >= maxHeldFixesPerRun || all >= maxHeldFixesTotal {
		return refuse(func(w http.ResponseWriter) {
			writePendingError(w, http.StatusTooManyRequests, dashapi.PendingCodeTooMany,
				"fix launches for this run already wait for a human's confirm; confirm or reject one first")
		})
	}
	res, refusal := s.securityAssessFixResolve(r.Context(), req.Run, req.Item)
	if refusal != nil {
		return refuse(func(w http.ResponseWriter) { refusal.write(s, w) })
	}
	digest := secassess.PromptSHA256(res.task.Prompt)
	pinned, replaced, ok := securityAssessFixPin(body, digest, res.root)
	if !ok {
		return refuse(func(w http.ResponseWriter) { http.Error(w, "invalid JSON body: not one object", http.StatusBadRequest) })
	}
	details := []dashapi.PendingLaunchDetail{
		{Label: fixHeldPromptLabel, Value: res.task.Prompt},
		{Label: fixHeldDigestLabel, Value: digest},
	}
	if len(replaced) > 0 {
		details = append(details, dashapi.PendingLaunchDetail{
			Label: fixHeldReplacedLabel, Value: clampDetailValue(strings.Join(replaced, ", ")), Warn: true,
		})
	}
	return heldExtra{Details: details, Body: pinned}
}

// securityAssessFixPin returns the body a confirm replays: the members of body
// in their order, except that a member the card computes (prompt, the digest,
// the project folder, or a member named like one of the card's labels) is taken
// out, then prompt_sha256 and project_root set to digest and root. replaced
// names the members the agent sent that Observer replaced with another value or
// dropped; ok is false when body is not one JSON object.
func securityAssessFixPin(body []byte, digest, root string) (pinned []byte, replaced []string, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, nil, false
	}
	own := map[string]string{jsonFoldKey("prompt_sha256"): digest, jsonFoldKey("project_root"): root}
	dropped := map[string]bool{jsonFoldKey("prompt"): true, fixHeldPromptLabel: true, fixHeldDigestLabel: true, fixHeldReplacedLabel: true}
	var out bytes.Buffer
	out.WriteByte('{')
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, false
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, nil, false
		}
		fold := jsonFoldKey(key)
		if want, mine := own[fold]; mine {
			var sent string
			if json.Unmarshal(raw, &sent) != nil || sent != want {
				replaced = append(replaced, key)
			}
			continue
		}
		if dropped[fold] || dropped[key] {
			replaced = append(replaced, key)
			continue
		}
		k, err := json.Marshal(key)
		if err != nil {
			return nil, nil, false
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		out.Write(k)
		out.WriteByte(':')
		out.Write(raw)
	}
	if _, err := dec.Token(); err != nil {
		return nil, nil, false
	}
	for _, m := range [][2]string{{"project_root", root}, {"prompt_sha256", digest}} {
		v, err := json.Marshal(m[1])
		if err != nil {
			return nil, nil, false
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		out.WriteString(`"` + m[0] + `":`)
		out.Write(v)
	}
	out.WriteByte('}')
	return out.Bytes(), replaced, true
}
