package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/guardtest"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Guard tools (T-154): the Security page's twins of the guard CLI flows that
// had no dashboard equivalent.
//
//   - POST /api/guard/test is `observer guard test`: one dry run through the
//     shared internal/guardtest (the CLI calls the same Run), answered in
//     process. It is read-shaped: nothing executes and nothing persists.
//   - /api/guard/jobs/policy and /api/guard/jobs/mcp run `observer guard
//     rescan | compile [--diff]` and `observer guard mcp scan | report` as
//     jobs in the shared registry (the evidence-job precedent): every argv
//     token comes from the closed tables below, nothing typed reaches
//     os/exec, and a kind that changes state needs the confirm token the
//     route's GET mints.
//   - /api/guard/jobs/chain runs the audit chain repairs (`observer guard
//     repair-anchors | dedup-events | relink-gaps`, each with and without
//     --apply) the same way (B-G8).

// guardTestMaxTarget bounds the dry-run subject (a command line or a path).
const guardTestMaxTarget = 4096

// guardTestKinds maps the card's subject kinds onto the event builders.
var guardTestKinds = map[string]func(base policy.Event, target string) policy.Event{
	"command": guardtest.Command,
	"file":    guardtest.FileWrite,
}

// guardTestResponse is POST /api/guard/test.
type guardTestResponse struct {
	// Mode is the configured [guard] mode the verdict was judged under.
	Mode string `json:"mode"`
	// Report is the `observer guard test --json` document.
	Report guardtest.Report `json:"report"`
	// ModeChangesVerdict is true when enforce would decide differently.
	ModeChangesVerdict bool `json:"mode_changes_verdict"`
}

// handleGuardTest serves POST /api/guard/test {kind: command|file, target,
// project_root?}. project_root, when given, must be a project this observer
// has captured (the CLI uses the current directory's git root instead); when
// empty the dry run happens in the home directory, outside every project.
func (s *Server) handleGuardTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Kind        string `json:"kind"`
		Target      string `json:"target"`
		ProjectRoot string `json:"project_root"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	build, ok := guardTestKinds[req.Kind]
	if !ok {
		http.Error(w, `kind must be "command" or "file"`, http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" || len(target) > guardTestMaxTarget || !utf8.ValidString(target) || strings.ContainsRune(target, 0) {
		http.Error(w, fmt.Sprintf("target must be 1 to %d characters of text", guardTestMaxTarget), http.StatusBadRequest)
		return
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load config: %w", err))
		return
	}
	roots, err := store.New(s.opts.DB).ProjectRoots(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	home, _ := os.UserHomeDir()
	where := home
	if req.ProjectRoot != "" {
		if !containsString(roots, req.ProjectRoot) {
			http.Error(w, "project_root is not a project this observer has captured", http.StatusBadRequest)
			return
		}
		where = req.ProjectRoot
	}
	res, err := guardtest.Run(cfg.Guard, home, roots, build(guardtest.Base(where, where, s.now().UTC()), target))
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, guardTestResponse{Mode: res.Mode, Report: res.Report(), ModeChangesVerdict: res.ModeChangesVerdict()})
}

func containsString(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// guardJobKind is one row of a guard job route's closed vocabulary.
type guardJobKind struct {
	// argv builds the `observer` arguments; an error is a 400.
	argv func(req guardJobRequest) ([]string, error)
	// writes marks a kind that changes state (guard_events, pins, an AI
	// client's config): it needs the confirm token.
	writes bool
	// label names the kind in the GET view (the UI's button copy is its own).
	label string
}

// guardJobRequest is a guard job route's POST body.
type guardJobRequest struct {
	Kind   string `json:"kind"`
	Period string `json:"period"`
}

// guardRescanPeriods is the closed window vocabulary for `guard rescan
// --since` (a rescan over a year is the evidence export's job, not this).
var guardRescanPeriods = map[string]bool{"24h": true, "168h": true, "720h": true}

func fixedArgv(args ...string) func(guardJobRequest) ([]string, error) {
	return func(guardJobRequest) ([]string, error) { return append([]string(nil), args...), nil }
}

// guardPolicyJobs is the Rules tab's vocabulary.
var guardPolicyJobs = map[string]guardJobKind{
	"rescan": {
		writes: true,
		label:  "Re-judge captured history and record the verdicts the live guard missed (observer guard rescan)",
		argv: func(req guardJobRequest) ([]string, error) {
			p := req.Period
			if p == "" {
				p = "168h"
			}
			if !guardRescanPeriods[p] {
				return nil, fmt.Errorf("period must be one of 24h, 168h, 720h")
			}
			return []string{"guard", "rescan", "--since", p}, nil
		},
	},
	"compile-diff": {
		label: "Compare the policy with the native rules in each AI client's config (observer guard compile --diff)",
		argv:  fixedArgv("guard", "compile", "--diff"),
	},
	"compile": {
		writes: true,
		label:  "Write the policy into each AI client's native permission rules (observer guard compile)",
		argv:   fixedArgv("guard", "compile"),
	},
}

// guardMCPJobs is the MCP tab's vocabulary.
var guardMCPJobs = map[string]guardJobKind{
	"mcp-scan": {
		writes: true,
		label:  "Scan AI client MCP configs now: pin new servers, detect drift (observer guard mcp scan)",
		argv:   fixedArgv("guard", "mcp", "scan"),
	},
	"mcp-report": {
		label: "MCP compliance summary (observer guard mcp report)",
		argv:  fixedArgv("guard", "mcp", "report"),
	},
}

// guardChainJobs is the Coverage tab's audit chain repair (plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md, B-G8): the three
// documented repairs store.GuardChainRepairHint names, each as a dry run
// (a read: it only reports) and an apply (it rewrites guard_events rows, so
// it carries the confirm token, and guard rule R-165 denies an agent's
// request to this route). Every argv is fixed; the CLI's own code runs.
var guardChainJobs = map[string]guardJobKind{
	"repair-anchors": {
		label: "Find the rows whose action id old maintenance cleared and prove each id from the row's own hash (observer guard repair-anchors)",
		argv:  fixedArgv("guard", "repair-anchors"),
	},
	"repair-anchors-apply": {
		writes: true,
		label:  "Write the proven action ids (observer guard repair-anchors --apply)",
		argv:   fixedArgv("guard", "repair-anchors", "--apply"),
	},
	"dedup-events": {
		label: "Find repeated guard rows a transcript re-parse wrote (observer guard dedup-events)",
		argv:  fixedArgv("guard", "dedup-events"),
	},
	"dedup-events-apply": {
		writes: true,
		label:  "Remove the repeated rows and re-hash the chain after them (observer guard dedup-events --apply)",
		argv:   fixedArgv("guard", "dedup-events", "--apply"),
	},
	"relink-gaps": {
		label: "Find links broken only by a deleted row (observer guard relink-gaps)",
		argv:  fixedArgv("guard", "relink-gaps"),
	},
	"relink-gaps-apply": {
		writes: true,
		label:  "Re-link the chain over the deleted rows and record the rewrite (observer guard relink-gaps --apply)",
		argv:   fixedArgv("guard", "relink-gaps", "--apply"),
	},
}

// guardJobsView is GET on a guard job route.
type guardJobsView struct {
	ConfirmToken string             `json:"confirm_token"`
	Kinds        []guardJobKindView `json:"kinds"`
	// CompileEnabled is [guard.dialects] compile (policy route only): the CLI
	// refuses `guard compile` when it is off.
	CompileEnabled *bool `json:"compile_enabled,omitempty"`
}

type guardJobKindView struct {
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	Writes bool   `json:"writes"`
}

// guardJobsHandler serves one guard job route over its vocabulary: GET is
// the kinds plus the confirm token, POST starts one job.
func (s *Server) guardJobsHandler(kinds map[string]guardJobKind, withCompile bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			view := guardJobsView{ConfirmToken: setConfirmCookie(w, r)}
			for k, row := range kinds {
				view.Kinds = append(view.Kinds, guardJobKindView{Kind: k, Label: row.label, Writes: row.writes})
			}
			sort.Slice(view.Kinds, func(i, j int) bool { return view.Kinds[i].Kind < view.Kinds[j].Kind })
			if withCompile {
				cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
				if err != nil {
					writeErr(w, fmt.Errorf("load config: %w", err))
					return
				}
				on := cfg.Guard.Dialects.Compile
				view.CompileEnabled = &on
			}
			writeJSON(w, view)
		case http.MethodPost:
			var req guardJobRequest
			if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
				http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
				return
			}
			row, ok := kinds[req.Kind]
			if !ok {
				http.Error(w, "unknown kind for this route", http.StatusBadRequest)
				return
			}
			if row.writes && !requireJSONConfirm(w, r) {
				return
			}
			args, err := row.argv(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			jobID, err := newJobID()
			if err != nil {
				writeErr(w, fmt.Errorf("generate job id: %w", err))
				return
			}
			s.startGuardJob(w, jobID, req.Kind, args, "")
		default:
			http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
		}
	}
}
