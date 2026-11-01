package guardtest

import (
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// testIdentity is the tool and session id a dry run carries, so a verdict
// can never be mistaken for a real session's.
const testIdentity = "guard-test"

// Base is the dry-run event before its subject: where it happens and when.
func Base(cwd, projectRoot string, now time.Time) policy.Event {
	return policy.Event{
		Tool: testIdentity, SessionID: testIdentity,
		Cwd: cwd, ProjectRoot: projectRoot, Now: now,
	}
}

// Command is base as a shell command whose shell the dry run does not name:
// read as POSIX, and on a Windows working directory also as PowerShell, the
// reading a hook gives a generic shell tool there
// (policy.UnstatedShellAltDialect). Without that second reading a dry run on
// Windows lexed `C:\Users\dev` as `C:Usersdev` (WINNODE item 2).
func Command(base policy.Event, command string) policy.Event {
	return CommandIn(base, command, "")
}

// CommandIn is base as a shell command read under dialect. An empty dialect
// is Command's unstated shell.
func CommandIn(base policy.Event, command string, dialect policy.Dialect) policy.Event {
	base.Kind = policy.KindShellExec
	base.ActionType = "run_command"
	base.Target = command
	base.Dialect = dialect
	base.AltDialect = policy.UnstatedShellAltDialect(base.Kind, dialect, base.Cwd)
	return base
}

// shellDialects maps the `observer guard test --shell` values onto the
// dialect a command is read under.
var shellDialects = map[string]policy.Dialect{
	"":           "",
	"posix":      policy.DialectPosix,
	"powershell": policy.DialectPowerShell,
	"cmd":        policy.DialectCmd,
}

// ShellDialect resolves a --shell value ("" is the unstated shell). ok is
// false for a value the guard does not read.
func ShellDialect(name string) (policy.Dialect, bool) {
	d, ok := shellDialects[name]
	return d, ok
}

// FileWrite is base as a write to path.
func FileWrite(base policy.Event, path string) policy.Event {
	base.Kind = policy.KindFileAccess
	base.ActionType = "write_file"
	base.Target = path
	return base
}

// Raw is base as an arbitrary event (`observer guard test --event`). An empty
// sessionID keeps the dry-run identity.
func Raw(base policy.Event, kind, target, actionType, sessionID string) policy.Event {
	base.Kind = policy.EventKind(kind)
	base.Target = target
	base.ActionType = actionType
	if sessionID != "" {
		base.SessionID = sessionID
	}
	return base
}

// Result is one dry run: the event, the configured mode, and the verdict
// under that mode and under enforce.
type Result struct {
	Event          policy.Event
	Mode           string
	Verdict        policy.Verdict
	EnforceVerdict policy.Verdict
}

// ModeChangesVerdict reports whether flipping [guard] mode to enforce would
// change this event's decision.
func (r Result) ModeChangesVerdict() bool { return r.EnforceVerdict.Decision != r.Verdict.Decision }

// Run evaluates ev with two fresh engines over cfg: one in the configured
// mode, one in enforce. roots is the known-project set (R-151's reference);
// nil leaves it empty, as the CLI always has.
func Run(cfg config.GuardConfig, home string, roots []string, ev policy.Event) (Result, error) {
	g, err := guard.New(guard.Options{Config: cfg, Home: home, KnownProjectRoots: roots})
	if err != nil {
		return Result{}, fmt.Errorf("construct guard: %w", err)
	}
	verdict, gerr := g.Evaluate(ev)
	if gerr != nil {
		return Result{}, fmt.Errorf("guard internal error: %w", gerr)
	}
	enforceCfg := cfg
	enforceCfg.Mode = "enforce"
	eg, err := guard.New(guard.Options{Config: enforceCfg, Home: home, KnownProjectRoots: roots})
	if err != nil {
		return Result{}, fmt.Errorf("construct enforce-mode guard: %w", err)
	}
	// The CLI has always ignored the enforce engine's internal error (the
	// configured-mode verdict above already surfaced one).
	enforceVerdict, _ := eg.Evaluate(ev) //nolint:errcheck // see above
	return Result{Event: ev, Mode: cfg.Mode, Verdict: verdict, EnforceVerdict: enforceVerdict}, nil
}

// Report is the `observer guard test --json` document. Fields are in the
// alphabetical order the CLI's map encoding always emitted.
type Report struct {
	Advice          string `json:"advice"`
	Decision        string `json:"decision"`
	EnforceDecision string `json:"enforce_decision"`
	Kind            string `json:"kind"`
	ProjectRoot     string `json:"project_root"`
	Reason          string `json:"reason"`
	RuleID          string `json:"rule_id"`
	Severity        string `json:"severity"`
	Source          string `json:"source"`
	Target          string `json:"target"`
}

// Report renders r as the --json document.
func (r Result) Report() Report {
	return Report{
		Advice:          r.Verdict.Advice,
		Decision:        r.Verdict.Decision.String(),
		EnforceDecision: r.EnforceVerdict.Decision.String(),
		Kind:            string(r.Event.Kind),
		ProjectRoot:     r.Event.ProjectRoot,
		Reason:          r.Verdict.Reason,
		RuleID:          r.Verdict.RuleID,
		Severity:        r.Verdict.Severity.String(),
		Source:          r.Verdict.Source,
		Target:          r.Event.Target,
	}
}
