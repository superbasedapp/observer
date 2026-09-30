package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

// `observer obs admission setup` — the interactive admin wizard for the
// input-admission guardrail (docs/admission-setup.md §2). It mirrors
// `observer init`'s interactive idiom exactly: line-oriented prompts, ONE
// consent before the single config write, and a zero-flag-on-a-TTY gate that
// falls back to a flag-driven batch mode for scripts/CI. It composes only
// existing pure pieces (the starter templates, the lint wrapper, the judge
// probe) through the obs_wire wrappers — this file imports no internal/obs
// package (the separability boundary).

// admissionSetupChoices is the resolved set of decisions the wizard applies to
// a config, gathered either interactively or from batch flags. Keeping the
// apply step (applyAdmissionSetup) pure over this struct makes the whole wizard
// unit-testable without a TTY.
type admissionSetupChoices struct {
	EnableObs bool
	// Judge names the hosting to write; empty keeps the current judge.
	JudgeBaseURL   string
	JudgeModel     string
	JudgeAPIKeyEnv string
	SetJudge       bool
	// AdoptTemplates lists starter-template keys to write; Purpose seeds
	// valid_use_case, DeniedTopics seeds denied_topics.
	AdoptTemplates []string
	Purpose        string
	DeniedTopics   []string
	// PrefilterDeny + MaxMessageBytes are the optional deterministic
	// pre-filter; 0 leaves MaxMessageBytes at the current value.
	PrefilterDeny   []string
	MaxMessageBytes int
	// Mode is the admission posture to write (default observe).
	Mode string
}

// applyAdmissionSetup returns cfg with the wizard's choices applied. It is
// PURE — no I/O, no prompts — so tests can assert the resulting config
// compiles + lints. Criteria are merged by ID (re-adopting a template replaces
// its prior row, never duplicates it).
func applyAdmissionSetup(cfg config.Config, ch admissionSetupChoices) config.Config {
	if ch.EnableObs {
		cfg.Observability.Enabled = true
	}
	cfg.Observability.Admission.Enabled = true
	if ch.Mode != "" {
		cfg.Observability.Admission.Mode = ch.Mode
	} else if cfg.Observability.Admission.Mode == "" {
		cfg.Observability.Admission.Mode = "observe"
	}
	if ch.SetJudge {
		cfg.Observability.Admission.Judge.BaseURL = ch.JudgeBaseURL
		cfg.Observability.Admission.Judge.Model = ch.JudgeModel
		cfg.Observability.Admission.Judge.APIKeyEnv = ch.JudgeAPIKeyEnv
	}
	byID := map[string]int{}
	for i, c := range cfg.Observability.Admission.Criterion {
		byID[c.ID] = i
	}
	for _, key := range ch.AdoptTemplates {
		crit, ok := obsAdmissionRenderTemplate(key, ch.Purpose, ch.DeniedTopics)
		if !ok {
			continue
		}
		if idx, exists := byID[crit.ID]; exists {
			cfg.Observability.Admission.Criterion[idx] = crit
		} else {
			cfg.Observability.Admission.Criterion = append(cfg.Observability.Admission.Criterion, crit)
			byID[crit.ID] = len(cfg.Observability.Admission.Criterion) - 1
		}
	}
	if len(ch.PrefilterDeny) > 0 {
		cfg.Observability.Admission.Prefilter.Deny = append(cfg.Observability.Admission.Prefilter.Deny, ch.PrefilterDeny...)
	}
	if ch.MaxMessageBytes > 0 {
		cfg.Observability.Admission.Prefilter.MaxMessageBytes = ch.MaxMessageBytes
	}
	return cfg
}

// setupPrompter reads y/n and free-text answers from a line-oriented stdin,
// mirroring init_interactive.go's initPrompter (empty = default; EOF aborts).
type setupPrompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *setupPrompter) ask(question string, def bool) (bool, error) {
	suffix := "[Y/n]"
	if !def {
		suffix = "[y/N]"
	}
	for {
		fmt.Fprintf(p.out, "  %s %s ", question, suffix)
		line, err := p.in.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		if err != nil && answer == "" {
			return false, fmt.Errorf("stdin closed — stopping; nothing was written")
		}
		switch answer {
		case "":
			return def, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(p.out, "  please answer y or n (enter for the default)")
			if err != nil {
				return false, fmt.Errorf("stdin closed — stopping; nothing was written")
			}
		}
	}
}

// prompt reads one free-text line; empty input takes def.
func (p *setupPrompter) prompt(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "  %s [%s] ", question, def)
	} else {
		fmt.Fprintf(p.out, "  %s ", question)
	}
	line, err := p.in.ReadString('\n')
	answer := strings.TrimSpace(line)
	if err != nil && answer == "" {
		if def != "" {
			return def, nil
		}
		return "", fmt.Errorf("stdin closed — stopping; nothing was written")
	}
	if answer == "" {
		return def, nil
	}
	return answer, nil
}

// localModelServer is one reachable OpenAI-compatible local model server.
type localModelServer struct {
	BaseURL string
	Label   string
}

// probeLocalModelServers checks the common local inference endpoints (Ollama
// 11434, vLLM/llama.cpp 8000) for a reachable /v1/models. Best-effort and
// fast — a short timeout so an absent server doesn't stall the wizard.
func probeLocalModelServers(ctx context.Context) []localModelServer {
	candidates := []localModelServer{
		{BaseURL: "http://127.0.0.1:11434/v1", Label: "Ollama (127.0.0.1:11434)"},
		{BaseURL: "http://127.0.0.1:8000/v1", Label: "vLLM/llama.cpp (127.0.0.1:8000)"},
	}
	var found []localModelServer
	client := &http.Client{Timeout: 700 * time.Millisecond}
	for _, c := range candidates {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/models", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 500 {
			found = append(found, c)
		}
	}
	return found
}

// collectAdmissionChoices runs the interactive prompt sequence, returning the
// resolved choices (or an error if stdin closed mid-flow). It performs no
// writes — the caller applies + confirms + persists.
func collectAdmissionChoices(ctx context.Context, p *setupPrompter, cfg config.Config) (admissionSetupChoices, error) {
	var ch admissionSetupChoices

	// 1. Preconditions.
	if !cfg.Observability.Enabled {
		yes, err := p.ask("[observability] is off — enable it now?", true)
		if err != nil {
			return ch, err
		}
		ch.EnableObs = yes
		if !yes {
			fmt.Fprintln(p.out, "  admission needs [observability] enabled; re-run when ready.")
			return ch, errSetupAborted
		}
	}

	// 2. Judge hosting.
	fmt.Fprintln(p.out, "\njudge hosting — where the LLM that adjudicates NL policy runs.")
	fmt.Fprintln(p.out, "  local (loopback) makes ZERO network calls; a remote judge receives a")
	fmt.Fprintln(p.out, "  secret-redacted, size-capped prompt (never a raw secret).")
	local := probeLocalModelServers(ctx)
	for _, s := range local {
		fmt.Fprintf(p.out, "  detected local model server: %s\n", s.Label)
	}
	setJudge, err := p.ask("configure the judge now?", true)
	if err != nil {
		return ch, err
	}
	if setJudge {
		if err := collectJudge(p, cfg, local, &ch); err != nil {
			return ch, err
		}
	}

	// 3. Usage rules — starter templates.
	fmt.Fprintln(p.out, "\nusage rules — adopt starter templates (edit later in config.toml):")
	for _, tpl := range obsAdmissionStarterTemplates() {
		fmt.Fprintf(p.out, "  • %s\n    %s\n", tpl.Title, tpl.Description)
		yes, err := p.ask(fmt.Sprintf("adopt %q?", tpl.Key), tpl.Key == "on_scope")
		if err != nil {
			return ch, err
		}
		if !yes {
			continue
		}
		if tpl.NeedsPurpose {
			purpose, err := p.prompt("app purpose (one line, seeds the on-scope rule):", ch.Purpose)
			if err != nil {
				return ch, err
			}
			if strings.TrimSpace(purpose) == "" {
				fmt.Fprintln(p.out, "  skipped — a purpose is required for this rule.")
				continue
			}
			ch.Purpose = purpose
		}
		if tpl.NeedsTopics {
			topics, err := p.prompt("denied topics (comma-separated):", "")
			if err != nil {
				return ch, err
			}
			ch.DeniedTopics = splitCSV(topics)
			if len(ch.DeniedTopics) == 0 {
				fmt.Fprintln(p.out, "  skipped — at least one topic is required for this rule.")
				continue
			}
		}
		ch.AdoptTemplates = append(ch.AdoptTemplates, tpl.Key)
	}

	// 4. Mode — observe-first.
	fmt.Fprintln(p.out, "\nmode — start in observe (records verdicts, blocks nothing); flip to")
	fmt.Fprintln(p.out, "  enforce only after a simulate/soak (`observer obs admission simulate`).")
	enforce, err := p.ask("start in enforce mode instead of observe?", false)
	if err != nil {
		return ch, err
	}
	ch.Mode = "observe"
	if enforce {
		ch.Mode = "enforce"
	}
	return ch, nil
}

// collectJudge gathers the judge base_url/model/api_key_env via a numbered
// hosting menu.
func collectJudge(p *setupPrompter, cfg config.Config, local []localModelServer, ch *admissionSetupChoices) error {
	fmt.Fprintln(p.out, "  1) local model server (loopback — no egress, no key)")
	fmt.Fprintln(p.out, "  2) hosted provider (OpenAI-compatible — opt-in egress, api_key_env)")
	fmt.Fprintln(p.out, "  3) aggregator (OpenRouter — opt-in egress, api_key_env)")
	fmt.Fprintln(p.out, "  4) private endpoint (your VPC — opt-in egress, api_key_env)")
	pick, err := p.prompt("choose 1-4:", "1")
	if err != nil {
		return err
	}
	ch.SetJudge = true
	switch strings.TrimSpace(pick) {
	case "1":
		def := "http://127.0.0.1:11434/v1"
		if len(local) > 0 {
			def = local[0].BaseURL
		}
		base, err := p.prompt("local base_url:", def)
		if err != nil {
			return err
		}
		model, err := p.prompt("model (e.g. llama3.1:8b-instruct):", cfg.Observability.Admission.Judge.Model)
		if err != nil {
			return err
		}
		ch.JudgeBaseURL, ch.JudgeModel, ch.JudgeAPIKeyEnv = base, model, ""
	case "2", "3", "4":
		def := map[string]string{"2": "https://api.openai.com/v1", "3": "https://openrouter.ai/api/v1", "4": ""}[pick]
		keyEnvDef := map[string]string{"2": "OPENAI_API_KEY", "3": "OPENROUTER_API_KEY", "4": ""}[pick]
		base, err := p.prompt("base_url:", def)
		if err != nil {
			return err
		}
		model, err := p.prompt("model:", "")
		if err != nil {
			return err
		}
		fmt.Fprintln(p.out, "  the API key is read from an ENV VAR at run time — name it here, never paste the key.")
		keyEnv, err := p.prompt("api_key_env (env var name):", keyEnvDef)
		if err != nil {
			return err
		}
		ch.JudgeBaseURL, ch.JudgeModel, ch.JudgeAPIKeyEnv = base, model, keyEnv
		fmt.Fprintln(p.out, "  note: a remote judge receives a secret-redacted, size-capped prompt (opt-in egress).")
	default:
		fmt.Fprintln(p.out, "  unrecognised choice — leaving the judge unchanged.")
		ch.SetJudge = false
	}
	return nil
}

// printAdmissionSummary prints the resolved config's admission posture + the
// exact next commands.
func printAdmissionSummary(out io.Writer, cfg config.Config) {
	ac := cfg.Observability.Admission
	hosting := judgeSetupHostingLabel(cfg)
	fmt.Fprintln(out, "\nadmission configured:")
	fmt.Fprintf(out, "  mode:          %s\n", ac.Mode)
	fmt.Fprintf(out, "  criteria:      %d\n", len(ac.Criterion))
	fmt.Fprintf(out, "  judge hosting: %s (%s)\n", hosting, ac.Judge.Model)
	fmt.Fprintln(out, "\nnext:")
	fmt.Fprintln(out, "  observer obs admission test \"<a sample request>\"   # dry-run one message")
	fmt.Fprintln(out, "  observer obs admission status                       # posture + judge reachability")
	fmt.Fprintln(out, "  observer obs admission simulate                     # replay captured traffic before enforce")
}

// judgeSetupHostingLabel reports the derived hosting label for the resolved
// admission judge (mirrors obs_wire's judgeHostingLabel derivation without the
// internal/obs import — a small duplication kept honest by the guide's
// "hosting is derived from base_url" note).
func judgeSetupHostingLabel(cfg config.Config) string {
	j := cfg.Observability.Admission.Judge
	if j.Model == "" {
		j = cfg.Observability.Judge
	}
	if j.Model == "" {
		return "off"
	}
	u := strings.ToLower(j.BaseURL)
	switch {
	case u == "":
		return "aggregator"
	case dataauthority.IsLoopbackJudgeEndpoint(j.BaseURL): // exact host parse, never a substring (JUDGE-1 round 5)
		return "local"
	case strings.Contains(u, "openrouter.ai"):
		return "aggregator"
	case strings.Contains(u, "openai.com"), strings.Contains(u, "anthropic.com"), strings.Contains(u, "googleapis.com"):
		return "provider"
	default:
		return "private"
	}
}

// errSetupAborted signals the wizard stopped cleanly at the user's request
// (not an error to surface as a failure).
var errSetupAborted = errors.New("setup aborted")

// runInteractiveAdmissionSetup drives the full interactive flow: collect →
// apply → reachability probe → lint → one consent → write.
func runInteractiveAdmissionSetup(ctx context.Context, out io.Writer, in io.Reader, cfg config.Config, configPath string) error {
	fmt.Fprintln(out, "observer obs admission setup — interactive")
	fmt.Fprintln(out, "each section previews; nothing is written without a final yes.")
	p := &setupPrompter{in: bufio.NewReader(in), out: out}

	ch, err := collectAdmissionChoices(ctx, p, cfg)
	if err != nil {
		if errors.Is(err, errSetupAborted) {
			return nil
		}
		return err
	}
	newCfg := applyAdmissionSetup(cfg, ch)

	// Reachability probe (best-effort; a slow local model is surfaced).
	if ch.SetJudge {
		probe := obsAdmissionProbeJudge(ctx, newCfg)
		switch {
		case probe.Off:
			fmt.Fprintln(out, "\njudge: off (no model configured)")
		case probe.OK:
			fmt.Fprintf(out, "\njudge reachable: %s (%s) in %dms\n", probe.Hosting, probe.Model, probe.LatencyMS)
		default:
			fmt.Fprintf(out, "\njudge NOT reachable: %s (%s) — %s\n", probe.Hosting, probe.Model, probe.Err)
			fmt.Fprintln(out, "  (you can still save; fix the endpoint/key/model and re-run `admission status`)")
		}
	}

	// Lint the resolved policy before offering to write.
	issues, fatal := obsAdmissionLintCLI(newCfg)
	for _, is := range issues {
		fmt.Fprintf(out, "  lint: %s\n", is)
	}
	if fatal {
		fmt.Fprintln(out, "policy has FATAL lint issues — not writing. Fix the above and re-run.")
		return nil
	}

	printAdmissionSummary(out, newCfg)
	yes, err := p.ask(fmt.Sprintf("\nwrite this configuration to %s?", configPath), true)
	if err != nil {
		return err
	}
	if !yes {
		fmt.Fprintln(out, "not written.")
		return nil
	}
	if err := config.WriteToml(configPath, newCfg); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Fprintf(out, "wrote %s (a .bak backup was kept).\n", configPath)
	return nil
}

// resolveAdmissionConfigPath returns the config file path to read/write: the
// explicit flag, else the default ~/.observer/config.toml (which need not yet
// exist — the wizard creates it).
func resolveAdmissionConfigPath(flagPath string) (string, error) {
	return config.ResolveGlobalPath(flagPath)
}

// setupStdinIsTerminal reports whether both stdin and stdout are TTYs (the
// zero-flag interactive gate), reusing the init wizard's char-device check.
func setupStdinIsTerminal() bool {
	return stdinIsTerminal() && stdoutIsTerminal()
}

// loadConfigForSetup loads the config for the wizard, tolerating a missing
// file (a fresh node) by falling back to defaults.
func loadConfigForSetup(path string) (config.Config, error) {
	if _, err := os.Stat(path); err != nil {
		return config.Default(), nil
	}
	return config.Load(config.LoadOptions{GlobalPath: path})
}
