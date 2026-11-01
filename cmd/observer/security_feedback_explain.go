//go:build !sbo_omit_security

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/secexplain"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_feedback_explain.go is the explain flow of security Phase H
// (security pillar plan sections 5.11 (b) and 6.2 step 3; lane sec-h):
// `observer security explain <id>` and the Findings tab's Explain button
// (POST /api/security/findings/{id}/explain) share explainSecurityFinding.
// It reads the finding, builds the prompt in internal/secexplain from rule
// data plus scrubbed and capped evidence fenced as untrusted, asks the
// configured judge through internal/judgeclient (secure egress for a remote
// judge, security_feedback_judge.go) and returns the advisory answer. It
// writes nothing: no status, no verdict, no posture, no event (SECP-15).

// securityExplainTimeout bounds one judge call.
const securityExplainTimeout = 60 * time.Second

// securityExplainJudge is one configured judge: the call, its resolved
// endpoint (for the egress rule) and its labels.
type securityExplainJudge struct {
	complete func(ctx context.Context, prompt string) (string, error)
	baseURL  string
	model    string
	hosting  string
}

// securityExplainReader is the read-only store surface the flow needs: by
// construction it has no method that could change a finding.
type securityExplainReader interface {
	SecFindingByID(ctx context.Context, id string) (secfinding.Finding, bool, error)
	SecFindingEvidence(ctx context.Context, id string) (string, string, bool, error)
	SessionAuthority(ctx context.Context, sessionID string) (dataauthority.Classification, bool, error)
}

// explainSecurityFinding explains finding id. judge is the configured judge
// (nil: none configured). An unknown id is ErrExplainUnknownFinding.
func explainSecurityFinding(ctx context.Context, r securityExplainReader, judge *securityExplainJudge, id string) (dashapi.SecurityExplanation, error) {
	f, ok, err := r.SecFindingByID(ctx, id)
	if err != nil {
		return dashapi.SecurityExplanation{}, err
	}
	if !ok {
		return dashapi.SecurityExplanation{}, dashapi.ErrExplainUnknownFinding
	}
	if judge == nil || judge.complete == nil {
		return dashapi.SecurityExplanation{Reason: "No judge is configured, so nothing was sent. Set [observability.judge] model (and base_url to use a model on this machine) to get explanations."}, nil
	}
	out := dashapi.SecurityExplanation{Model: judge.model, Hosting: judge.hosting}
	evidence, session, _, err := r.SecFindingEvidence(ctx, id)
	if err != nil {
		return dashapi.SecurityExplanation{}, err
	}
	// JUDGE-1 (docs/security.md): org or unknown data reaches only a judge
	// on this machine (or an org-approved one, which this flow does not
	// know of); a personal session's finding may go to a remote judge
	// through the secure egress.
	auth := dataauthority.Authority("")
	if session != "" {
		if c, found, err := r.SessionAuthority(ctx, session); err == nil && found {
			auth = c.Authority
		}
	}
	if ok, why := dataauthority.JudgeEgressAllowed(auth, judge.baseURL, false); !ok {
		out.Reason = "Nothing was sent: " + why + ". Point [observability.judge] base_url at a model on this machine to explain it."
		return out, nil
	}
	prompt := secexplain.Prompt(secexplain.Input{
		RuleID: f.Rule.ID, Category: string(f.Category), Severity: string(f.Severity), Confidence: string(f.Confidence),
		Status: string(f.Status), Path: f.Location.RelPath, Line: f.Location.StartLine, Evidence: evidence,
	}, scrub.New().ScrubForward)
	cctx, cancel := context.WithTimeout(ctx, securityExplainTimeout)
	defer cancel()
	reply, err := judge.complete(cctx, prompt)
	if err != nil {
		out.Reason = "The judge did not answer: " + err.Error()
		return out, nil
	}
	ex, ok := secexplain.Answer(reply)
	if !ok {
		out.Reason = "The judge returned an empty answer."
		return out, nil
	}
	out.Available, out.Text, out.Advisory, out.Label = true, ex.Text, ex.Advisory, ex.Label
	return out, nil
}

// securityExplainFor is the dashboard and CLI entry: it applies the opt-in
// rule (security.feedback selected), opens nothing it does not need, and
// explains id through the configured judge.
func securityExplainFor(ctx context.Context, cfg config.Config, database *sql.DB, id string) (dashapi.SecurityExplanation, error) {
	if !securitySelected(componentSnapshotForConfig(cfg), securityFeedbackComponent) {
		return dashapi.SecurityExplanation{}, dashapi.ErrExplainNotSelected
	}
	return explainSecurityFinding(ctx, store.New(database), securityExplainJudgeFor(cfg), id)
}

// securityExplainDash is dashapi.Options.SecurityExplain.
func securityExplainDash(configPath string, database *sql.DB) dashapi.SecurityExplain {
	return func(ctx context.Context, id string) (dashapi.SecurityExplanation, error) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			return dashapi.SecurityExplanation{}, err
		}
		return securityExplainFor(ctx, cfg, database, id)
	}
}

// newSecurityExplainCmd is `observer security explain <id>`.
func newSecurityExplainCmd() *cobra.Command {
	var configPath string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "explain <finding-id>",
		Short: "Ask the configured judge to explain one finding (advisory; changes nothing)",
		Long: "Explain one Code security finding with the judge configured under [observability.judge]\n" +
			"(component security.feedback). The prompt carries rule data and the finding's redacted\n" +
			"evidence, scrubbed and fenced as untrusted; a remote judge also gets the secure egress\n" +
			"(secret redaction and a size cap). The answer is advisory: it never changes the finding's\n" +
			"status, a verdict or the commit gate. With no judge configured, nothing is sent.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			ex, err := securityExplainFor(cmd.Context(), cfg, database, args[0])
			if errors.Is(err, dashapi.ErrExplainNotSelected) {
				return fmt.Errorf("security explain: %w", err)
			}
			if err != nil {
				return err
			}
			if asJSON {
				return writeSecurityJSON(cmd.OutOrStdout(), ex)
			}
			w := cmd.OutOrStdout()
			if !ex.Available {
				fmt.Fprintln(w, ex.Reason)
				return nil
			}
			fmt.Fprintln(w, ex.Text)
			fmt.Fprintf(w, "\n%s (%s, %s)\n", ex.Label, ex.Model, ex.Hosting)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// securityFeedbackSubcommands are Phase H's verbs under `observer security`.
func securityFeedbackSubcommands() []*cobra.Command {
	return []*cobra.Command{newSecurityExplainCmd(), newSecurityReportCmd()}
}
