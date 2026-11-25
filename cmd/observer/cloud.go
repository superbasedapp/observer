//go:build !sbo_omit_cloud_intelligence

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud.go is the `observer cloud` command family (CI-P2 Lane E — cloud-
// intelligence Azure Foundry plan of record §6 "CI-P2" CLI bullet). It is
// integration wiring only: it COMPOSES the already-landed pure packages
// (cloudcontract / cloudevidence), the node-local store seam (cloudlocal.go +
// dataauthority), and the CONSENT-GATED EGRESS SEAM (internal/cloudgateway). It
// invents no protocol.
//
// EGRESS POSTURE (divergence-remediation plan rev 4.1 §2 R2 + its F11
// disposition). This file no longer holds the network client, the credential
// store, or any direct import of internal/cloudclient / cloudcred / cloudpop.
// Every outbound call goes through internal/cloudgateway, which resolves live
// consent (fail-closed) before touching the network and keeps a distinguished
// BOOTSTRAP lane for the sign-in action itself. That is what the narrowed
// tests/invariant/cloud_egress_test.go allow-list now pins: the gateway is the
// one importer of the network lane, and cmd/observer reaches it only through
// that seam.
//
// The family is split by topic, all in this package: cloud.go holds the root
// command, base-URL resolution and the shared preview summary;
// cloud_envelope.go the evidence build; cloud_status.go, cloud_login.go,
// cloud_preview.go (preview and consent), cloud_sync.go (sync, job, the drain
// and the upload error classes), cloud_results.go (result pull and
// association) and cloud_account.go (logout and delete-account) the verbs; and
// cloud_purpose.go the purpose and field-class tables.
//
// Every subcommand still runs and exits — no goroutine, ticker, watcher hook, or
// daemon wiring lives here. What changed under R2 is the PRINCIPLE ("no egress
// without prior explicit consent", replacing "only typed CLI commands may touch
// the network"), which is why the gateway, not this file's shape, is now the
// enforcement point.

const (
	// cloudScrubberVersion is the scrubber-version label this lane binds into
	// every consent receipt and envelope. It is a stable node-side convention
	// (the scrub package exposes no version constant); the same value MUST be
	// used at preview, consent, and rebuild so the two-digest coherence check
	// holds.
	cloudScrubberVersion = "scrub.v1"
	// cloudRetentionPolicyVersion labels the retention policy a receipt is
	// bound under (recorded, node-local; the enforceable retention lives
	// server-side per plan §2.8).
	cloudRetentionPolicyVersion = "retention.v1-candidate"
	// cloudFeatureSessionEnrichment is the one enrichment feature this arc
	// ships (plan §5 in-scope: Signed-in Free session enrichment).
	cloudFeatureSessionEnrichment = cloudcontract.FeatureSessionEnrichment
	// cloudBaseURLEnv is the environment fallback for the cloud base URL.
	// Resolution order (D15): --base-url flag > this env var > [cloud].base_url
	// in config.toml > defaultCloudBaseURL (the hosted service). A shipped build
	// therefore signs in out of the box; env/config override only for staging or
	// self-hosting.
	cloudBaseURLEnv = "SBO_CLOUD_BASE_URL"
	// defaultCloudBaseURL is the hosted Cloud Intelligence service — the built-in
	// final fallback so `observer cloud login` (and the dashboard Sign in button
	// that spawns it) work without the operator hand-setting [cloud].base_url.
	// The Advanced settings field advertises this same URL as its placeholder.
	// Overridable for staging / self-hosting via --base-url, the env var, or
	// [cloud].base_url.
	defaultCloudBaseURL = "https://cloud.superbased.app"
	// cloudLoginPortEnv is the environment fallback for the WorkOS PKCE
	// callback listener port. There is no --flag for this value, so
	// resolution (D15) is: this env var > [cloud].login_port in config.toml
	// > the command's built-in default (9797).
	cloudLoginPortEnv = "SBO_CLOUD_LOGIN_PORT"
	// cloudSendingLeaseTTL is how long an outbox item may sit in `sending`
	// before `observer cloud sync` reclaims it as stranded (FD4). Since sync is
	// manual and single-shot, any `sending` row older than this is from a prior
	// interrupted run; the window is generous so a genuinely in-flight upload on
	// a slow link is never reclaimed out from under itself.
	cloudSendingLeaseTTL = 15 * time.Minute
)

// newCloudCmd assembles the `observer cloud` command family.
func newCloudCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Signed-in personal cloud intelligence",
		Long: "Personal cloud-intelligence commands (Signed-in Free spine).\n\n" +
			"These commands are the ONLY code that talks to the hosted service: the\n" +
			"observer/watcher never link a cloud network package. Besides being run by\n" +
			"hand, they are spawned as a subprocess by the `observer start` daemon's two\n" +
			"opt-in tickers (auto-sync when [cloud].auto_sync = true, every\n" +
			"[cloud].auto_sync_interval_minutes, default " + strconv.Itoa(config.CloudAutoSyncDefaultMinutes) + " minutes; background\n" +
			"enrichment while the enrichment policy is on) and by the dashboard's\n" +
			"Settings -> Cloud Intelligence buttons. Every upload stays consent-gated:\n" +
			"nothing is sent without a live grant, however the command was started.\n\n" +
			"The cloud base URL is taken from --base-url, else the " + cloudBaseURLEnv + " environment\n" +
			"variable, else [cloud].base_url in config.toml, else the built-in default\n" +
			"(" + defaultCloudBaseURL + "). The WorkOS login callback port is taken from\n" +
			cloudLoginPortEnv + ", else [cloud].login_port.",
	}
	cmd.AddCommand(
		newCloudStatusCmd(),
		newCloudLoginCmd(),
		newCloudPreviewCmd(),
		newCloudConsentCmd(),
		newCloudEnableCmd(),
		newCloudDisableCmd(),
		newCloudSyncCmd(),
		newCloudJobCmd(),
		newCloudGradeCommitCmd(),
		newCloudLogoutCmd(),
		newCloudDeleteAccountCmd(),
	)
	return cmd
}

// resolveCloudBaseURL applies the D15 flag > env > [cloud].base_url resolution,
// falling back to defaultCloudBaseURL (the hosted service) when none is set — so
// a fresh install signs in out of the box. It never returns "".
func resolveCloudBaseURL(flagVal string, cfg config.Config) string {
	if strings.TrimSpace(flagVal) != "" {
		return strings.TrimSpace(flagVal)
	}
	if v := strings.TrimSpace(os.Getenv(cloudBaseURLEnv)); v != "" {
		return v
	}
	if v := strings.TrimSpace(cfg.Cloud.BaseURL); v != "" {
		return v
	}
	return defaultCloudBaseURL
}

// cloudBaseURLSource names which D15 precedence layer resolveCloudBaseURL
// actually used, for status output — "built-in default" when nothing is set and
// the compiled default applies.
func cloudBaseURLSource(flagVal string, cfg config.Config) string {
	switch {
	case strings.TrimSpace(flagVal) != "":
		return "--base-url"
	case strings.TrimSpace(os.Getenv(cloudBaseURLEnv)) != "":
		// no-bare-usd:allow (the preview shows the exact bytes that would leave the machine)
		return "$" + cloudBaseURLEnv
	case strings.TrimSpace(cfg.Cloud.BaseURL) != "":
		return "[cloud].base_url"
	default:
		return "built-in default"
	}
}

// cloudBaseURLFlagUsage is the --base-url help text the `observer cloud` verbs
// share: what the flag is, then where the URL comes from when it is unset.
func cloudBaseURLFlagUsage(what string) string {
	return what + " (else $" + cloudBaseURLEnv + ", else [cloud].base_url)"
}

// cloudCredDir resolves the credential-store fallback directory (~/.observer),
// derived from the configured DB path so it tracks a custom --config.
func cloudCredDir(cfg config.Config) string {
	return filepath.Dir(cfg.Observer.DBPath)
}

// openCloudGateway builds the consent-gated egress seam. grants is the consent
// source: pass the store for anything that may touch the FEATURE lane, or nil
// for the bootstrap-only commands (`status`, `logout`, `delete-account`) that
// never send session- or window-derived data — a nil source makes every feature
// send fail closed rather than silently permissive.
//
// An empty baseURL is tolerated: the gateway still answers credential questions
// and can clear local state, and every network method refuses with
// ErrNoBaseURL. Commands that REQUIRE an endpoint call requireCloudBaseURL
// first, so the "pass --base-url" copy stays where the user can act on it.
//
// onTokenHealed (optional) is told when an expired API token was transparently
// re-exchanged through the persisted sign-in, so a command can say so.
func openCloudGateway(cfg config.Config, baseURL, devToken string, grants cloudgateway.GrantStore, onTokenHealed func()) (*cloudgateway.Gateway, error) {
	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:         grants,
		CredDir:        cloudCredDir(cfg),
		BaseURL:        baseURL,
		DevToken:       strings.TrimSpace(devToken),
		WorkOSClientID: resolveWorkOSClientID(cfg),
		OnTokenHealed:  onTokenHealed,
	})
	if err != nil {
		return nil, fmt.Errorf("build cloud gateway: %w", err)
	}
	return gw, nil
}

// cloudHostKey reduces a resolved base URL to the lowercase host the node's
// results-pull cursor is keyed by (see store.LoadCloudResultCursor): the
// hosted results sequence is per estate, so staging's cursor must never be
// replayed against production. An unparsable value is used verbatim.
func cloudHostKey(resolved string) string {
	u, err := url.Parse(strings.TrimSpace(resolved))
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimSpace(resolved))
	}
	return strings.ToLower(u.Host)
}

// cloudResetResultCursor clears the node's results-pull cursor after a
// sign-in, a sign-out or an account deletion (T-962). The hosted cursor
// ("v2:<n>") is a per-ACCOUNT sequence and the node cannot see which account
// a token belongs to, so a cursor kept across any of those events could skip
// the first n results of the next account (seen live: v2:13 against a fresh
// server). Clearing it makes the next sync pull from the beginning, which is
// idempotent (already-stored results update in place).
//
// allHosts clears every host's cursor (the full local wipe); otherwise only the
// host resolved names (an empty value selects the legacy bare key). It is
// best-effort: a database that cannot be opened prints one warning line and
// never fails the command, because signing out must always work.
func cloudResetResultCursor(ctx context.Context, w io.Writer, configPath, resolved string, allHosts bool) {
	_, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		fmt.Fprintf(w, "Warning: could not reset the results position (%v). The next sync may skip results until it is reset.\n", err)
		return
	}
	defer cleanup()
	st := store.New(database)
	if allHosts {
		err = st.ClearAllCloudResultCursors(ctx)
	} else {
		err = st.ClearCloudResultCursor(ctx, cloudHostKey(resolved))
	}
	if err != nil {
		fmt.Fprintf(w, "Warning: could not reset the results position (%v). The next sync may skip results until it is reset.\n", err)
	}
}

// requireCloudBaseURL returns the resolved base URL or the honest "how to set
// it" error. It is the one place that copy lives.
func requireCloudBaseURL(resolved string) error {
	if resolved == "" {
		return fmt.Errorf("no cloud base URL - pass --base-url, set %s, or set [cloud].base_url in config.toml", cloudBaseURLEnv)
	}
	return nil
}

// cloudPrintEnvelopeSummary prints the human-readable digest of what the bytes
// above actually contain: the structural signal, and — the part that matters
// most — EVERY excerpt verbatim, so a developer reads the exact post-scrub text
// that would leave the machine rather than having to find it inside the JSON.
func cloudPrintEnvelopeSummary(w io.Writer, res cloudEnvelopeResult) {
	if res.EvidenceSettingsJSON != "" {
		fmt.Fprintf(w, "evidence settings: %s\n", res.EvidenceSettingsJSON)
	}
	cloudPrintBudgetLine(w, res.Budget)
	env := res.Envelope
	if env == nil {
		return
	}
	fmt.Fprintln(w, "----")
	fmt.Fprintf(w, "duration:                %d s\n", env.DurationSeconds)
	if env.Metrics.ResolvedUsage() == cloudcontract.UsageNotMeasured {
		fmt.Fprintf(w, "metrics:                 tokens and cost not measured (no token usage captured for this session), error rate %.3f\n",
			env.Metrics.ErrorRate)
	} else {
		fmt.Fprintf(w, "metrics:                 tokens in %d / out %d, cache read %d, cost $%.4f, error rate %.3f\n",
			env.Metrics.TokensIn, env.Metrics.TokensOut, env.Metrics.CacheReadTokens,
			env.Metrics.CostUSD, env.Metrics.ErrorRate)
	}
	if len(env.ActivityMix) > 0 {
		parts := make([]string, 0, len(env.ActivityMix))
		for _, e := range env.ActivityMix {
			parts = append(parts, fmt.Sprintf("%s=%d", e.Key, e.Count))
		}
		fmt.Fprintf(w, "activity mix:            %s\n", strings.Join(parts, " "))
	}
	if len(env.Milestones) > 0 {
		parts := make([]string, 0, len(env.Milestones))
		for _, m := range env.Milestones {
			parts = append(parts, fmt.Sprintf("%s@%ds", m.Kind, m.ElapsedSeconds))
		}
		fmt.Fprintf(w, "milestones:              %s\n", strings.Join(parts, " "))
	}
	build := env.Outcomes.Build
	if build == "" {
		build = "(none observed)"
	}
	// The unknown counts are shown WITH the knowable ones, never folded into
	// them: a session whose suites all ran behind `|| true` reports "0/0 passed,
	// 4 runs unknowable", which is the truth, rather than a clean-looking zero.
	unknown := ""
	if env.Outcomes.TestsUnknown > 0 || env.Outcomes.BuildsUnknown > 0 {
		unknown = fmt.Sprintf(" (%d test / %d build run(s) had an unknowable outcome - the recorded exit status belonged to another segment of the same command line)",
			env.Outcomes.TestsUnknown, env.Outcomes.BuildsUnknown)
	}
	fmt.Fprintf(w, "outcomes:                tests %d/%d passed, build %s%s\n",
		env.Outcomes.TestsPassed, env.Outcomes.TestsRun, build, unknown)
	if env.Overflow != nil && env.Overflow.ActionsOmitted > 0 {
		fmt.Fprintf(w, "actions sampled:         %d kept, %d omitted (even stride across the whole session)\n",
			len(env.Actions), env.Overflow.ActionsOmitted)
	}
	if len(env.Context) == 0 {
		fmt.Fprintln(w, "excerpts:                none - this purpose uploads NO session content")
		return
	}
	fmt.Fprintf(w, "excerpts:                %d (post-scrub, exactly as they would upload)\n", len(env.Context))
	for i, c := range env.Context {
		fmt.Fprintf(w, "  [%d] %s (%d bytes, cap %d)\n", i+1, c.Source, len(c.Text), c.LengthCapBytes)
		for _, line := range strings.Split(c.Text, "\n") {
			fmt.Fprintf(w, "      %s\n", line)
		}
	}
}

// cloudConfirm reads a y/N line from r.
func cloudConfirm(r io.Reader, w io.Writer, prompt string) (bool, error) {
	fmt.Fprintf(w, "%s [y/N]: ", prompt)
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	ans := strings.ToLower(strings.TrimSpace(sc.Text()))
	return ans == "y" || ans == "yes", nil
}
