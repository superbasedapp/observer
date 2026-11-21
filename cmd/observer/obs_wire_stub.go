package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/alertspec"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	otlpingest "github.com/marmutapp/superbased-observer/internal/ingest/otlp"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
	"github.com/marmutapp/superbased-observer/internal/selfobs/emit"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// obsAdmissionHandle is the no_obs-build stub of the shared admission carrier
// (gap P0-7). It has no fields — admission (and all of internal/obs) is
// compiled out — but the type must exist so buildProxy's return signature and
// proxy.go/start.go compile identically in both builds.
type obsAdmissionHandle struct{}

// obsPolicyStateFacts mirrors the !no_obs definition so policystate_wire.go
// (non-build-tagged) compiles in the no_obs build (R3-S5). Admission (and all
// of internal/obs) is compiled out here, so PolicyStateFacts always reports
// Live=false with empty hashes → both local points resolve to none/no_policy.
type obsPolicyStateFacts struct {
	Live         bool
	AdmitterHash string
	AdmitterMode string
	EgressHash   string
	EgressMode   string
	LastSeen     time.Time

	AdmitterHasOrgRail  bool
	AdmitterOrgKey      string
	AdmitterGeneration  int64
	AdmitterOrgVersion  int64
	AdmitterBodyHash    string
	AdmitterInertReason string

	EgressHasOrgRail  bool
	EgressOrgKey      string
	EgressGeneration  int64
	EgressOrgVersion  int64
	EgressBodyHash    string
	EgressInertReason string
}

// PolicyStateFacts is the no_obs stub of the P0-6 local-point state reader: no
// admission service exists, so it returns the zero value (Live=false). ctx is
// accepted for signature parity with the !no_obs build and ignored.
func (h *obsAdmissionHandle) PolicyStateFacts(_ context.Context) obsPolicyStateFacts {
	return obsPolicyStateFacts{}
}

// PublishOrgAdmission / ClearOrgAdmission / PublishOrgEgress / ClearOrgEgress
// are no-ops in the no_obs build (Phase W poller/LKG signature parity) —
// admission (and all of internal/obs) is compiled out here, so there is no
// Org layer to publish into or clear.
func (h *obsAdmissionHandle) PublishOrgAdmission(_ string, _, _ int64, _, _ string, _, _ bool, _ any) {
}

func (h *obsAdmissionHandle) ClearOrgAdmission() {}

func (h *obsAdmissionHandle) PublishOrgEgress(_ string, _, _ int64, _, _ string, _, _ bool, _ any) {}

func (h *obsAdmissionHandle) ClearOrgEgress() {}

// LiveCapabilities advertises nothing in the no_obs build: there is no
// admission runtime here, so every judge-requiring org policy correctly stays
// capability_mismatch (fail-closed).
func (h *obsAdmissionHandle) LiveCapabilities() []string { return nil }

// wireAdmission is a no-op in the no_obs build — admission lives inside the
// observability subsystem, which is compiled out here. It returns a nil handle
// to match the !no_obs signature. The relay parameter (C1 judge relay,
// docs/plans/c1-judge-relay-spec-2026-08-15.md §3) is accepted for signature
// parity with the !no_obs build and ignored — there is no judge to relay to.
//
// The stub binds nothing onto the proxy: obs_wire_proxy.go (the proxy half
// of the real wiring) is not linked, so proxy.go reads obsProxyBinder as nil
// and this file stays free of internal/proxy. That is what lets the public
// tree, where this file is the only obs variant, build without capture.proxy
// too (lane MP-L1L, T-715, ruling D-518).
func wireAdmission(_ context.Context, cfg config.Config, _ *sql.DB, _ orgJudgeRelayFunc, logger *slog.Logger, _ emit.Sink) *obsAdmissionHandle {
	// D-514 / D-516: an [observability.admission] block this build cannot
	// honour starts off with the feasibility seam's one line.
	if line, off := settingOffLine("observability.admission.enabled", cfg.Observability.Admission.Enabled, nil); off && logger != nil {
		logger.Warn("admission: " + line)
	}
	return nil
}

// errObsCompiledOut is returned by the eval CLI wrappers in the no_obs build:
// the whole observability subsystem (incl. the eval plane) is compiled out.
var errObsCompiledOut = errors.New("this binary was built without observability (AI Apps compiled out) - the eval plane is unavailable")

// Plain eval shapes the (non-build-tagged) eval command references. Mirror the
// !no_obs definitions so the command file compiles in both builds.
type obsDatasetInfo struct {
	ID          int64
	Name        string
	Description string
	CreatedAt   string
	ItemCount   int64
}

type obsEvalSummary struct {
	RunID     int64
	Total     int
	Passed    int
	MeanScore float64
	PassRate  float64
}

func obsEvalEnabled(_ config.Config) bool { return false }

func obsEvalScorerNames() []string { return nil }

func obsEvalCreateDatasetFromTraces(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _, _ string, _ int) (int64, int, error) {
	return 0, 0, errObsCompiledOut
}

func obsEvalListDatasets(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger) ([]obsDatasetInfo, error) {
	return nil, errObsCompiledOut
}

func obsEvalRun(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ string, _ []string, _, _, _ string, _ float64) (obsEvalSummary, error) {
	return obsEvalSummary{}, errObsCompiledOut
}

// newObsTraceHandler is the no-op stub for the no_obs build: the generalized
// observability subsystem (internal/obs) is compiled out of the binary
// entirely (decision D2). Nothing here imports internal/obs, and /v1/traces is
// never served for Plane A.
//
// No silent loss (W0-4, F06): a config that turns [observability] on in a
// build without it gets one WARN naming the edition, and `observer doctor`
// shows the same as the observability.build row (obsBuildDoctorCheck).
func newObsTraceHandler(_ context.Context, cfg config.Config, _ *sql.DB, logger *slog.Logger) otlpingest.TraceHandler {
	if cfg.Observability.Enabled && logger != nil {
		logger.Warn(obsNotCompiledMessage(), "edition", obsEditionLabel(), "remedy", obsNotCompiledRemedy)
	}
	return nil
}

// obsBuildDoctorCheck is the no_obs half of the observability.build doctor
// row: WARN when [observability] is enabled in a build that cannot run it.
func obsBuildDoctorCheck(cfg config.Config) diag.Check {
	if !cfg.Observability.Enabled {
		return diag.Check{
			Name:    obsBuildCheckName,
			Status:  diag.StatusOK,
			Message: "AI Apps observability is not in this " + obsEditionLabel() + " build and [observability] is off",
		}
	}
	return diag.Check{
		Name:    obsBuildCheckName,
		Status:  diag.StatusWarn,
		Message: obsNotCompiledMessage(),
		Details: []string{
			"no AI Apps trace receiver, no obs_* tables: SDK and OTLP app spans sent to this machine are not stored",
			obsNotCompiledRemedy,
		},
	}
}

// obsDashboardRoutes is the no_obs stub: no obs trajectory endpoints exist. The
// shared-admission-handle parameter (gap P0-7) is accepted for signature parity
// and ignored.
func obsDashboardRoutes(_ context.Context, _ config.Config, _ string, _ *sql.DB, _ *obsAdmissionHandle, _ *slog.Logger) []dashapi.ExtraRoute {
	return nil
}

// obsHotDashboardRoutes is the no_obs stub of the hot-enable route set: no
// obs route exists.
func obsHotDashboardRoutes(_ context.Context, _ config.Config, _ string, _ *sql.DB, _ *obsAdmissionHandle, _ bool, _ *slog.Logger) []dashapi.ExtraRoute {
	return nil
}

// obsRoutePatterns is the no_obs stub: no obs route exists, so the hot-enable
// gate registers nothing (obs_wire_apps.go).
func obsRoutePatterns() []string { return nil }

// obsRouteCapability / obsRouteSection are the no_obs stubs of the route
// classifiers the hot-enable gate reads; with no patterns they are never
// consulted.
func obsRouteCapability(string) dashapi.Capability { return dashapi.CapabilityView }

func obsRouteSection(string) dashapi.Section { return dashapi.SectionNone }

// newObsLatestTraceReader is the no_obs stub: there is no obs store.
func newObsLatestTraceReader(context.Context, *sql.DB) (func(context.Context) (*planechoice.LatestTrace, error), error) {
	return nil, errors.New(obsNotCompiledMessage())
}

// obsOrgProviders is the no_obs stub: the org-tier observability provider seam
// is empty (every tier no-ops; obs is compiled out).
func obsOrgProviders(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger) store.ObsOrgProviders {
	return store.ObsOrgProviders{}
}

// Plain admission shapes the (non-build-tagged) admission command references.
// Mirror the !no_obs definitions so the command file compiles in both builds.
type obsAdmissionStatusInfo struct {
	Enabled       bool
	Mode          string
	JudgeHosting  string
	CriteriaCount int
	PolicyHash    string
	Decisions24h  map[string]int
	ChainRows     int
	ChainOK       bool
}

type obsAdmissionTestResult struct {
	Disabled        bool
	Decision        string
	Severity        string
	Criterion       string
	Reason          string
	Degraded        string
	JudgeUsed       bool
	EnforceDecision string
	LatencyMS       int
}

func obsAdmissionStatusCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger) (obsAdmissionStatusInfo, error) {
	return obsAdmissionStatusInfo{Mode: "off", Decisions24h: map[string]int{}}, errObsCompiledOut
}

type obsBudgetSpender struct {
	User     string
	FiveHour float64
	Weekly   float64
	Monthly  float64
}

type obsAdmissionBudgetStatus struct {
	Enabled     bool
	FiveHourUSD float64
	WeeklyUSD   float64
	MonthlyUSD  float64
	UserHeader  string
	Breaches24h int
	TopSpenders []obsBudgetSpender
}

func obsAdmissionBudgetStatusCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ int) (obsAdmissionBudgetStatus, error) {
	return obsAdmissionBudgetStatus{}, errObsCompiledOut
}

func obsAdmissionTestCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ string) (obsAdmissionTestResult, error) {
	return obsAdmissionTestResult{Disabled: true}, errObsCompiledOut
}

func obsAdmissionLintCLI(_ config.Config) (issues []string, fatal bool) {
	return nil, false
}

// Plain setup-wizard shapes + wrappers for the no_obs build.
type obsAdmissionTemplate struct {
	Key          string
	Title        string
	Description  string
	NeedsPurpose bool
	NeedsTopics  bool
}

type obsAdmissionProbeJudgeResult struct {
	Hosting   string
	Model     string
	Off       bool
	OK        bool
	LatencyMS int64
	Err       string
}

func obsAdmissionStarterTemplates() []obsAdmissionTemplate { return nil }

func obsAdmissionRenderTemplate(_, _ string, _ []string) (config.AdmissionCriterionConfig, bool) {
	return config.AdmissionCriterionConfig{}, false
}

func obsAdmissionProbeJudge(_ context.Context, _ config.Config) obsAdmissionProbeJudgeResult {
	return obsAdmissionProbeJudgeResult{Off: true}
}

type obsAdmissionSimulateResult struct {
	Disabled     bool
	Replayed     int
	PolicyHash   string
	JudgeCalls   int
	WouldBlock   int
	Decisions    map[string]int
	PerCriterion map[string]int
}

func obsAdmissionSimulateCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ int) (obsAdmissionSimulateResult, error) {
	return obsAdmissionSimulateResult{Disabled: true, Decisions: map[string]int{}, PerCriterion: map[string]int{}}, errObsCompiledOut
}

// obsAdmissionDoctorChecks is a no-op in the no_obs build — the admission
// health checks live inside the observability subsystem, compiled out here.
func obsAdmissionDoctorChecks(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger) []diag.Check {
	return nil
}

// Plain calibration shapes the (non-build-tagged) admission command references.
type obsCalibrateProbe struct {
	Label     string
	Decision  string
	JudgeUsed bool
	Degraded  string
	LatencyMS int
}

type obsAdmissionCalibrateResult struct {
	Off       bool
	Reason    string
	Model     string
	Hosting   string
	TargetMS  int64
	Probes    int
	P50MS     int
	P95MS     int
	MaxMS     int
	Degraded  int
	JudgeUsed int
	Decisions map[string]int
	PerProbe  []obsCalibrateProbe
	Recommend bool
	Verdict   string
}

func obsAdmissionCalibrateCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ string, _ int64) (obsAdmissionCalibrateResult, error) {
	return obsAdmissionCalibrateResult{Off: true, Decisions: map[string]int{}}, errObsCompiledOut
}

// --- node-side obs alerting stubs (gap-audit item #9). The evaluator loop +
// CLI live in obs_alerts.go (non-tagged); these plain shapes + no-op wrappers
// mirror the !no_obs definitions so it compiles in the no_obs build. ---

type obsFiredAlert struct {
	RuleName      string
	Metric        string
	Comparator    string
	Threshold     float64
	Value         float64
	WindowMinutes int
	Delivered     bool
	FiredAt       time.Time
	Dimensions    alertspec.Dimensions
}

type obsAlertRuleStatus struct {
	Name            string
	Metric          string
	Comparator      string
	Threshold       float64
	WindowMinutes   int
	CooldownMinutes int
	CurrentValue    float64
	Breaching       bool
	LastFired       time.Time
}

type obsAlertsStatus struct {
	Enabled           bool
	WebhookConfigured bool
	IntervalMinutes   int
	Rules             []obsAlertRuleStatus
	Recent            []obsFiredAlert
}

// obsAlertsRuntimeEnabled is always false in the no_obs build — the whole
// observability subsystem (incl. alerting) is compiled out, so the evaluator
// loop returns immediately.
func obsAlertsRuntimeEnabled(_ config.Config) bool { return false }

func obsEvaluateAlertsOnce(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger) ([]obsFiredAlert, error) {
	return nil, nil
}

// obsAlertTransitions is a no-op in a build without obs (lane C9).
func obsAlertTransitions(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ time.Time) ([]obsClearedAlert, map[string]string, error) {
	return nil, nil, nil
}

// obsSettleAlertResolves is a no-op in a build without obs (R-C20): nothing
// is owed there.
func obsSettleAlertResolves(_ context.Context, _ *sql.DB, _ []obsResolveAttempt, _ *slog.Logger) {}

func obsRecordAlert(_ context.Context, _ *sql.DB, _ obsFiredAlert, _ bool) error {
	return errObsCompiledOut
}

// newBenchmarkEvalScoreFn is nil in the no_obs build: the obs-eval registry is
// compiled out, so the Benchmarks Harness's registry-backed scorers
// (contains/regex/llm_judge/…) report unavailable. The benchmark-only
// tests_pass scorer is unaffected (it needs no obs).
func newBenchmarkEvalScoreFn(_ config.Config) evalScoreFn { return nil }

func obsAlertsStatusCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ int) (obsAlertsStatus, error) {
	return obsAlertsStatus{}, errObsCompiledOut
}

// --- G22 Plane-A egress-routing CLI stubs (`observer obs egress`). Plain
// shapes + no-op wrappers mirroring the !no_obs definitions so obs_egress.go
// compiles in the no_obs build (obs is compiled out). ---

type obsEgressTargetInfo struct {
	ID    string
	URL   string
	Shape string
}

type obsEgressRuleInfo struct {
	Name          string
	Action        string
	ReasonCode    string
	OnUnavailable string
}

type obsEgressDecisionRow struct {
	TS              string
	Mode            string
	RuleName        string
	Action          string
	ReasonCode      string
	UpstreamID      string
	ModelFrom       string
	ModelTo         string
	Effort          string
	MustUseTarget   bool
	Applied         bool
	FailClosed      bool
	SwitchHeld      bool
	RealizedOutcome string
	VerdictDecision string
	RequestID       string
	User            string
}

type obsEgressStatus struct {
	Enabled     bool
	Mode        string
	PolicyHash  string
	CompileErr  string
	Targets     []obsEgressTargetInfo
	Rules       []obsEgressRuleInfo
	Counts      map[string]int
	Recent      []obsEgressDecisionRow
	ChainRows   int
	ChainOK     bool
	ChainDetail string
}

func obsEgressStatusCLI(_ context.Context, _ config.Config, _ *sql.DB, _ *slog.Logger, _ int) (obsEgressStatus, error) {
	return obsEgressStatus{Mode: "off", Counts: map[string]int{}}, errObsCompiledOut
}

func obsEgressLintCLI(_ config.Config) (issues []string, fatal bool) {
	return nil, false
}

// obsNotCompiledRemedy says what to do about an [observability] section in a
// build that cannot honour it.
const obsNotCompiledRemedy = "install the developer or full edition (scripts/install.sh --edition developer), or set [observability].enabled = false"

// obsNotCompiledMessage is the one sentence a no-obs build logs and shows in
// doctor when [observability] is enabled.
func obsNotCompiledMessage() string {
	return fmt.Sprintf("observability: [observability].enabled = true, but this %s build does not include AI Apps observability; nothing is served or stored for it", obsEditionLabel())
}
