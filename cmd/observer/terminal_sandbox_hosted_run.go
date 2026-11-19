//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxkey"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/termrun"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_hosted_run.go is the daemon side of a hosted run (lane
// SBX-P7): Create checks everything that can be checked without the vendor
// (the floors, the local probe, the tier, the custody, the tool delivery,
// the upload manifest, the consent and the spend cap) and refuses by name;
// Attach writes the run record and a plan file and returns the PTY child's
// argv. The PTY child (`observer sandbox-hosted-host`, terminal_sandbox_
// hosted_host.go) is the only process that reads the credential and calls
// the vendor, and only for this user-launched run (I6).

// The hosted driver's helper verbs and markers.
const (
	hostedHostVerb    = "sandbox-hosted-host"
	hostedInnerMarker = "observer-hosted-inner"
	hostedPlanVersion = 1
)

// The hosted launch refusals (copy keys a surface renders).
const (
	verdictHostedConsentRequired = sandboxselect.VerdictConsentRequired
	verdictHostedCustody         = sandboxselect.VerdictCustodyUnsatisfiable
	verdictHostedTool            = sandboxselect.VerdictToolUnavailableInImage
)

// hostedPlanFile is the per-run plan the host helper reads. It holds no
// secret by rule (TestHostedPlanFileHoldsNoSecrets): the credential is read
// by the helper at use time.
type hostedPlanFile struct {
	Version  int    `json:"version"`
	RunID    string `json:"run_id"`
	Provider string `json:"provider"`
	Endpoint string `json:"endpoint"`
	// EndpointSPKISHA256 is the endpoint's server key pin ("" for none):
	// the credential must have been connected with it (SBX-GOV-4).
	EndpointSPKISHA256 string `json:"endpoint_spki_sha256,omitempty"`
	Region             string `json:"region"`
	Template           string `json:"template"`
	Tier               string `json:"tier"`
	Custody            string `json:"custody"`
	// TimeoutMinutes is the vendor timeout (the spend cap's answer).
	TimeoutMinutes int `json:"timeout_minutes"`
	// Root is the host workspace; Files the manifest the user consented to
	// (re-listed and compared by the helper before upload).
	Root     string                       `json:"root"`
	ScopeKey string                       `json:"scope_key"`
	Files    []sandboxremote.ManifestFile `json:"files"`
	// UploadListing is how the helper re-lists Root before the upload (a
	// folder that is not a repository, decision SBXD-8): the same listing
	// the consent was given for, so the scope keys agree.
	UploadListing hostedUploadListing `json:"upload_listing,omitzero"`
	// BoxBinary is the host path of the in-box observer to upload.
	BoxBinary string `json:"box_binary"`
	// BoxBinaryInImage: the box image carries the in-box observer at the
	// layout's binary path (the row's published box_binary = "image"), so
	// nothing is uploaded and the box only checks its version.
	BoxBinaryInImage bool `json:"box_binary_in_image,omitempty"`
	// ToolStateRel are the tool's HOME-relative state dirs (pulled at each
	// checkpoint and at teardown).
	ToolStateRel []string `json:"tool_state_rel"`
	// ToolInstalls are the install ways the tool may use at first start, in
	// order (only on the internet tier with no template; empty otherwise):
	// the host helper checks the box for each one's programs before the
	// workspace is uploaded and runs the first that fits (lane UX, H4).
	ToolInstalls []sandboxremote.InstallChoice `json:"tool_installs,omitempty"`
	// ToolInstall is the single install argv a plan written before
	// ToolInstalls carries; read only when ToolInstalls is empty.
	ToolInstall []string `json:"tool_install,omitempty"`
	// ForwardEnv are the provider API-key variable names copied into the
	// box (custody in_box_api_key only; values are read by the helper).
	ForwardEnv []string `json:"forward_env,omitempty"`
	// CustodySetting and CustodyRule record how Custody was reached
	// (decision SBXD-1): the configured value for the tool ("auto", or an
	// explicit one) and the resolution row (sandboxkey.CustodyRule*).
	// Custody itself is always the resolved custody the helper runs with.
	CustodySetting string `json:"custody_setting,omitempty"`
	CustodyRule    string `json:"custody_rule,omitempty"`
	// ToolKeys and LoginSeed are the opt-in in-box key sources of decision
	// SBXD-4 for this run's tool (only under in_box_api_key custody, and
	// only where the tool's registry row grounds the file): the helper
	// reads the tool's own saved keys, or seeds its login's access token.
	ToolKeys          bool `json:"tool_keys,omitempty"`
	LoginSeed         bool `json:"login_seed,omitempty"`
	CheckpointMinutes int  `json:"checkpoint_minutes"`
	DailyBoxMinutes   int  `json:"daily_box_minutes"`
	// DBExport is [terminal.sandbox.hosted].db_export (opt-in, ruling
	// P-141): the teardown exports the box's SQLite stores only when set.
	// RetentionDays is [terminal.sandbox].workspace_retention_days, the
	// horizon the teardown sweeps earlier runs' copies by (0 keeps them).
	DBExport      bool   `json:"db_export,omitempty"`
	RetentionDays int    `json:"retention_days,omitempty"`
	ObserverDir   string `json:"observer_dir"`
	Tool          string `json:"tool"`
	// Source, Delivery and CloneURL are the launch's resolved workspace
	// delivery (lane G4: a vendor with Deliveries; "" sync on the others).
	// A remote_clone run uploads nothing and clones CloneURL in the box.
	Source   string `json:"source,omitempty"`
	Delivery string `json:"delivery,omitempty"`
	CloneURL string `json:"clone_url,omitempty"`
	// CloneBranch is the work branch a core box-side clone makes in the box
	// after the clone (the launch's workspace branch; "" for none).
	CloneBranch string `json:"clone_branch,omitempty"`
	// CloneWhere and CloneWhereReason are where a clone-remote launch
	// clones (box or home) and why (a workspace.CloneWhereReasonText
	// code; decision SBXD-5). HomeCloneDir is the clone this machine made
	// for a home clone (Delivery upload_snapshot): the helper uploads its
	// tracked files, then removes it.
	CloneWhere       string `json:"clone_where,omitempty"`
	CloneWhereReason string `json:"clone_where_reason,omitempty"`
	HomeCloneDir     string `json:"home_clone_dir,omitempty"`
	// ResumeBoxRunID names the held box a resume launch takes over (the
	// org-hosted row's resume, design 3.6); "" for a fresh box.
	ResumeBoxRunID string `json:"resume_box_run_id,omitempty"`

	// DiffAgainst is [terminal.sandbox.hosted].diff_against: what an upload
	// run's saved diff is taken against ("baseline", the default and what
	// "" means, or "head").
	DiffAgainst string `json:"diff_against,omitempty"`
	// DenyCIDRs are the ranges the create asks the vendor to refuse (the
	// private-range deny of the internet tier, decision SBXD-7; the same
	// answer the consent bound).
	DenyCIDRs []string `json:"deny_cidrs,omitempty"`
	// GuardHooks: the box gets guard's hook registration for the tool
	// ([terminal.sandbox.hosted].guard_hooks resolved at launch, lane HOOKS;
	// terminal_sandbox_hosted_guardhooks.go).
	GuardHooks bool `json:"guard_hooks,omitempty"`
}

// hostedForwardEnvNames are the provider API-key variables an
// in_box_api_key run copies into the box when the launch environment holds
// them, derived from the one provider table (sandboxkey.InBoxKeyEnv: plain
// API keys only, never a key file path, a login or a refresh token; gap
// H3, which also added XAI_API_KEY). Where the environment has none, the
// host helper fills a variable from a key the person stored
// (hostedCredInBoxKeysHook), for the providers the tool can use.
var hostedForwardEnvNames = sandboxkey.InBoxKeyEnv()

// hostedChoice is what Create decided for Attach.
type hostedChoice struct {
	plan hostedPlanFile
}

// hostedChoices holds each created run's choice until Attach.
var hostedChoices sync.Map

// hostedTier is the egress tier of a hosted run (the resolved profile's).
func (d *hostedDriver) tier() vocab.Tier {
	t := vocab.Tier(d.r.egress.Mode)
	if t == "" {
		t = vocab.TierInternet
	}
	return t
}

// floor refuses a launch the local config or an org floor does not allow
// on this row.
func (d *hostedDriver) floor(cfg config.TerminalSandboxConfig, tier vocab.Tier, custody vocab.KeyCustody, region string) error {
	row, _ := sandboxbackend.Get(d.vendor.ID)
	if cfg.PinnedNoBackend != "" {
		return fmt.Errorf("terminal_sandbox: your organization's pin of %s allows none of the sandbox backends this machine is set to use, so no backend is enabled; the sandboxed terminal is refused, never run without it", cfg.PinnedNoBackend)
	}
	if !slices.Contains(sandboxEnabledBackends(cfg), d.vendor.ID) {
		return fmt.Errorf("terminal_sandbox: %s is not in [terminal.sandbox].backends %v; a hosted sandbox is used only when listed", d.vendor.ID, cfg.Backends)
	}
	if floor := vocab.IsoClass(cfg.MinIsolation); floor != "" && row.Iso.Class.Rank() < floor.Rank() {
		return fmt.Errorf("terminal_sandbox: %s builds %s isolation, below [terminal.sandbox].min_isolation = %s", d.vendor.ID, row.Iso.Class, floor)
	}
	if !row.OffersTier(tier) {
		return fmt.Errorf("terminal_sandbox: %s: %s has no %s network tier (a hosted box cannot use the host network); set [terminal.sandbox].egress to internet, proxy_only or none", sandboxselect.VerdictEgressUnsupported, d.vendor.Name, tier)
	}
	// A host allow-list cannot be honoured by a hosted box (the LEFT-SBX
	// merge, audit finding 4): its egress is the vendor's, block-all or
	// allow-all, never Observer's gateway. On the internet tier it would
	// reach every host, so while the list (or an org pin that left no host
	// in common) is set, the launch is refused naming the key; proxy_only
	// and none block the box's own egress and are unaffected.
	if key := hostedEgressHostsKey(cfg); key != "" && tier == vocab.TierInternet {
		return fmt.Errorf("terminal_sandbox: %s: %s is set, and %s's box egress on the internet tier is the vendor's own and reaches every host, so it cannot honour a host list; use the proxy_only or none tier with this row, or a local row whose gateway applies the list", sandboxselect.VerdictEgressUnsupported, key, d.vendor.Name)
	}
	floors := sandboxOrgFloors()
	in := sandboxselect.Input{
		Request: sandboxselect.Request{Backend: row.ID, Tier: tier, Interactive: true, Custody: custody, Region: region, AcceptReducedCapture: true, ProviderDirect: cfg.EffectiveProviderDirect()},
		Host:    sandboxHostKind(), Floors: floors,
		// Consent is checked on its own, with the fact that changed named
		// (Create); here only the org's floors decide.
		Probes: map[string]sandboxselect.Probe{row.ID: {ConsentRecorded: true}},
		Tool:   sandboxselect.Tool{Mapped: true, ProxyRouted: true, CredentialInReach: hostedCredentialInReach(custody)},
	}
	if drop, dropped := sandboxselect.FloorDrop(row, in, true); dropped {
		return sandboxRefusalError{msg: isolationFloorMessage(drop)}
	}
	return nil
}

// hostedEgressHostsKey names the setting that asks for a host allow-list
// on the agent's egress: the org pin that left no host in common
// (PinnedNoEgressHost), else [terminal.sandbox].egress_allow_hosts when it
// lists any host; "" when neither is set.
func hostedEgressHostsKey(cfg config.TerminalSandboxConfig) string {
	if cfg.PinnedNoEgressHost != "" {
		return "your organization's pin of " + cfg.PinnedNoEgressHost + " (no host in common with this machine's list)"
	}
	if len(cfg.EgressAllowHosts) > 0 {
		return "[terminal.sandbox].egress_allow_hosts"
	}
	return ""
}

// hostedToolDelivery decides how the agent tool reaches the box (SBX-IMG-1,
// orchestrator default; lane UX, item H4): no agent CLI is uploaded; a
// template the user named holds it, or, on the internet tier only, it
// installs from its vendor at first start through one of its grounded
// install ways that the vendor's default image is not known to break
// (sandboxremote.PlanToolInstall, the one rule the probe's per-row tool
// notice also walks). The answer is the ordered install choices (none when
// a template holds the tool); the host helper picks the first one the box
// can run before the workspace is uploaded. A refusal is a typed one with
// the plain sentence apart from the technical detail.
func hostedToolDelivery(tool, template string, tier vocab.Tier, v sandboxremote.Vendor) ([]sandboxremote.InstallChoice, error) {
	p := hostedToolPlan(tool, template, tier, v)
	if p.OK {
		return p.Choices, nil
	}
	return nil, &dashapi.SandboxStepRefusal{Code: verdictHostedTool, Message: p.Message, Technical: p.Code + ": " + p.Technical}
}

// hostedToolPlan is PlanToolInstall for tool on vendor v (an empty tier is
// the hosted default, internet).
func hostedToolPlan(tool, template string, tier vocab.Tier, v sandboxremote.Vendor) sandboxremote.ToolInstallPlan {
	if tier == "" {
		tier = vocab.TierInternet
	}
	return sandboxremote.PlanToolInstall(sandboxremote.ToolInstallInput{
		ToolName: integration.DisplayName(tool), Vendor: v, Template: template, Tier: tier, Options: hostedInstallOptions(tool),
	})
}

// hostedInstallOptions are the tool's grounded Linux install rows from the
// integration registry, in the registry's order (the pure package decides
// which of them run in a box).
func hostedInstallOptions(tool string) []sandboxremote.InstallOption {
	spec, ok := integration.For(tool)
	if !ok || spec.Binary == nil {
		return nil
	}
	var out []sandboxremote.InstallOption
	for _, h := range spec.Binary.Installs {
		if h.OS == "" || h.OS == "linux" {
			out = append(out, sandboxremote.InstallOption{Channel: h.Channel, Argv: append([]string(nil), h.Argv...), Requires: append([]string(nil), h.Requires...)})
		}
	}
	return out
}

// hostedToolNotices are the probe row's per-tool notices for hosted row id
// (lane UX, item H4): every sandbox-launchable tool whose launch on the row
// would be refused by hostedToolDelivery at the configured tier, with the
// same sentence. Nil for a row that is not a hosted vendor's, or when none
// would be.
func hostedToolNotices(id string, cfg config.TerminalSandboxConfig, tier vocab.Tier) map[string]dashapi.SandboxKeyNotice {
	v, ok := sandboxremote.VendorFor(id)
	if !ok {
		return nil
	}
	template := hostedVendorConfig(cfg.Hosted, id).Template
	var out map[string]dashapi.SandboxKeyNotice
	for _, c := range integration.Capabilities() {
		if !integration.TerminalLaunchable(c) || len(c.Sandbox.StateRW) == 0 {
			continue
		}
		p := hostedToolPlan(c.Tool, template, tier, v)
		if p.OK {
			continue
		}
		if out == nil {
			out = map[string]dashapi.SandboxKeyNotice{}
		}
		out[c.Tool] = dashapi.SandboxKeyNotice{Code: p.Code, Message: p.Message, Technical: verdictHostedTool + ": " + p.Technical, Place: settingslink.TerminalSandboxHosted}
	}
	return out
}

// hostedRepoTop is git's top level of the working tree at root (the hardened
// read-only git envelope); ok false when root is not in a repository.
func hostedRepoTop(ctx context.Context, root string) (string, bool) {
	top, _, err := gitview.RunReadOnlyEnv(ctx, root, 4096, 20*time.Second, extrun.GitHardeningEnv(""), "rev-parse", "--show-toplevel")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(top)), true
}

// hostedListWorkspace lists the upload candidates: git's tracked plus
// untracked-not-ignored files under root (the hardened read-only git
// envelope), each lstat'd, never followed.
var hostedListWorkspace = func(ctx context.Context, root string) ([]sandboxremote.Candidate, bool, error) {
	t, ok := hostedRepoTop(ctx, root)
	if !ok {
		return nil, false, nil
	}
	if filepath.Clean(t) != filepath.Clean(root) {
		return nil, false, fmt.Errorf("terminal_sandbox: the workspace %s is inside the repository %s; launch from the repository root to upload it", root, t)
	}
	out, over, err := gitview.RunReadOnlyEnv(ctx, root, 64<<20, 60*time.Second, extrun.GitHardeningEnv(""), "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	if err != nil {
		return nil, true, fmt.Errorf("terminal_sandbox: list the workspace files: %w", err)
	}
	if over {
		return nil, true, fmt.Errorf("terminal_sandbox: %w: the workspace file list is over 64 MiB", sandboxremote.ErrScopeTooLarge)
	}
	return hostedCandidates(root, out), true, nil
}

// hostedCandidates turns git's NUL-separated listing of paths under root
// into upload candidates, each lstat'd, never followed (shared by the
// repository listing and the non-repository one).
func hostedCandidates(root string, out []byte) []sandboxremote.Candidate {
	var cands []sandboxremote.Candidate
	seen := map[string]bool{}
	for _, p := range bytes.Split(out, []byte{0}) {
		rel := string(p)
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		c := sandboxremote.Candidate{Path: rel, Kind: sandboxremote.KindOther}
		if fi, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil { //nolint:gosec // G703: rel is a path git listed under root; it is only lstat'd (never followed or read here), and PlanManifest excludes any path outside root
			switch {
			case fi.Mode()&fs.ModeSymlink != 0:
				c.Kind = sandboxremote.KindSymlink
			case fi.Mode().IsRegular():
				c.Kind, c.Size = sandboxremote.KindRegular, fi.Size()
			case fi.IsDir():
				c.Kind = sandboxremote.KindDir
			}
		}
		cands = append(cands, c)
	}
	return cands
}

// hostedManifest plans the upload of root.
func (d *hostedDriver) manifest(ctx context.Context, root string) (sandboxremote.Manifest, error) {
	home, _ := os.UserHomeDir()
	if h, err := filepath.EvalSymlinks(home); err == nil {
		home = h
	}
	return hostedPlanUpload(ctx, root, filepath.ToSlash(home), hostedUploadListingFor(d.cfg))
}

// launchFacts are the consent facts of one launch.
func (d *hostedDriver) launchFacts(tier vocab.Tier, m sandboxremote.Manifest) (sandboxremote.ConsentFacts, bool) {
	f, ok := d.consentFactsStatic()
	f.Tier, f.Capture, f.ScopeKey = string(tier), hostedConsentCapture(d.vendor.ID, tier, vocab.KeyCustody(d.cfg.KeyCustody)), m.ScopeKey
	f.PrivateRanges = hostedPrivateRangesFact(d.vendor, d.cfg, tier)
	return f, ok
}

// hostedConsentCapture is the capture level the consent screen states: the
// level the row, tier and custody compute for a proxy-routed agent (a run
// whose tool is not routed records its own, lower level in its evidence).
// Under auto (decision SBXD-1) it states both answers when they differ:
// the level with the key on this machine and the level with it in the box,
// so the consent does not change with the tool a launch runs.
func hostedConsentCapture(id string, tier vocab.Tier, custody vocab.KeyCustody) string {
	if custody == vocab.CustodyAuto {
		row := hostedRow(id)
		if hostedRowRefusesInBox(row) {
			return hostedConsentCapture(id, tier, vocab.CustodyHomeRelay)
		}
		home := hostedConsentCapture(id, tier, vocab.CustodyHomeRelay)
		box := hostedConsentCapture(id, tier, vocab.CustodyInBoxAPIKey)
		if home == box {
			return home
		}
		return home + " when the key stays on this machine, " + box + " when it is in the box"
	}
	return sandboxselect.CaptureLabel(hostedRunCapture(id, tier, custody, true))
}

// hostedLaunchCustody resolves the custody one launch of tool runs with
// (sandboxkey.HomeKey, the one owner: the probe line, the setup step and
// the dialog read the same table) and returns the verdict too, so the
// launch refuses with its plain words.
func (d *hostedDriver) hostedLaunchCustody(tool string) (vocab.KeyCustody, sandboxkey.HomeKeyVerdict, sandboxkey.HomeKeyFacts) {
	tf := hostedToolKeyFacts(d.homeKeyFacts(), d.cfg, tool)
	v := sandboxkey.HomeKey(tf)
	return vocab.KeyCustody(v.Resolution.Custody), v, tf
}

// Create runs every check the vendor is not needed for and records the
// run's plan for Attach. Nothing here reads a credential value or calls the
// vendor.
func (d *hostedDriver) Create(ctx context.Context, req termsvc.PrepareRequest) (termsvc.CreateResult, error) {
	tier := d.tier()
	// The custody this launch runs with (decision SBXD-1): auto or the
	// tool's own value resolved for this tool; an explicit node value as
	// set. Every step below reads the resolved one.
	custody, keyVerdict, keyFacts := d.hostedLaunchCustody(req.Tool)
	pc := hostedVendorConfig(d.cfg, d.vendor.ID)
	region, endpoint, ok := hostedResolve(d.vendor, pc)
	if !ok {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s: %s", verdictHostedRegionUnknown, hostedResolveRefusal(d.vendor, pc))
	}
	if err := d.floor(launchFloorConfig(d.r.cfg, string(tier)), tier, custody, region); err != nil {
		return termsvc.CreateResult{}, err
	}
	// The model key's custody for this tool (S7d), before the probe so its
	// refusal is the typed one with plain words, and before any workspace
	// is prepared or any box made.
	if !keyVerdict.OK {
		return termsvc.CreateResult{}, &dashapi.SandboxStepRefusal{Code: verdictHostedCustody, Message: keyVerdict.Message, Technical: keyVerdict.Code + ": " + keyVerdict.Technical}
	}
	if p := d.probe(ctx); p.Verdict != sandboxselect.VerdictAvailable {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %s is not available: %s: %s", d.vendor.ID, p.Verdict, p.Reason)
	}
	install, err := hostedToolDelivery(req.Tool, pc.Template, tier, d.vendor)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	spec, _ := integration.For(req.Tool)
	if len(spec.Sandbox.StateRW) == 0 {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: tool %q is not sandbox-launchable: %s", req.Tool, spec.Sandbox.Note)
	}
	delivery, err := hostedSourceDelivery(ctx, d.vendor, req, tier, d.r.cfg)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	var m sandboxremote.Manifest
	switch {
	case delivery.HomeClone:
		// A clone made here (SBXD-5): the consent is for that URL's
		// clone, whose files are listed once it exists (below).
		m = sandboxremote.Manifest{Root: req.ProjectRoot, ScopeKey: hostedCloneScope(delivery)}
	case delivery.uploads():
		if m, err = d.manifest(ctx, req.ProjectRoot); err != nil {
			return termsvc.CreateResult{}, err
		}
	default:
		// A box-side clone uploads nothing from this machine.
		m = sandboxremote.Manifest{Root: req.ProjectRoot, ScopeKey: hostedCloneScope(delivery)}
	}
	routed, _ := d.r.launchRouted(req.Tool, req.ProjectRoot, req.ToolArgs)
	capture := hostedRunCapture(d.vendor.ID, tier, custody, routed)
	facts, _ := d.launchFacts(tier, m)
	if v := sandboxremote.CheckConsent(hostedLoadConsent(d.r.observerDir, d.vendor.ID), facts); v != sandboxremote.ConsentOK {
		// A typed refusal (same words as before): the dashboard answers it
		// with a 409 naming the row and the verdict, so the New Terminal
		// dialog shows the consent again instead of this sentence.
		return termsvc.CreateResult{}, &dashapi.SandboxConsentRefusal{Provider: d.vendor.ID, Verdict: v}
	}
	minutes, err := sandboxremote.PlanTimeout(d.maxRunMinutes(), d.cfg.DailyBoxMinutes, hostedLedgerUsed(d.r.observerDir, d.vendor.ID, d.now(), d.cfg.DailyBoxMinutes))
	if err != nil {
		return termsvc.CreateResult{}, fmt.Errorf("terminal_sandbox: %w", err)
	}
	minutes = hostedBoxMinutes(d.vendor, minutes)
	// The host side never clones for a hosted row: an upload sends the
	// tree as consented, and a remote_clone delivery clones in the box.
	wsReq := req
	wsReq.WorkspaceSource, wsReq.WorkspaceRemote = "", ""
	ws, err := d.r.prepareWorkspace(ctx, wsReq)
	if err != nil {
		return termsvc.CreateResult{}, err
	}
	// A clone made here (SBXD-5) runs now, after the consent and the spend
	// check and before any box is made, with this machine's own git login.
	var home hostedHomeCloneResult
	if delivery.HomeClone {
		if home, err = d.homeClone(ctx, ws.id, delivery); err != nil {
			return termsvc.CreateResult{}, err
		}
		m.Files, m.Count, m.Bytes, m.Excluded = home.Manifest.Files, home.Manifest.Count, home.Manifest.Bytes, home.Manifest.Excluded
	}
	var forward []string
	inBox := custody == vocab.CustodyInBoxAPIKey
	if inBox {
		forward = hostedForwardEnvNames
	}
	plan := hostedPlanFile{
		Version: hostedPlanVersion, RunID: ws.id, Provider: d.vendor.ID, Endpoint: endpoint, EndpointSPKISHA256: pc.EndpointSPKISHA256, Region: region,
		Template: pc.Template, Tier: string(tier), Custody: string(custody), TimeoutMinutes: minutes,
		Root: m.Root, ScopeKey: m.ScopeKey, Files: m.Files, UploadListing: hostedUploadListingFor(d.cfg), BoxBinary: hostedBoxBinaryPath(pc, d.r.observerBin), BoxBinaryInImage: pc.BoxBinaryInImage,
		ToolStateRel: spec.Sandbox.StateRW, ToolInstalls: install, ForwardEnv: forward,
		CustodySetting: sandboxkey.CustodySetting(keyFacts), CustodyRule: keyVerdict.Resolution.Rule,
		ToolKeys: inBox && keyFacts.ToolSavedKeys, LoginSeed: inBox && keyFacts.LoginSeed,
		CheckpointMinutes: d.cfg.CheckpointMinutes, DailyBoxMinutes: d.cfg.DailyBoxMinutes, ObserverDir: d.r.observerDir, Tool: req.Tool,
		DBExport: d.cfg.DBExport, RetentionDays: d.r.cfg.WorkspaceRetentionDays, DiffAgainst: d.cfg.DiffAgainst,
		DenyCIDRs: hostedRangeDeny(d.vendor, d.cfg, tier).CIDRs,
		Source:    string(delivery.Source), Delivery: string(delivery.Delivery), CloneURL: delivery.CloneURL, CloneBranch: delivery.CloneBranch,
	}
	plan.GuardHooks = hostedGuardHooksFor(req.Tool, d.cfg, hostedGuardEnforcing).Seed
	plan.CloneWhere, plan.CloneWhereReason, plan.HomeCloneDir = string(delivery.Where), delivery.WhereReason, home.Dir
	if d.reg.resumeBox != nil {
		// A resume launch takes over a held box (the row's resume, design
		// 3.6): a new run id here, the box's own run id in the mint.
		plan.ResumeBoxRunID = d.reg.resumeBox()
	}
	hostedChoices.Store(ws.id, hostedChoice{plan: plan})
	iso := termrun.Isolation{
		Class: string(hostedRow(d.vendor.ID).Iso.Class), Stack: []string{d.vendor.ID}, EgressTier: string(tier),
		CaptureLevel: string(capture.Level), CaptureRule: capture.Rule,
		CaptureOrigin: string(vocab.OriginRemoteSandbox), KeyCustody: string(custody),
	}
	if v, ok := hostedRow(d.vendor.ID).VerificationOn(sandboxHostKind()); ok {
		iso.Verification = string(v.Kind)
	}
	return termsvc.CreateResult{
		Run: termsvc.SandboxRun{ID: ws.id, Tool: req.Tool, Dir: ws.dir, ProjectRoot: req.ProjectRoot, Copy: !ws.live},
		Note: fmt.Sprintf("sandbox: backend=%s region=%s egress=%s capture=%s upload=%s timeout=%dm",
			d.vendor.ID, region, tier, sandboxselect.CaptureLabel(capture), m.Summary(), minutes),
		Isolation: iso, ProxyRouted: routed,
	}, nil
}

// hostedRow returns a hosted registry row.
func hostedRow(id string) sandboxbackend.Capability {
	row, _ := sandboxbackend.Get(id)
	return row
}

// hostedRunCapture is the computed capture of a hosted run.
func hostedRunCapture(id string, tier vocab.Tier, custody vocab.KeyCustody, routed bool) sandboxselect.CaptureResult {
	return sandboxselect.ComputeCapture(sandboxselect.CaptureInput{
		Row: hostedRow(id), Tier: tier, Custody: custody,
		ProxyRouted: routed, CredentialInReach: hostedCredentialInReach(custody),
	})
}

// hostedPathInput is what the box-path class table reads.
type hostedPathInput struct {
	vendor     sandboxremote.Vendor
	runDir     string   // the run's directory on this machine
	quarantine string   // the run's quarantine directory (the transcript pull's)
	stateRel   []string // the tool's HOME-relative state dirs, in the pull's order
}

// hostedPathClass is one class of box path a relayed hook payload may name,
// and the directory on this machine the relay serves it from.
type hostedPathClass struct {
	class string
	rows  func(hostedPathInput) []sandboxrelayd.PathPrefix
}

// hostedPathClasses is the box-path class table of a hosted run, walked in
// order (FX4 item 3, live L3-07). The relay rewrites a payload's working
// directory and file keys through the rows before any binding check or
// confined read (sandboxrelayd pathmap.go), so a box path is never a root
// on this machine, and a path under no row is left as written and refused
// path_outside_run, as any other path outside the run (fail closed):
//
//   - the workspace: the box's own fixed workspace is the run's directory
//     (G4-R2). A working directory may name it (sandboxrelayd runDirs);
//   - the agent's state: each of the tool's HOME-relative state dirs in the
//     box's agent home (Claude Code's ~/.claude, where its transcript_path
//     points) is the matching directory of the run's quarantine, where the
//     transcript pull copies it (<quarantine>/<index>, the pull's LocalRel
//     root). Only a FILE key may name it: a working directory there is
//     still refused, because the binding's working-directory rule reads the
//     run's workspace and project only. The rest of the agent home (any
//     other dot directory, the home itself) has no row.
//
// Before FX4 the agent-state class had no row, so a committed project hook
// in an org box was refused for its transcript_path and Claude Code turned
// the refusal into a failed tool call.
var hostedPathClasses = []hostedPathClass{
	{class: "workspace", rows: func(in hostedPathInput) []sandboxrelayd.PathPrefix {
		if in.vendor.BoxWorkspace == "" {
			return nil // a same-path vendor: the box's workspace is the run's own path
		}
		return []sandboxrelayd.PathPrefix{{Box: in.vendor.BoxWorkspace, Host: in.runDir}}
	}},
	{class: "agent state", rows: func(in hostedPathInput) []sandboxrelayd.PathPrefix {
		if in.vendor.BoxHome == "" || in.quarantine == "" {
			return nil
		}
		var out []sandboxrelayd.PathPrefix
		for i, rel := range in.stateRel {
			box := path.Join(in.vendor.BoxHome, filepath.ToSlash(rel))
			if box == in.vendor.BoxHome || !strings.HasPrefix(box, in.vendor.BoxHome+"/") {
				continue // never the home itself, never outside it
			}
			out = append(out, sandboxrelayd.PathPrefix{Box: box, Host: filepath.Join(in.quarantine, strconv.Itoa(i))})
		}
		return out
	}},
}

// hostedPathMap is the run record's box-to-host path map: the rows of every
// class in hostedPathClasses.
func hostedPathMap(in hostedPathInput) []sandboxrelayd.PathPrefix {
	var out []sandboxrelayd.PathPrefix
	for _, c := range hostedPathClasses {
		out = append(out, c.rows(in)...)
	}
	return out
}

// hostedBoxBinaryPath is the host path of the in-box observer.
func hostedBoxBinaryPath(pc config.TerminalSandboxHostedProviderConfig, observerBin string) string {
	if b := strings.TrimSpace(pc.BoxBinary); b != "" {
		return b
	}
	return observerBin
}

// Attach writes the run record and the plan file, and returns the helper
// argv the PTY child runs.
func (d *hostedDriver) Attach(_ context.Context, created termsvc.CreateResult) (termsvc.AttachResult, error) {
	v, ok := hostedChoices.LoadAndDelete(created.Run.ID)
	if !ok {
		return termsvc.AttachResult{}, fmt.Errorf("terminal_sandbox: run %s has no hosted plan (Create did not run)", created.Run.ID)
	}
	plan := v.(hostedChoice).plan
	// The agent-state rows name the directories the transcript pull writes
	// (the plan's run id, observer dir and state dirs, as the pull reads them).
	pm := hostedPathMap(hostedPathInput{
		vendor: d.vendor, runDir: created.Run.Dir,
		quarantine: hostedQuarantineDir(plan.ObserverDir, plan.RunID), stateRel: plan.ToolStateRel,
	})
	if err := d.r.writeRemoteRunRecord(created.Run, pm); err != nil {
		return termsvc.AttachResult{}, err
	}
	netReq := sandbox.NetRequest{Egress: hostedHostEgress(vocab.Tier(plan.Tier)), ProxyPort: d.r.proxyPort}
	netReq.HostSocketDir = filepath.Join(os.TempDir(), "observer-sbx-"+created.Run.ID)
	host, err := sandbox.RelayHostArgv(d.r.observerBin, netReq, nil, sandbox.RelayRequest{RunID: created.Run.ID, HostObserverDir: d.r.observerDir})
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	planPath, err := writeHostedPlan(d.r.observerDir, plan)
	if err != nil {
		_ = sandboxrelayd.RemoveRun(d.r.observerDir, created.Run.ID)
		return termsvc.AttachResult{}, err
	}
	d.r.unattached.Delete(created.Run.ID)
	wrap := []string{d.r.observerBin, hostedHostVerb, "--plan", planPath, "--"}
	wrap = append(wrap, host...)
	return termsvc.AttachResult{WrapArgv: append(wrap, hostedInnerMarker)}, nil
}

// hostedHostEgress is the tier the HOME side builds for a hosted run: the
// relay always, the model proxy forward unless the tier is none. The box's
// own egress is the vendor's (block-all or allow-all); Observer's gateway is
// never used for a hosted box.
func hostedHostEgress(t vocab.Tier) sandbox.Egress {
	if t == vocab.TierNone {
		return sandbox.Egress(vocab.TierNone)
	}
	return sandbox.Egress(vocab.TierProxyOnly)
}

// Resize is owned by the PTY: the host helper passes the terminal's size
// to the vendor (E2B's Update) or to the guest helper's control stream.
func (d *hostedDriver) Resize(context.Context, termsvc.SandboxRun, uint16, uint16) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: d.vendor.ID + ": the host helper passes the terminal's size to the box"}, nil
}

// Signal is owned by the PTY.
func (d *hostedDriver) Signal(context.Context, termsvc.SandboxRun, string) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: d.vendor.ID + ": the host helper forwards what the terminal sends"}, nil
}

// Copy is not offered: the workspace was uploaded and changes come back
// through the staged-diff step.
func (d *hostedDriver) Copy(context.Context, termsvc.CopyRequest) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: d.vendor.ID + ": no copy; the box's changes come back as a staged diff"}, nil
}

// Checkpoint: Observer never snapshots a hosted box; the transcript pull on
// the checkpoint timer is the host helper's.
func (d *hostedDriver) Checkpoint(context.Context, termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictNotSupported, Detail: d.vendor.ID + ": Observer never snapshots or pauses a hosted box; transcripts are pulled on the checkpoint timer"}, nil
}

// Stop is owned by the PTY: closing the terminal hangs up the helper, which
// pulls, deletes and confirms.
func (d *hostedDriver) Stop(context.Context, termsvc.SandboxRun, time.Duration) (termsvc.LifecycleResult, error) {
	return termsvc.LifecycleResult{Verdict: termsvc.VerdictPTYOwned, Detail: d.vendor.ID + ": closing the terminal pulls the transcripts and deletes the box"}, nil
}

// Destroy releases a run that never started (no box was created: Attach
// makes none).
func (d *hostedDriver) Destroy(_ context.Context, run termsvc.SandboxRun) (termsvc.LifecycleResult, error) {
	hostedChoices.Delete(run.ID)
	_ = os.Remove(hostedPlanPath(d.r.observerDir, run.ID))
	return d.r.destroyBwrap(run)
}

// hostedPlanPath is a run's plan file.
func hostedPlanPath(observerDir, runID string) string {
	return filepath.Join(hostedStateDir(observerDir), "plans", runID+".json")
}

// writeHostedPlan writes a run's plan file (0600).
func writeHostedPlan(observerDir string, plan hostedPlanFile) (string, error) {
	p := hostedPlanPath(observerDir, plan.RunID)
	if err := hostedWriteOwned(p, plan); err != nil {
		return "", fmt.Errorf("terminal_sandbox: write the hosted plan: %w", err)
	}
	return p, nil
}

// readHostedPlan reads a plan file (owner-only, capped) and removes it.
func readHostedPlan(p string) (hostedPlanFile, error) {
	b, err := hostedReadOwned(p)
	_ = os.Remove(p) //nolint:gosec // G703: the plan file path the launch wrote under the state dir
	if err != nil {
		return hostedPlanFile{}, err
	}
	var plan hostedPlanFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&plan); err != nil {
		return hostedPlanFile{}, fmt.Errorf("hosted plan: %w", err)
	}
	if plan.Version != hostedPlanVersion {
		return hostedPlanFile{}, fmt.Errorf("hosted plan: version %d, this binary reads %d (restart the daemon after an upgrade)", plan.Version, hostedPlanVersion)
	}
	if _, ok := sandboxremote.VendorFor(plan.Provider); !ok || !path.IsAbs(plan.Root) {
		return hostedPlanFile{}, errors.New("hosted plan: bad provider or root")
	}
	return plan, nil
}

// hostedBoxMinutes caps a planned box timeout at the shortest plan cap the
// vendor documents (S13: Vercel Hobby 45 minutes, E2B Hobby 60). The
// account's plan is never read from the vendor, so a create never asks for
// more than the smallest account may allow.
func hostedBoxMinutes(v sandboxremote.Vendor, planned int) int {
	if lc := v.MinLifetimeMinutes(); lc > 0 && planned > lc {
		return lc
	}
	return planned
}

// maxRunMinutes is the box's run cap: the local max_run_minutes, lowered by
// the vendor's own cap when its registration names one (fix round 1, A8:
// the organization's max_run_minutes); it never raises the local cap.
func (d *hostedDriver) maxRunMinutes() int {
	m := d.cfg.MaxRunMinutes
	if d.reg.runCap != nil {
		if c := d.reg.runCap(d); c > 0 && c < m {
			m = c
		}
	}
	return m
}
