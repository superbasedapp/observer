//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_hosted_delivery.go resolves a hosted launch's workspace
// source through the vendor row's Deliveries capability and
// workspace.DeliveryFor (lane G4, g1-design.md section 4.1), and decides a
// box-side clone's gates (lane CLONE): the remote-clone switch, the tier the
// box can reach the git host on, a non-empty host list and the URL. The
// probe (the dialog's source list) and the launch walk the same rules, so
// they can never disagree (TestHostedAcceptedSourcesMatchTheLaunch). The
// branch is on the delivery value and on capability flags, never on a
// vendor id.
//
// Lane CLONE2 (decision SBXD-5): the clone-remote source is one "Clone a
// remote URL", cloned in the box or on this machine as
// [terminal.sandbox.hosted].clone_where (or the launch's own choice while
// it is auto) and workspace.DecideCloneWhere say. A clone made on this
// machine (hostedHomeCloneRules: the same plan and URL validation the local
// rows' clone-remote uses, terminal_sandbox_hosted_homeclone.go) is an
// upload of that clone's tracked files, so it runs on every tier; a box
// clone stays internet-only (hostedDeliveryTiers).

// hostedDelivery is a launch's resolved workspace delivery.
type hostedDelivery struct {
	// Source and Delivery are the resolved values.
	Source   workspace.Source
	Delivery workspace.Delivery
	// CloneURL is the validated URL of a clone-remote launch: cloned in
	// the box for a remote_clone delivery, or on this machine for a home
	// clone (HomeClone, delivered as upload_snapshot); CloneBranch the work
	// branch made after the clone ("" for none).
	CloneURL, CloneBranch string
	// HomeClone: this machine clones CloneURL and uploads the clone's
	// tracked files (SBXD-5).
	HomeClone bool
	// Where and WhereReason are where a clone-remote launch clones and why
	// (a workspace.CloneWhereReasonText code); "" for every other source.
	Where       workspace.CloneWhere
	WhereReason string
}

// uploads reports whether the delivery uploads this machine's tree.
func (h hostedDelivery) uploads() bool { return h.Delivery != workspace.DeliveryRemoteClone }

// hostedSourceOrder is the closed workspace source vocabulary in the order
// a picker lists it.
var hostedSourceOrder = []workspace.Source{workspace.SourceLive, workspace.SourceCloneLocal, workspace.SourceCloneRemote, workspace.SourceWorktree}

// hostedRowModes is the row's declared deliveries; a row that declares none
// takes the live tree uploaded (the earlier rule).
func hostedRowModes(v sandboxremote.Vendor) []workspace.Delivery {
	if len(v.Deliveries) == 0 {
		return []workspace.Delivery{workspace.DeliveryUploadSnapshot}
	}
	modes := make([]workspace.Delivery, 0, len(v.Deliveries))
	for _, d := range v.Deliveries {
		modes = append(modes, workspace.Delivery(d))
	}
	return modes
}

// hostedDeliveryTier is one row of the tier x delivery table: whether a
// delivery runs on a tier ("" matches any delivery or any tier).
type hostedDeliveryTier struct {
	delivery workspace.Delivery
	tier     vocab.Tier
	runs     bool
}

// hostedDeliveryTiers is decided before Start, walked top-down, first match
// wins: a box-side clone reaches the git host over the box's own network,
// so it runs on the internet tier only (proxy_only routes only the model
// proxy and none routes nothing; neither is widened for a clone, the org
// mint's remote_clone_needs_egress rule); every upload runs on any tier
// the row offers.
var hostedDeliveryTiers = []hostedDeliveryTier{
	{workspace.DeliveryRemoteClone, vocab.TierInternet, true},
	{workspace.DeliveryRemoteClone, "", false},
	{"", "", true},
}

// hostedDeliveryRunsOn reports whether delivery d runs on tier t.
func hostedDeliveryRunsOn(d workspace.Delivery, t vocab.Tier) bool {
	for _, r := range hostedDeliveryTiers {
		if (r.delivery == "" || r.delivery == d) && (r.tier == "" || r.tier == t) {
			return r.runs
		}
	}
	return false
}

// hostedBoxCloneHTTPSOnly reports whether the row's box clones with no git
// credential at all, so only a public https:// address can clone: every row
// but one whose calls carry an organization-minted token (MintedCredential),
// whose organization may attach its own read-only credential for that one
// repository during the clone (g1-design 4.3).
func hostedBoxCloneHTTPSOnly(v sandboxremote.Vendor) bool { return !v.MintedCredential }

// hostedBoxCloneIsCore reports whether the row's box-side clone is the core
// clone (workspace.PlanBoxClone, run after the box's directories are made)
// rather than a clone argv the row's registration fixes (the org row's,
// sent as the run's first exec).
func hostedBoxCloneIsCore(v sandboxremote.Vendor) bool {
	return hostedVendorRegs[v.ID].cloneSpec == nil
}

// hostedHomeCloneOffered reports whether the row can take a clone made on
// this machine (SBXD-5): it uploads a tree (upload_snapshot) and its box
// clone is the core one, so an upload of the clone's files stands in for
// it. The org row's clone is its organization's own (with its own
// read-only credential) and its box takes no upload of that kind, so it
// clones in the box whatever clone_where says.
func hostedHomeCloneOffered(v sandboxremote.Vendor) bool {
	return hostedBoxCloneIsCore(v) && slices.Contains(hostedRowModes(v), workspace.DeliveryUploadSnapshot)
}

// hostedSourceInput is one source decision's input. checkURL is false for
// the probe, which judges every rule but the URL's. cloneWhere is the
// launch's own clone location ("" takes the config); ctx bounds the
// anonymous listing auto may run (nil: the background).
type hostedSourceInput struct {
	ctx         context.Context
	v           sandboxremote.Vendor
	src         workspace.Source
	tier        vocab.Tier
	cfg         config.TerminalSandboxConfig
	url, branch string
	root        string
	cloneWhere  string
	checkURL    bool
}

// hostedCloneRule is one gate of a box-side clone, walked top-down; the
// first that refuses wins; its refusal's Message is also the dialog's note
// for a source the row delivers but does not take now.
type hostedCloneRule struct {
	name    string
	refuses func(in hostedSourceInput) (bool, *dashapi.SandboxStepRefusal)
}

// hostedCloneSwitchRule is the remote-clone switch, the first gate of both
// ways (the box's and this machine's).
var hostedCloneSwitchRule = hostedCloneRule{"remote-clone-switch", func(in hostedSourceInput) (bool, *dashapi.SandboxStepRefusal) {
	// The dialog shows Message as the source's reason, so it names where the
	// switch is (the Allow remote clone checkbox of the Sandbox isolation card).
	return !in.cfg.AllowRemoteClone, &dashapi.SandboxStepRefusal{
		Code:      sandboxselect.VerdictSourceUnsupported,
		Message:   "Cloning a remote URL into a sandbox is switched off on this machine. Turn on Allow remote clone in Terminals > Settings > Sandbox isolation.",
		Technical: "the clone-remote source needs [terminal.sandbox].allow_remote_clone = true",
	}
}}

// hostedHomeCloneRules are a clone on this machine's gates (SBXD-5): the
// switch, then the local rows' own plan of a clone-remote (the same URL
// validation and host list, where an empty list allows any host because
// the clone runs on this machine), plus no credential in the URL (it is
// kept in the consent and run records, and this machine's own git login
// is what clones a private repository). Any tier: what reaches the box is
// an upload.
var hostedHomeCloneRules = []hostedCloneRule{
	hostedCloneSwitchRule,
	{"url", func(in hostedSourceInput) (bool, *dashapi.SandboxStepRefusal) {
		if !in.checkURL {
			return false, nil
		}
		err := workspace.ValidateHomeCloneURL(in.url, in.cfg.RemoteAllowedHosts)
		if err == nil {
			_, err = workspace.Plan(workspace.Request{
				Source: workspace.SourceCloneRemote, RemoteURL: in.url, Branch: in.branch, ManagedRoot: hostedHomeClonePlanRoot(),
				ID: "probe", AllowRemoteClone: true, RemoteAllowedHosts: in.cfg.RemoteAllowedHosts,
			})
		}
		if err == nil {
			return false, nil
		}
		return true, &dashapi.SandboxStepRefusal{
			Code:      "clone_url_invalid",
			Message:   "The remote URL cannot be cloned on this machine: name an https://, ssh:// or user@host:path address (on one of the git hosts you listed, when you listed any), with no password or token in it; your own git login signs in.",
			Technical: err.Error(),
		}
	}},
}

// hostedHomeClonePlanRoot is the stand-in managed root the URL gate plans
// against (the real one is the run's own, made at launch).
func hostedHomeClonePlanRoot() string { return filepath.Join(os.TempDir(), "observer-home-clone") }

// hostedCloneRules are a box-side clone's gates.
var hostedCloneRules = []hostedCloneRule{
	hostedCloneSwitchRule,
	{"tier", func(in hostedSourceInput) (bool, *dashapi.SandboxStepRefusal) {
		return !hostedDeliveryRunsOn(workspace.DeliveryRemoteClone, in.tier), &dashapi.SandboxStepRefusal{
			Code:      "remote_clone_needs_egress",
			Message:   "The box clones the repository itself, so it needs internet access, and the sandbox network setting gives it none (the model proxy only, or no network). Set the network to internet, or use a source this machine uploads.",
			Technical: fmt.Sprintf("a box-side clone (remote_clone) runs on the internet tier only; [terminal.sandbox].egress is %s", in.tier),
		}
	}},
	{"host-list", func(in hostedSourceInput) (bool, *dashapi.SandboxStepRefusal) {
		msg := "List the git hosts a box may clone from first (for example github.com): a box on a provider's machines clones only from hosts you name."
		if in.v.OrgEndpoint {
			msg = "Your organization has not named the git hosts its boxes may clone from."
		}
		return len(in.cfg.RemoteAllowedHosts) == 0, &dashapi.SandboxStepRefusal{
			Code:      "remote_clone_hosts_missing",
			Message:   msg,
			Technical: "[terminal.sandbox].remote_allowed_hosts is empty; a box-side clone never takes the empty list's any-host rule",
		}
	}},
	{"url", func(in hostedSourceInput) (bool, *dashapi.SandboxStepRefusal) {
		if !in.checkURL {
			return false, nil
		}
		err := workspace.ValidateBoxCloneURL(in.url, in.cfg.RemoteAllowedHosts, hostedBoxCloneHTTPSOnly(in.v))
		if err == nil && hostedBoxCloneIsCore(in.v) {
			// The core clone's whole plan (the box workspace path, the work
			// branch) is checked here too, so nothing in it fails in the box.
			_, err = workspace.PlanBoxClone(workspace.BoxCloneRequest{URL: in.url, Dest: in.v.Layout(in.root).Workspace, Branch: in.branch})
		}
		msg := "The remote URL cannot be cloned in the box: name a public https:// address on one of the git hosts you listed, with no user name or token in it."
		if !hostedBoxCloneHTTPSOnly(in.v) {
			msg = "The remote URL cannot be cloned in the box: name an address on one of your organization's git hosts, with no password or token in it."
		}
		if err == nil {
			return false, nil
		}
		return true, &dashapi.SandboxStepRefusal{Code: "clone_url_invalid", Message: msg, Technical: err.Error()}
	}},
}

// hostedDecideSource is the one decision both the probe and the launch walk.
func hostedDecideSource(in hostedSourceInput) (hostedDelivery, *dashapi.SandboxStepRefusal) {
	modes := hostedRowModes(in.v)
	d, err := workspace.DeliveryFor(in.src, modes)
	if err != nil {
		ref := &dashapi.SandboxStepRefusal{
			Code:      sandboxselect.VerdictSourceUnsupported,
			Message:   in.v.Name + " does not take this workspace source.",
			Technical: err.Error(),
		}
		if in.src == workspace.SourceLive {
			if _, cerr := workspace.DeliveryFor(workspace.SourceCloneLocal, modes); cerr == nil {
				ref.Message += " Choose the copy of the project instead: it uploads your tracked files."
				ref.Technical += "; use the clone-local source"
			}
		}
		return hostedDelivery{}, ref
	}
	out := hostedDelivery{Source: in.src, Delivery: d}
	if d != workspace.DeliveryRemoteClone {
		return out, nil
	}
	return hostedDecideClone(in, out)
}

// hostedFirstRefusal walks a gate table top-down: the first refusal, or nil.
func hostedFirstRefusal(rules []hostedCloneRule, in hostedSourceInput) *dashapi.SandboxStepRefusal {
	for _, r := range rules {
		if refused, ref := r.refuses(in); refused {
			return ref
		}
	}
	return nil
}

// hostedDecideClone decides where a clone-remote launch clones (SBXD-5):
// both ways' gates are walked, workspace.DecideCloneWhere picks the way
// (running the anonymous listing first when auto needs it, at launch only;
// the probe offers the source once either way can take it), and the chosen
// way's own refusal, if any, is the answer.
func hostedDecideClone(in hostedSourceInput, out hostedDelivery) (hostedDelivery, *dashapi.SandboxStepRefusal) {
	setting, ref := hostedCloneWhereSetting(in.cfg, in.cloneWhere)
	if ref != nil {
		return hostedDelivery{}, ref
	}
	homeCapable := hostedHomeCloneOffered(in.v)
	boxRef := hostedFirstRefusal(hostedCloneRules, in)
	var homeRef *dashapi.SandboxStepRefusal
	if homeCapable {
		homeRef = hostedFirstRefusal(hostedHomeCloneRules, in)
	}
	dw := workspace.CloneWhereInput{Setting: setting, HomeCapable: homeCapable, BoxOK: boxRef == nil, HomeOK: homeRef == nil}
	dec := workspace.DecideCloneWhere(dw)
	if dec.NeedsAnon {
		if !in.checkURL {
			// The dialog's list: the box can take it, so the source is
			// offered; the listing runs at launch.
			out.WhereReason = dec.Reason
			return out, nil
		}
		dw.Anon = hostedAnonAnswer(in.ctx, in.url)
		dec = workspace.DecideCloneWhere(dw)
	}
	out.Where, out.WhereReason = dec.Where, dec.Reason
	if dec.Where == workspace.CloneWhereHome {
		if homeRef != nil {
			return hostedDelivery{}, homeRef
		}
		// A clone made here reaches the box as an upload of its files.
		out.Delivery, out.HomeClone = workspace.DeliveryUploadSnapshot, true
		out.CloneURL, out.CloneBranch = in.url, in.branch
		return out, nil
	}
	if boxRef != nil {
		return hostedDelivery{}, boxRef
	}
	out.CloneURL = in.url
	if hostedBoxCloneIsCore(in.v) {
		out.CloneBranch = in.branch
	}
	return out, nil
}

// hostedCloneWhereSetting is the effective clone location of a launch: the
// config's (its default, auto, when unset), or the launch's own choice
// while the config leaves it to auto. A config that pins box or home (the
// developer's own value, or an organization's pin) is never moved by a
// launch: a different choice is refused, so the dialog and the launch say
// the same thing.
func hostedCloneWhereSetting(cfg config.TerminalSandboxConfig, launch string) (workspace.CloneWhere, *dashapi.SandboxStepRefusal) {
	set, err := workspace.ParseCloneWhere(cfg.Hosted.CloneWhere)
	if err != nil {
		set = workspace.CloneWhereAuto
	}
	if strings.TrimSpace(launch) == "" {
		return set, nil
	}
	l, err := workspace.ParseCloneWhere(launch)
	if err != nil {
		return "", &dashapi.SandboxStepRefusal{Code: "clone_where_invalid", Message: "Choose where to clone the repository: automatically, in the box or on this machine.", Technical: err.Error()}
	}
	if set != workspace.CloneWhereAuto && l != set {
		return "", &dashapi.SandboxStepRefusal{
			Code:      "clone_where_fixed",
			Message:   "Where the repository is cloned is set to " + hostedCloneWhereWords[set] + " in Terminals > Settings > Hosted sandboxes (or by your organization), so a launch cannot choose another place.",
			Technical: fmt.Sprintf("[terminal.sandbox.hosted].clone_where is %s; the launch asked for %s", set, l),
		}
	}
	return l, nil
}

// hostedCloneWhereWords names a clone location in plain words.
var hostedCloneWhereWords = map[workspace.CloneWhere]string{
	workspace.CloneWhereAuto: "automatic",
	workspace.CloneWhereBox:  "in the box",
	workspace.CloneWhereHome: "on this machine",
}

// hostedCloneWhereLine is the one line a clone-remote launch's dialog,
// terminal and consent screen say about where it clones and why.
func hostedCloneWhereLine(d hostedDelivery) string {
	words := hostedCloneWhereWords[d.Where]
	why := workspace.CloneWhereReasonText[d.WhereReason]
	switch {
	case words == "" && why == "":
		return ""
	case words == "":
		return why
	case why == "":
		return "cloned " + words
	}
	return "cloned " + words + ": " + why
}

// hostedCloneWhereRule is the consent screen's statement of the auto rule
// (decision SBXD-0: said once, so an auto answer that changes per launch
// needs no second agreement unless it changes what is sent).
const hostedCloneWhereRule = "Automatic clones a repository anyone can read inside the box, and any other on this machine with your git login, uploading its tracked files; the agreement names which of the two it covers, so the other asks again."

// hostedDefaultSource is the source of a launch that names none: the first
// one in picker order the row delivers that needs no URL (the vendor rows:
// the live tree uploaded; the org row: the local clone).
func hostedDefaultSource(v sandboxremote.Vendor) workspace.Source {
	modes := hostedRowModes(v)
	for _, s := range hostedSourceOrder {
		if d, err := workspace.DeliveryFor(s, modes); err == nil && d != workspace.DeliveryRemoteClone {
			return s
		}
	}
	return workspace.SourceLive
}

// hostedAcceptedSources lists the workspace sources hosted row id takes on
// tier under cfg, in picker order (ok false for a row that is not a hosted
// vendor's), so the New Terminal dialog offers only those before Start.
// notes says, in plain words, why a source the row delivers is not offered
// now (the remote-clone switch, the tier, the host list); a source the row
// never delivers has no note. The URL is judged at launch.
func hostedAcceptedSources(id string, tier vocab.Tier, cfg config.TerminalSandboxConfig) (srcs []string, notes map[string]string, ok bool) {
	v, ok := sandboxremote.VendorFor(id)
	if !ok {
		return nil, nil, false
	}
	srcs = []string{}
	modes := hostedRowModes(v)
	for _, s := range hostedSourceOrder {
		_, ref := hostedDecideSource(hostedSourceInput{v: v, src: s, tier: tier, cfg: cfg})
		if ref == nil {
			srcs = append(srcs, string(s))
			continue
		}
		if _, err := workspace.DeliveryFor(s, modes); err == nil {
			if notes == nil {
				notes = map[string]string{}
			}
			notes[string(s)] = ref.Message
		}
	}
	return srcs, notes, true
}

// hostedSourceDelivery resolves req's workspace source for vendor v on tier
// under the effective sandbox config cfg.
func hostedSourceDelivery(ctx context.Context, v sandboxremote.Vendor, req termsvc.PrepareRequest, tier vocab.Tier, cfg config.TerminalSandboxConfig) (hostedDelivery, error) {
	src := hostedDefaultSource(v)
	if s := strings.TrimSpace(req.WorkspaceSource); s != "" {
		parsed, err := workspace.ParseSource(s)
		if err != nil {
			return hostedDelivery{}, err
		}
		src = parsed
	}
	d, ref := hostedDecideSource(hostedSourceInput{
		ctx: ctx, v: v, src: src, tier: tier, cfg: cfg, root: req.ProjectRoot,
		url: strings.TrimSpace(req.WorkspaceRemote), branch: strings.TrimSpace(req.WorkspaceBranch), cloneWhere: req.WorkspaceCloneWhere, checkURL: true,
	})
	if ref != nil {
		return hostedDelivery{}, ref
	}
	return d, nil
}

// hostedSourceDeliveries maps each source hosted row id delivers to its
// delivery (a row with no Deliveries uploads the live tree:
// upload_snapshot), so the dialog labels and checks a source by how it
// reaches the box (items H5 and H8), never by the row id. A source the row
// delivers but does not take now (WorkspaceSourceNotes says why) is listed
// too, so its label reads the same while it is unavailable. ok false for a
// row that is not a hosted vendor's.
func hostedSourceDeliveries(id string) (map[string]string, bool) {
	v, ok := sandboxremote.VendorFor(id)
	if !ok {
		return nil, false
	}
	modes := hostedRowModes(v)
	out := map[string]string{}
	for _, s := range hostedSourceOrder {
		if d, err := workspace.DeliveryFor(s, modes); err == nil {
			out[string(s)] = string(d)
		}
	}
	return out, true
}
