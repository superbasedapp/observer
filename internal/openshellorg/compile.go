package openshellorg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/sandboxopenshell"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The authoritative spec compile of the org-hosted row (g1-design.md sections
// 3.2 step 5 and 6.1, rule W2). It runs on the org server only: the mint
// records its result and digest on the ledger, the front creates exactly that
// spec, and the sync compares the box against it. The node's own compile is
// only a preview. The policy document comes from the existing pure compiler
// in internal/sandboxopenshell (imported read-only), with an EMPTY bind plan:
// no bind ever reaches a shared gateway. This file holds the none and
// proxy_only rows; the internet row arrives with lane G4 once its
// BlockedCIDRs hunk exists in netrules.go, and until then an internet run is
// refused internet_tier_not_built.

// SpecVersion is the recorded spec's schema version.
const SpecVersion = 1

// Box-side paths and the box user. They are the box's own paths (the box
// image's), never a laptop's: the compile never sees a developer path.
const (
	BoxHome      = "/home/sandbox"
	BoxWorkspace = "/sandbox/workspace"
	BoxRunDir    = "/sandbox/run"
	BoxUID       = 1000
	BoxGID       = 1000
)

// The fixed box files under BoxRunDir (G3-A2 with G4-A3): the clone's
// baseline commit the collect diffs against, and the agent session ids the
// node writes for a resume. This package is their one owner: the worker's
// collect and hold read them here, and the node writes them here.
const (
	BoxBaselineFile = BoxRunDir + "/baseline"
	BoxSessionsFile = BoxRunDir + "/sessions.json"
)

// KeeperArgv is the box's command: a plain shell keeper that holds the box
// open while execs run (section 3.2 step 5). It needs nothing uploaded, so a
// box whose observer binary arrives after the create (box_binary = upload)
// starts (G4 fix round 1, ruling A4; sh, exec and sleep are in every box
// image G-L2 checked).
var KeeperArgv = []string{"sh", "-c", "exec sleep infinity"}

// CloneArgv is the box-side clone of a clone-remote run (section 4.3,
// G1-R10): a plain git clone with "--" before the validated URL, into the
// box's fixed workspace. The one owner: the mint records it, the front
// compares the clone exec with it byte for byte, and the node sends exactly
// it as the run's first exec under a create token (G4 fix round 1, ruling
// A1). Plain git clone does not recurse submodules.
func CloneArgv(url string) []string {
	return []string{"git", "clone", "--", url, BoxWorkspace}
}

// CloneEnv is the clone exec's exact environment (ruling A1): no prompt,
// and nothing else.
func CloneEnv() map[string]string {
	return map[string]string{"GIT_TERMINAL_PROMPT": "0"}
}

// The run's label keys beyond the two sandboxopenshell owns.
const (
	LabelNode   = "observer.superbased.node"
	LabelMember = "observer.superbased.member"
)

// OrgSpec is the create spec the org compiled for one run. Every content
// field of a node's CreateSandbox is ignored by the front in favour of this.
type OrgSpec struct {
	Version   int    `json:"v"`
	Workspace string `json:"workspace"`
	BoxName   string `json:"box_name"`
	Image     string `json:"image"`
	// Labels are the label grammar, sorted by key.
	Labels    []sandboxopenshell.Label `json:"labels"`
	CPU       int                      `json:"cpu"`
	MemoryMiB int                      `json:"memory_mib"`
	Tier      Tier                     `json:"tier"`
	Source    Source                   `json:"source"`
	// PolicyYAML is the OpenShell policy document (empty bind plan).
	PolicyYAML string `json:"policy_yaml"`
	// Command is the in-box keeper; TTY is always false.
	Command []string `json:"command"`
	TTY     bool     `json:"tty"`
	Env     []string `json:"env"`
	// EgressHosts and CloneHosts are the narrowed inputs, recorded so a
	// resume can recompile under today's org values and compare.
	EgressHosts []string `json:"egress_hosts,omitempty"`
	CloneHosts  []string `json:"clone_hosts,omitempty"`
	// CloneURL is the validated clone URL of a clone-remote run;
	// GitProviderProfile names its repository provider row, if any.
	CloneURL           string `json:"clone_url,omitempty"`
	GitProviderProfile string `json:"git_provider_profile,omitempty"`
}

// CompileInput is what one org compile reads.
type CompileInput struct {
	OrgID    string
	RunID    string
	MemberID string
	NodeHash string
	Image    string
	Quotas   Quotas
	Narrowed Narrowed
	// AllowCIDRs and BlockedCIDRs are the org's own network ranges for the
	// internet tier (section 6.1): AllowCIDRs added back after the private
	// ranges are removed, BlockedCIDRs subtracted last. Never a node's list.
	AllowCIDRs, BlockedCIDRs []string
	// HostAddrs are the sandbox host's own addresses as the sync last read
	// them (never reachable from a box); nil when the gateway reports none.
	HostAddrs []netip.Addr
}

// HostAddrsOf turns the org's sandbox host entries into the compile's
// addresses (OB-085). An IP entry becomes a netip.Addr (an IPv4-mapped IPv6
// address is unmapped, as the host-local rule compares). A CIDR entry, an
// address with a zone, or anything else answers org_host_addrs_invalid:
// the compile takes single addresses only until it takes prefixes, and the
// list is deny-side, so dropping an entry would open the host. Only the
// internet tier reads the list (T5b and the compile), so the other tiers
// never see this refusal.
func HostAddrsOf(entries []string) ([]netip.Addr, Reason) {
	var out []netip.Addr
	for _, e := range entries {
		a, err := netip.ParseAddr(e)
		if err != nil || a.Zone() != "" {
			return nil, ReasonHostAddrsInvalid
		}
		out = append(out, a.Unmap())
	}
	return out, ReasonNone
}

// ErrCompile wraps every compile failure that is not a closed reason.
var ErrCompile = errors.New("openshellorg: org compile")

// shortHash is the first 16 hex characters of a domain-separated SHA-256.
func shortHash(domain, v string) string {
	sum := sha256.Sum256([]byte(domain + "\n" + v))
	return hex.EncodeToString(sum[:])[:16]
}

// compileRow is one row of the tier table.
type compileRow struct {
	Tier  Tier
	Built bool
	Vocab vocab.Tier
}

// compileTable says which tiers this build compiles. The internet row is
// lane G4's, built on the netrules.go BlockedCIDRs hunk.
var compileTable = []compileRow{
	{TierNone, true, vocab.TierNone},
	{TierProxyOnly, true, vocab.TierProxyOnly},
	{TierInternet, true, vocab.TierInternet},
}

// BoxObserverBinary is the in-box observer's path, under the run dir like
// every box-side file the node writes (OB-084): the program the internet
// tier's network rule names. The node's layout for the org row equals it (a
// test pins them).
const BoxObserverBinary = BoxRunDir + "/bin/observer"

// BoxGitBinary is the image's git, named by the network rule only when the
// run clones in the box (its git host is then on the rule from the start).
const BoxGitBinary = "/usr/bin/git"

// orgNetInput is the internet tier's network input (section 6.1): the
// narrowed egress hosts plus the validated clone host, an empty list
// compiling no host (every connection denied, never every host), the org's
// own allow and blocked ranges, the sandbox host's addresses, and the box
// programs that may connect. The node's own egress_allow_cidrs never reach
// it.
func orgNetInput(in CompileInput) sandboxopenshell.NetInput {
	hosts := append(append([]string(nil), in.Narrowed.EgressHosts...), in.Narrowed.CloneHosts...)
	bins := []string{BoxObserverBinary}
	if len(in.Narrowed.CloneHosts) > 0 {
		bins = append(bins, BoxGitBinary)
	}
	return sandboxopenshell.NetInput{
		Hosts: hosts, NoHost: len(hosts) == 0,
		AllowCIDRs: append([]string(nil), in.AllowCIDRs...), BlockedCIDRs: append([]string(nil), in.BlockedCIDRs...),
		HostAddrs: in.HostAddrs, Binaries: bins,
	}
}

// CompileOrgSpec compiles the run's create spec and its digest. It answers a
// closed reason (internet_tier_not_built) or an error for an input it cannot
// compile.
func CompileOrgSpec(in CompileInput) (OrgSpec, string, Reason, error) {
	var row *compileRow
	for i := range compileTable {
		if compileTable[i].Tier == in.Narrowed.Tier {
			row = &compileTable[i]
		}
	}
	if row == nil {
		return OrgSpec{}, "", ReasonInputWidensOrg, nil
	}
	if !row.Built {
		return OrgSpec{}, "", ReasonInternetTierNotBuilt, nil
	}
	var net sandboxopenshell.NetInput
	if row.Tier == TierInternet {
		// An internet run whose org named no internal ranges is refused, not
		// guessed (section 6.1).
		if len(in.BlockedCIDRs) == 0 {
			return OrgSpec{}, "", ReasonBlockedCIDRsMissing, nil
		}
		net = orgNetInput(in)
	}
	plan, err := sandboxopenshell.Compile(sandboxopenshell.Input{
		Net: net,
		// The home is the box's own directory on its writable layer, kept
		// across a hold (stop) and deleted with the box; the workspace and
		// the run dir are box-local writable paths, no binds (ruling A4).
		Settings:     sandboxopenshell.Settings{HomeMode: sandboxopenshell.HomeLayer, Egress: row.Vocab},
		BoxReadWrite: []string{BoxWorkspace, BoxRunDir},
		Home:         BoxHome,
		UID:          BoxUID,
		GID:          BoxGID,
		ObserverDir:  BoxHome + "/.observer",
		Scope:        sandboxopenshell.Scope{Workspace: BoxWorkspace, SocketDir: BoxRunDir},
	})
	if err != nil {
		return OrgSpec{}, "", "", fmt.Errorf("%w: %w", ErrCompile, err)
	}
	run, err := sandboxopenshell.EncodeID(in.RunID)
	if err != nil {
		return OrgSpec{}, "", "", fmt.Errorf("%w: %w", ErrCompile, err)
	}
	labels := []sandboxopenshell.Label{
		{Key: sandboxopenshell.LabelInstall, Value: "o" + shortHash("sbo-openshell-install-v1", in.OrgID) + "o"},
		{Key: LabelMember, Value: "o" + shortHash("sbo-openshell-member-v1", in.MemberID) + "o"},
		{Key: LabelNode, Value: "o" + shortHash("sbo-openshell-node-v1", in.NodeHash) + "o"},
		{Key: sandboxopenshell.LabelRun, Value: run},
	}
	sort.Slice(labels, func(i, j int) bool { return labels[i].Key < labels[j].Key })
	spec := OrgSpec{
		Version: SpecVersion, Workspace: WorkspaceName(in.MemberID), BoxName: BoxName(in.OrgID, in.RunID),
		Image: in.Image, Labels: labels, CPU: in.Quotas.BoxCPU, MemoryMiB: in.Quotas.BoxMemoryMiB,
		Tier: in.Narrowed.Tier, Source: in.Narrowed.Source, PolicyYAML: string(plan.PolicyYAML),
		Command: append([]string(nil), KeeperArgv...), Env: plan.Env,
		EgressHosts: in.Narrowed.EgressHosts, CloneHosts: in.Narrowed.CloneHosts, CloneURL: in.Narrowed.CloneURL,
	}
	if in.Narrowed.GitProvider != nil {
		spec.GitProviderProfile = in.Narrowed.GitProvider.ProviderProfile
	}
	d, err := SpecDigest(spec)
	if err != nil {
		return OrgSpec{}, "", "", err
	}
	return spec, d, ReasonNone, nil
}

// SpecDigest is the SHA-256 hex of the spec's canonical JSON. The box name
// and labels are part of it, so a resume compares the spec its box was made
// with.
func SpecDigest(s OrgSpec) (string, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrCompile, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// RecompileForResumeWith compiles a held box's recorded inputs again under
// today's org values (T7r's spec_changed_since_hold), over the whole compile
// input, so an internet box recompiles with today's org ranges (AllowCIDRs,
// BlockedCIDRs, HostAddrs). in.RunID is the box's run id. The box keeps its
// identity (box name, workspace and labels, including the node label of the
// node that created it), so only a change of the org's image, policy,
// resources or narrowed inputs changes the digest. An empty digest with a
// reason means the inputs no longer compile at all (for example the org
// dropped the run's tier), which T7r also reads as a changed spec. Its one
// caller is the mint; RecompileForResume, which dropped the ranges, is gone
// (RC1-A5).
func RecompileForResumeWith(rec OrgSpec, in CompileInput) (string, Reason, error) {
	spec, _, r, err := CompileOrgSpec(in)
	if err != nil || r != ReasonNone {
		return "", r, err
	}
	spec.BoxName, spec.Workspace = rec.BoxName, rec.Workspace
	spec.Labels = append([]sandboxopenshell.Label(nil), rec.Labels...)
	d, err := SpecDigest(spec)
	return d, ReasonNone, err
}
