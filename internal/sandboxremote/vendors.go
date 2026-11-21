package sandboxremote

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// vendors.go is the per-vendor table (sandbox plan v2 sections 7.1, 7.2 and
// 5.7, lane SBX-P7). Every fact is grounded in the vendor's public
// documentation, read 2026-10-22; the docs/sandboxed-terminals.md endpoint
// tables name the page per call. A fact the docs do not state is written
// down as such (Unverified) and never used to claim more.

// The vendor ids. They equal the registry row ids (VendorRow maps them).
const (
	VendorE2B    = "e2b"
	VendorModal  = "modal"
	VendorVercel = "vercel-sandbox"
	// VendorOpenShellOrg is the org-hosted OpenShell gateway (tracker F-019,
	// lane G4): its "vendor" is the organization's own gateway, reached
	// through the org's validating front, which the org publishes in its
	// signed managed sandbox body.
	VendorOpenShellOrg = "openshell-org"
	// VendorDockerSandboxes is Docker's cloud sandboxes (Docker Agentic
	// Platform, the Sandboxes API at connect.docker.com; lane SBX-DOCKER).
	VendorDockerSandboxes = "docker-sandboxes"
	// VendorInstaBox is InstaBox (instabox.sh): a Linux VM per box, reached
	// over its REST API and its terminal WebSocket.
	VendorInstaBox = "instabox"
	// VendorDaytona is Daytona Cloud (daytona.io), a hosted vendor:
	// REST plus its SSH access tokens through the pure-Go SSH transport
	// (sandbox plan v2's Daytona row), never its AGPL Go SDK.
	VendorDaytona = "daytona"
)

// RegionKind says how a vendor places a box.
type RegionKind string

// The closed RegionKind vocabulary.
const (
	// RegionByEndpoint: each region is its own deployment, chosen by the API
	// endpoint (E2B); a credential belongs to one region.
	RegionByEndpoint RegionKind = "by_endpoint"
	// RegionSelectable: the create request names the region.
	RegionSelectable RegionKind = "selectable"
)

// ProviderChosen is the region a run records when the vendor picks it and
// nothing pins it (an org allowed_regions floor refuses it, S7b).
const ProviderChosen = "provider chosen"

// Regions is a vendor's region model.
type Regions struct {
	Kind RegionKind
	// Default is the region used when none is configured; ProviderChosen
	// when the vendor does not document one.
	Default string
	// Known are the region names the docs list.
	Known []string
	// Endpoints maps a region to its API origin (RegionByEndpoint only).
	Endpoints map[string]string
	// Docs maps every Known region to the vendor page that grounds it. A
	// region with no page is not listed: a by-endpoint region sends the
	// stored credential to its endpoint, so an ungrounded one could send a
	// key to a host nobody checked (TestVendorRegionsGrounded).
	Docs map[string]string
}

// regionDocs maps each region to one grounding page.
func regionDocs(doc string, regions ...string) map[string]string {
	out := make(map[string]string, len(regions))
	for _, r := range regions {
		out[r] = doc
	}
	return out
}

// TierMapping is how a vendor builds one egress tier, or that it cannot.
type TierMapping struct {
	// Mechanism is the vendor setting the tier uses (shown in docs and the
	// panel); empty means the tier is absent for this vendor.
	Mechanism string
	// Source says whether the vendor's tier means what the shipped tier
	// means (refusing host-local, link-local and private ranges for
	// internet): documented only when the vendor's docs say so.
	Source vocab.ClassSource
	// Relay: the run's relay carries the model proxy (and, on internet, the
	// gateway is not used: the vendor's own allow-all is the path out).
	Relay bool
}

// MemoryImagePolicy is what a vendor can do with a live box's memory.
type MemoryImagePolicy struct {
	// AutoPauseExists: the vendor can pause a live box into a memory image.
	AutoPauseExists bool
	// CanDisable: the create request can switch it off (and the driver
	// does).
	CanDisable bool
	Note       string
}

// PlanCap is one plan's longest box lifetime.
type PlanCap struct {
	Plan    string
	Minutes int
}

// Price is a dated list price for a labelled estimate.
type Price struct {
	// USDPerHour is the price of the default box size for one hour.
	USDPerHour float64 `json:"usd_per_hour"`
	Size       string  `json:"size"`
	Date       string  `json:"date"`
	Source     string  `json:"source"`
}

// EndpointDoc grounds one call of a wire client.
type EndpointDoc struct {
	Call   string `json:"call"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Doc    string `json:"doc"`
	// Unverified names what the docs do not state about this call.
	Unverified string `json:"unverified,omitempty"`
}

// Vendor is one hosted sandbox provider.
type Vendor struct {
	ID   string
	Name string
	// DefaultEndpoint is the API origin an environment-variable credential
	// may be sent to (SBX-GOV-4: an env credential is bound to it only).
	DefaultEndpoint string
	// Domains are the vendor's own registrable domains: every API endpoint
	// and every region page is under one of them.
	Domains []string
	// KeystoreService is the keychain service the credential is stored
	// under.
	KeystoreService string
	// EnvCredential are the environment variable names read at use time,
	// the first one decisive (absent means not configured).
	EnvCredential []string
	Regions       Regions
	Tiers         map[vocab.Tier]TierMapping
	LifetimeCaps  []PlanCap
	MemoryImages  MemoryImagePolicy
	Price         Price
	// RelayStdin: the vendor documents a second process with a streaming
	// stdin, so the relay runs over its own exec stream (exec_stdio).
	RelayStdin bool
	// GuestPTY: the vendor documents no PTY resize, so the box-side guest
	// helper owns the PTY and applies sizes sent on the relay's control
	// stream.
	GuestPTY bool
	// Reattach: the vendor documents reconnecting to a running process.
	Reattach bool
	// GuestReattach (lane SBX-UPD): on a GuestPTY row the guest helper
	// keeps the agent's PTY in the box and a new exec of its attach verb
	// reconnects it, so a run whose home helper went is re-adopted without
	// a vendor reattach. Verification stays doc: whether the vendor keeps
	// the guest helper's process after its exec stream ends is a live check
	// (register REM-13). Held false on every row (SBX-UPD audit finding 2,
	// orchestrator ruling): the keeper-only attach key is built, and the flag
	// is turned on only once REM-13 is checked live; until then no run starts
	// a keeper and the agent ends with its stream, as before.
	GuestReattach bool
	// BoxHome is the writable directory the driver uses as HOME for every
	// process it starts in the box; the workspace, the in-box observer and
	// the relay files live under it.
	BoxHome string
	// Docs grounds every call the wire client makes.
	Docs []EndpointDoc
	// Unverified names what the docs do not state that matters here.
	Unverified []string
	// TemplateRule says what a template must be on this vendor ("" when any
	// image or template name the vendor lists will do); it is named in the
	// refusal of a launch that needs one and of a create the vendor refused
	// for its template.
	TemplateRule string
	// NetworkNotes are what a live run saw the vendor's own network do that
	// Observer does not carry and cannot stop (shown on the consent screen).
	NetworkNotes []string
	// DenyRanges is whether the create request can refuse the private ranges
	// on the internet tier while leaving the rest open (decision SBXD-7;
	// network.go PrivateRangeDeny decides, the wire client only renders).
	// The zero value: it cannot, which the notes disclose.
	DenyRanges DenyCapability
	// MintedCredential (lane G4, the org-hosted row): the row has no stored
	// or environment credential. Every call carries a short-lived token the
	// org server mints for this member, node and run, through a
	// CredentialSource the hosted core hands the wire client
	// (Credential.Minted); the keystore and environment lookups and the
	// credential_missing probe row do not apply. The endpoint is the one the
	// org published (OrgEndpoint).
	MintedCredential bool
	// UploadViaExec (lane G4): the vendor has no file API, so the hosted
	// core writes files as bounded one-shot exec parts whose credit is each
	// part's exit (flow-controlled: never more than one part in flight).
	UploadViaExec bool
	// Deliveries are the workspace deliveries the row offers
	// (internal/workspace Delivery values); the hosted prepare step resolves
	// the run's source through workspace.DeliveryFor with them. The vendor
	// rows offer upload_snapshot (the live source: the tree's files uploaded
	// once) and remote_clone (the box clones a public repository itself, on
	// the internet tier only); the org row offers sync (clone-local,
	// uploaded) and remote_clone. Empty takes the live upload only (the
	// earlier rule).
	Deliveries []string
	// OrgEndpoint: the API endpoint exists only as one the organization
	// published (front_url), never a default or a local value.
	OrgEndpoint bool
	// BoundedStdin (lane G4): the vendor ends an exec whose client outruns
	// its bounded stdin buffer (OpenShell 0.1.6, exit 74), so a streaming
	// stdin runs under the in-box paced-stdin wrapper (ExecSpec.PacedStdin)
	// and the relay argv is wrapped by it.
	BoundedStdin bool
	// BoxWorkspace and BoxRunDir are the box's fixed workspace and run dir
	// (lane G4 fix round 1, ruling A3: the org row's /sandbox/workspace and
	// /sandbox/run). "" keeps the hosted rule: the workspace at the laptop's
	// same path and the run dir under the box home. With a fixed workspace
	// the laptop's path never reaches the box, so a resume from another
	// machine uses the same paths. With a fixed run dir every box-side file
	// the node writes lives under it (OB-084): the in-box observer at
	// <run dir>/bin/observer, the upload parts, sessions.json, and the
	// guest's baseline.
	BoxWorkspace, BoxRunDir string
	// NoRootExec (ruling A3): the vendor runs every exec as the box user and
	// offers no root exec, so the core never asks for one and the wire
	// client refuses ExecSpec.AsRoot instead of dropping it.
	NoRootExec bool
	// ReadyWaitSeconds bounds the wait for a box the vendor's create (or a
	// resume) answered before it was ready: the hosted core polls Get with
	// backoff until the box runs, before its first exec (FX3 item 1, live
	// finding F-L3P4-1: OpenShell 0.1.6's CreateSandbox answers before the
	// sandbox reaches its ready phase). 0 is DefaultReadyWaitSeconds. A
	// vendor whose create answers a running box never waits.
	ReadyWaitSeconds int
	// OneShotStdinBytes is the most stdin one one-shot exec carries on an
	// UploadViaExec vendor (each upload part is one such exec); 0 keeps the
	// core's quarter-MiB default.
	OneShotStdinBytes int
	// DefaultImageLacks are programs the vendor's default image (the one a
	// box gets when no template is set) is known not to have, each with the
	// live run or page that showed it (lane UX, item H4). A launch with no
	// template uses it to refuse, before Start, an agent tool whose every
	// install way needs one of them (PlanToolInstall). A program not listed
	// is unknown, never assumed present: the host helper still checks the
	// box before the upload (PickInstall).
	DefaultImageLacks []ImageFact
}

// ImageFact is one grounded fact about a vendor's default image: a program
// it does not have, and where that was seen (a dated live run or page).
type ImageFact struct {
	Program string
	Source  string
}

// ImageLacks returns the programs the vendor's default image is known not to
// have.
func (v Vendor) ImageLacks() []string {
	out := make([]string, 0, len(v.DefaultImageLacks))
	for _, f := range v.DefaultImageLacks {
		out = append(out, f.Program)
	}
	return out
}

// DefaultReadyWaitSeconds is the ready wait of a row that names none.
const DefaultReadyWaitSeconds = 180

// ReadyWait is the row's bounded wait for a box to become ready.
func (v Vendor) ReadyWait() time.Duration {
	if v.ReadyWaitSeconds <= 0 {
		return DefaultReadyWaitSeconds * time.Second
	}
	return time.Duration(v.ReadyWaitSeconds) * time.Second
}

// blockAll is the shared mapping text of the none and proxy_only tiers.
func blockAll(mech string, relay bool) TierMapping {
	return TierMapping{Mechanism: mech, Source: vocab.SourceDocumented, Relay: relay}
}

// vendors is the table.
var vendors = map[string]Vendor{
	VendorE2B: {
		ID: VendorE2B, Name: "E2B",
		DefaultEndpoint: "https://api.e2b.app",
		Domains:         []string{"e2b.app", "e2b.dev"},
		KeystoreService: "sbo-sandbox-e2b-v1",
		EnvCredential:   []string{"E2B_API_KEY"},
		// Only the default deployment is grounded in E2B's own documentation
		// (the API reference's server, api.e2b.app). Other regional
		// endpoints are not listed until each has an E2B doc page (the
		// SBX-P7 merge's audit finding 1).
		Regions: Regions{
			Kind: RegionByEndpoint, Default: "us-west-1",
			Known:     []string{"us-west-1"},
			Endpoints: map[string]string{"us-west-1": "https://api.e2b.app"},
			Docs:      regionDocs("https://docs.e2b.dev/api-reference/sandboxes", "us-west-1"),
		},
		Tiers: map[vocab.Tier]TierMapping{
			vocab.TierNone:      blockAll("allow_internet_access = false (deny 0.0.0.0/0); the relay carries only the hook stream", false),
			vocab.TierProxyOnly: blockAll("allow_internet_access = false; the relay carries the hook stream and the model proxy", true),
			// E2B documents that private and link-local ranges (169.254/16
			// included) are refused outside the guest for every sandbox and
			// cannot be disabled (docs.e2b.dev/network/restrict-public-access),
			// but the live run of 2026-10-23 got an answer (HTTP 401) from
			// 169.254.169.254 inside the box on proxy_only and internet, so
			// the claim is not taken as shown: claimed, and disclosed
			// (NetworkNotes).
			vocab.TierInternet: {Mechanism: "the default allow-all egress (with network.denyOut naming the private ranges unless they are allowed) plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		// SBXD-7: NewSandboxV2.network.denyOut is "List of denied CIDR blocks
		// or IP addresses for egress traffic" (SandboxNetworkConfig); an
		// allowOut entry would take precedence, and the create sends none.
		// The reference names IPv4 forms only (its deny-all example is
		// 0.0.0.0/0), so only the IPv4 ranges are sent.
		DenyRanges: DenyCapability{
			How:    "network.denyOut on the create (NewSandboxV2), with allow_internet_access true and no allowOut",
			Source: "e2b-dev/e2b spec/openapi.yml (SandboxNetworkConfig.denyOut, NewSandboxV2.network) at 08c4eeba6d08, read 2026-11-18; https://e2b.dev/docs/network/internet-access",
		},
		LifetimeCaps: []PlanCap{{"Hobby", 60}, {"Pro", 1440}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: true, CanDisable: true, Note: "autoPause is false by default and the driver sends false"},
		Price: Price{
			USDPerHour: 0.1656, Size: "2 vCPU, 4 GiB (the pricing page default; docs also name 2 vCPU and 512 MiB)",
			Date: "2026-10-22", Source: "https://e2b.dev/pricing and https://docs.e2b.dev/faq/calculate-sandbox-price",
		},
		RelayStdin: true, GuestPTY: false, Reattach: true, BoxHome: "/home/user",
		// The live tree uploaded once, or the box clones a public https
		// repository itself (lane CLONE; no git credential is sent).
		Deliveries: []string{"upload_snapshot", "remote_clone"},
		Docs: []EndpointDoc{
			{"create", "POST", "/v2/sandboxes (templateID, timeout, autoPause false, allow_internet_access, network.denyOut on the internet tier unless private ranges are allowed, metadata, envVars)", "https://docs.e2b.dev/api-reference/sandboxes; spec/openapi.yml (NewSandboxV2) at e2b-dev/E2B db8d80dad5be; SandboxNetworkConfig at 08c4eeba6d08", ""},
			{"get", "GET", "/sandboxes/{sandboxID}", "spec/openapi.yml (SandboxDetail)", ""},
			{"list", "GET", "/v2/sandboxes?metadata=", "spec/openapi.yml (ListedSandbox, X-Next-Token)", ""},
			{"delete", "DELETE", "/sandboxes/{sandboxID}", "spec/openapi.yml", ""},
			{"set timeout", "POST", "/sandboxes/{sandboxID}/timeout", "spec/openapi.yml (SandboxTimeoutRequest)", "what a timeout over the plan cap does"},
			{"upload", "POST", "/files?path=&username= (envd, sandbox.<domain>)", "spec/envd/envd.yaml; docs.e2b.dev/openapi-public.yaml", ""},
			{"download", "GET", "/files?path= (envd)", "spec/envd/envd.yaml", ""},
			{"start", "POST", "/process.Process/Start (Connect, server stream)", "spec/envd/process/process.proto; docs.e2b.dev/openapi-public.yaml", "the EndEvent.status vocabulary"},
			{"connect", "POST", "/process.Process/Connect (Connect, server stream)", "spec/envd/process/process.proto", ""},
			{"send input", "POST", "/process.Process/SendInput", "spec/envd/process/process.proto", ""},
			{"resize", "POST", "/process.Process/Update", "spec/envd/process/process.proto", ""},
			{"signal", "POST", "/process.Process/SendSignal", "spec/envd/process/process.proto", ""},
		},
		Unverified: []string{
			"the per-sandbox envd host form 49983-<id>.<domain> (the driver uses the documented sandbox.<domain> with E2b-Sandbox-Id and E2b-Sandbox-Port)",
			"the Keepalive-Ping-Interval header name (behaviour documented, name SDK-only; the driver does not send it)",
			"rate limits of the non-list endpoints and of envd",
			"the refusal of link-local and metadata addresses the docs state (169.254.169.254 answered inside a box in the 2026-10-23 live run)",
			"whether network.denyOut refuses 169.254.169.254 inside the box (an HTTP 401 there may be the box's own VM metadata service, which a network rule outside the VM would not see; inference, not checked)",
			"whether denyOut takes IPv6 ranges and whether a box has IPv6 egress at all (only the IPv4 ranges are sent)",
			"whether the box's DNS resolver sits in a denied range (the reference names 8.8.8.8 as the default nameserver for allowOut domains)",
		},
		NetworkNotes: []string{
			"in the 2026-10-23 live run the metadata address 169.254.169.254 answered (HTTP 401) inside an E2B box on the proxy_only and internet tiers; that traffic goes through E2B's own network, which Observer does not carry and cannot stop (Observer's relay carries only the hook stream and the model proxy, and refuses link-local and metadata addresses for what it carries)",
		},
	},
	VendorModal: {
		ID: VendorModal, Name: "Modal",
		DefaultEndpoint: "https://api.modal.com:443",
		Domains:         []string{"modal.com"},
		KeystoreService: "sbo-sandbox-modal-v1",
		EnvCredential:   []string{"MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"},
		Regions: Regions{
			Kind: RegionSelectable, Default: ProviderChosen,
			Known: []string{"us", "eu", "ap", "us-east", "us-central", "us-south", "us-west", "eu-west", "eu-north", "eu-south", "ap-northeast", "ap-southeast", "ap-south", "ap-melbourne", "jp", "au", "uk", "ca", "me", "sa", "af", "mx"},
			Docs:  regionDocs("https://modal.com/docs/guide/region-selection", "us", "eu", "ap", "us-east", "us-central", "us-south", "us-west", "eu-west", "eu-north", "eu-south", "ap-northeast", "ap-southeast", "ap-south", "ap-melbourne", "jp", "au", "uk", "ca", "me", "sa", "af", "mx"),
		},
		Tiers: map[vocab.Tier]TierMapping{
			vocab.TierNone:      blockAll("network_access BLOCKED (block_network); the relay carries only the hook stream", false),
			vocab.TierProxyOnly: blockAll("network_access BLOCKED; the relay carries the hook stream and the model proxy", true),
			// Modal documents outbound access to "any public IP address" but
			// not refusing the metadata endpoint or private ranges: claimed.
			vocab.TierInternet: {Mechanism: "the default open egress plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		LifetimeCaps: []PlanCap{{"all plans", 1440}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: false, Note: "no auto-pause; memory snapshots are opt-in and never requested"},
		Price: Price{
			USDPerHour: 0.19, Size: "1 physical core, 2 GiB (sandbox rates, before any region multiplier)",
			Date: "2026-10-22", Source: "https://modal.com/pricing",
		},
		RelayStdin: true, GuestPTY: true, Reattach: false, GuestReattach: false, BoxHome: "/root",
		// The live tree uploaded once, or the box clones a public https
		// repository itself (lane CLONE; no git credential is sent).
		Deliveries: []string{"upload_snapshot", "remote_clone"},
		Docs: []EndpointDoc{
			{"client", "gRPC", "modal.client.ModalClient at api.modal.com:443 through github.com/modal-labs/modal-client/go v0.11.1 (Apache-2.0)", "https://modal.com/docs/guide/sandboxes; https://github.com/modal-labs/modal-client/tree/main/go", "the gRPC API itself is declared non-public; only the SDK is used"},
			{"app", "SDK", "Apps.FromName(CreateIfMissing)", "modal-client/go app.go", ""},
			{"create", "SDK", "Sandboxes.Create(Timeout, BlockNetwork, Regions, Tags, Runtime gvisor)", "https://modal.com/docs/guide/sandboxes; modal-client/go sandbox.go", ""},
			{"exec", "SDK", "Sandbox.Exec (stdin and stdout pipes, stderr ignored; no PTY flag used)", "modal-client/go sandbox.go", ""},
			{"files", "SDK", "Sandbox.Filesystem.WriteBytes / ReadBytes", "modal-client/go sandbox_fs.go", ""},
			{"list", "SDK", "Sandboxes.List(Tags)", "modal-client/go sandbox.go", ""},
			{"terminate", "SDK", "Sandbox.Terminate", "modal-client/go sandbox.go", ""},
		},
		Unverified: []string{
			"the default region when none is set (recorded as provider chosen)",
			"whether a sandbox keeps the guest helper's process after its exec stream ends (the guest PTY reattach, register REM-13)",
			"refusal of the metadata endpoint and private ranges on the open tier",
			"a deny rule for address ranges (SBXD-7): the Go SDK v0.11.1 Sandboxes.Create takes only allow lists (OutboundCIDRAllowlist, OutboundDomainAllowlist, \"non-nil enables allowlist mode\") and BlockNetwork, and https://modal.com/docs/guide/sandbox-networking (searched 2026-11-18) documents outbound_cidr_allowlist and block_network only, so the private ranges cannot be denied while the rest stays open",
			"numeric rate limits",
		},
	},
	VendorVercel: {
		ID: VendorVercel, Name: "Vercel Sandbox",
		DefaultEndpoint: "https://api.vercel.com",
		Domains:         []string{"vercel.com"},
		KeystoreService: "sbo-sandbox-vercel-v1",
		EnvCredential:   []string{"VERCEL_TOKEN", "VERCEL_TEAM_ID", "VERCEL_PROJECT_ID"},
		Regions: Regions{
			Kind: RegionSelectable, Default: "iad1",
			Known: []string{"arn1", "bom1", "cdg1", "cle1", "cpt1", "dub1", "fra1", "gru1", "hkg1", "hnd1", "iad1", "icn1", "kix1", "lhr1", "pdx1", "sfo1", "sin1", "syd1", "yul1"},
			Docs:  regionDocs("https://vercel.com/docs/regions", "arn1", "bom1", "cdg1", "cle1", "cpt1", "dub1", "fra1", "gru1", "hkg1", "hnd1", "iad1", "icn1", "kix1", "lhr1", "pdx1", "sfo1", "sin1", "syd1", "yul1"),
		},
		Tiers: map[vocab.Tier]TierMapping{
			vocab.TierNone:      blockAll("networkPolicy deny-all (DNS included); the relay carries only the hook stream", false),
			vocab.TierProxyOnly: blockAll("networkPolicy deny-all; the relay carries the hook stream and the model proxy", true),
			// The firewall docs do not say whether metadata or private ranges
			// are refused under allow-all: claimed.
			vocab.TierInternet: {Mechanism: "networkPolicy allow-all (or, with the private ranges denied, a policy that allows every name and address and denies those subnets) plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		// SBXD-7: the v3 create's networkPolicy takes an object of allowed
		// domains and subnets, where "subnets.deny: CIDRs to deny traffic to.
		// These take precedence over allowed domains and CIDRs" (the vendor's
		// own SDK, which sends that object to POST /v3/sandboxes; its test
		// pins {"allow": {"*": []}, "subnets": {"deny": ["10.0.0.0/8"]}}).
		// Every example is IPv4, so only the IPv4 ranges are sent.
		DenyRanges: DenyCapability{
			How:    "networkPolicy {allow: [\"*\"], subnets: {allow: [\"0.0.0.0/0\"], deny: the ranges}} on the v3 create",
			Source: "vercel/sandbox packages/vercel-sandbox/src/network-policy.ts (NetworkPolicy.subnets) and api-client/validators.ts (V2NetworkPolicyObjectValidator) at 19c6bc59b812, read 2026-11-18; https://vercel.com/docs/vercel-sandbox/concepts/firewall",
		},
		LifetimeCaps: []PlanCap{{"Hobby", 45}, {"Pro", 1440}, {"Enterprise", 1440}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: false, Note: "no live pause; the filesystem snapshot on stop is switched off with persistent = false"},
		Price: Price{
			USDPerHour: 0.17, Size: "2 vCPU, 4 GB at full CPU in iad1 (active CPU is billed, so most runs cost less)",
			Date: "2026-10-22", Source: "https://vercel.com/docs/sandbox/pricing",
		},
		RelayStdin: true, GuestPTY: true, Reattach: false, GuestReattach: false, BoxHome: "/vercel/sandbox",
		// The live tree uploaded once, or the box clones a public https
		// repository itself (lane CLONE; no git credential is sent).
		Deliveries: []string{"upload_snapshot", "remote_clone"},
		Docs: []EndpointDoc{
			{"create", "POST", "/v3/sandboxes?teamId= (projectId, name, image, timeout ms, persistent false, networkPolicy (a mode, or the private-range deny object on the internet tier), region, tags in the body; no ports)", "https://vercel.com/docs/rest-api/sandboxes/create-a-named-sandbox-1; openapi.vercel.sh createSandboxesV3", "the shape of tags (sent as an object of strings, matching the list filter's key:value)"},
			{"get", "GET", "/v2/sandboxes/{name}?teamId=&projectId= (never resume=true)", "https://vercel.com/docs/rest-api/sandboxes/get-a-named-sandbox", ""},
			{"list", "GET", "/v2/sandboxes?teamId=&project=&tags=key:value&limit=&cursor=", "https://vercel.com/docs/rest-api/sandboxes/list-sandboxes", ""},
			{"delete", "DELETE", "/v2/sandboxes/{name}?teamId=&projectId=&deleteOrphanSnapshots=true", "https://vercel.com/docs/rest-api/sandboxes/delete-a-sandbox", ""},
			{"run command", "POST", "/v2/sandboxes/sessions/{sessionId}/cmd?teamId= (attachStdin)", "https://vercel.com/docs/rest-api/sandboxes/execute-a-command", ""},
			{"logs", "GET", "/v2/sandboxes/sessions/{sessionId}/cmd/{cmdId}/logs?teamId= (NDJSON)", "https://vercel.com/docs/rest-api/sandboxes/stream-command-logs", "whether a re-request replays from the start (SDK behaviour only)"},
			{"stdin", "POST", "/v2/sandboxes/sessions/{sessionId}/cmd/{cmdId}/stdin?teamId= (base64, offset)", "https://vercel.com/docs/rest-api/sandboxes/write-to-command-stdin", ""},
			{"wait", "GET", "/v2/sandboxes/sessions/{sessionId}/cmd/{cmdId}?teamId=&wait=true", "https://vercel.com/docs/rest-api/sandboxes/get-a-command", ""},
			{"kill", "POST", "/v2/sandboxes/sessions/{sessionId}/cmd/{cmdId}/kill?teamId=", "https://vercel.com/docs/rest-api/sandboxes/kill-a-command", ""},
			{"write files", "POST", "/v2/sandboxes/sessions/{sessionId}/fs/write?teamId= (application/gzip tar, x-cwd /)", "https://vercel.com/docs/rest-api/sandboxes/write-files", ""},
			{"read file", "POST", "/v2/sandboxes/sessions/{sessionId}/fs/read?teamId=", "https://vercel.com/docs/rest-api/sandboxes/read-a-file", ""},
		},
		Unverified: []string{
			"the /interactive WebSocket PTY (SDK and CLI source only): not used; the guest helper owns the PTY instead",
			"refusal of the metadata endpoint and private ranges under allow-all",
			"the private-range policy object on the REST create itself (read from the vendor's SDK source, which sends it to POST /v3/sandboxes; the REST reference's update-network-policy page shows the older mode custom with deniedCIDRs instead)",
			"whether a subnets.deny entry also refuses a name that resolves into a denied range, and whether IPv6 ranges are accepted (only the IPv4 ranges are sent)",
			"whether the custom policy (allow \"*\" and subnet 0.0.0.0/0) carries every protocol allow-all does (DNS, git over ssh)",
			"whether every 429 carries Retry-After",
			"whether a sandbox keeps the guest helper's process after its command's log stream and stdin end (the guest PTY reattach, register REM-13)",
		},
		// The 2026-10-23 live run: the v3 create starts only an image the
		// team owns; a runtime name answered 404 "Image not found" and no
		// box was made, and the vendor default image holds no agent tool.
		// Observer does not build a team image (that would be a vendor
		// call outside a launch), so the none and proxy_only tiers, which
		// cannot install the tool at first start, need one named here.
		TemplateRule: "Vercel Sandbox's v3 create starts only an image your Vercel team owns (a public runtime name such as node22 answers 404 Image not found); for the none and proxy_only tiers, make a team image that holds the agent tool with Vercel's own tooling and name it in [terminal.sandbox.hosted.vercel].template, or use the internet tier, where the tool installs at first start",
		// Decision (SBX-P7 merge, audit finding 10): Vercel's REST API takes
		// teamId and projectId in the query string, which the vendor requires.
		// They are account and project identifiers, not secrets; the token
		// stays in the Authorization header and never enters a URL.
	},
	// The org-hosted OpenShell gateway (g1-design.md sections 3 and 4). Every
	// fact is the design of record's and the 0.1.6 live gate's (G-L1 and
	// G-L2, decision log OB-077 to OB-079), never a third party's docs.
	VendorOpenShellOrg: {
		ID: VendorOpenShellOrg, Name: "OpenShell (org-hosted)",
		// No default endpoint: the front URL is the org's, published in its
		// signed body (OrgEndpoint).
		KeystoreService: "sbo-openshell-org-grant-v1",
		// RegionByEndpoint with no endpoint: the region a run records is the
		// org's own label, carried beside the published endpoint.
		Regions: Regions{Kind: RegionByEndpoint, Default: RegionOrgPublished, Known: []string{RegionOrgPublished}},
		Tiers: map[vocab.Tier]TierMapping{
			vocab.TierNone:      blockAll("an OpenShell policy with no network rule (the org gateway's supervisor proxy denies every connection); the relay carries only the hook stream", false),
			vocab.TierProxyOnly: blockAll("an OpenShell policy with no network rule; the relay carries the hook stream and the model proxy", true),
			// The org-compiled network rule: the org's hosts narrowed by the
			// node's, private ranges removed, the org's allow_cidrs added and
			// its blocked_cidrs subtracted last (section 6.1).
			vocab.TierInternet: {Mechanism: "the org-compiled OpenShell network rule (org hosts, private ranges removed, blocked_cidrs subtracted last) plus the relay for the model proxy", Source: vocab.SourceDocumented, Relay: true},
		},
		// The row's static cap (7200 s); the org's max_run_minutes lowers it
		// at launch and the front and the reaper enforce it.
		LifetimeCaps: []PlanCap{{"the organization's gateway", 120}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: false, Note: "no suspend: OpenShell 0.1.6 drivers do not implement it (a held box is a stopped box)"},
		RelayStdin:   true, GuestPTY: false, Reattach: false, BoxHome: "/home/sandbox",
		Docs: []EndpointDoc{
			{"create", "gRPC", "openshell.v1.OpenShell/CreateSandbox through the org's front (the front creates the spec the org compiled at mint)", "docs/plans/openshell/build/g1-design.md section 3.2 step 5", ""},
			{"get", "gRPC", "openshell.v1.OpenShell/GetSandbox", "g1-design.md section 7.6 row F3", ""},
			{"delete", "gRPC", "openshell.v1.OpenShell/DeleteSandbox (a teardown token only)", "g1-design.md section 7.6 row F6", ""},
			{"exec", "gRPC", "openshell.v1.OpenShell/ExecSandbox (one-shot, stdin in the request)", "g1-design.md section 3.3", ""},
			{"interactive", "gRPC", "openshell.v1.OpenShell/ExecSandboxInteractive (bidi; TTY for the agent, TTY off for the relay)", "g1-design.md section 3.3; live gate G-L2 verdict tty_false (OB-079)", ""},
			{"health", "gRPC", "grpc.health.v1.Health/Check (service superbased.openshell.front)", "g1-design.md section 7.6 row F1", ""},
		},
		Unverified: []string{
			"the front's answers through a real org deployment (live checks G-L3 and G-L6)",
		},
		NetworkNotes: []string{
			"the box's own network refusals stay on your organization's machine and are not reported to this machine in this release",
		},
		MintedCredential: true, UploadViaExec: true, OrgEndpoint: true, BoundedStdin: true,
		// The org's fixed box paths (internal/openshellorg compile.go
		// BoxWorkspace and BoxRunDir; a test pins them equal).
		BoxWorkspace: "/sandbox/workspace", BoxRunDir: "/sandbox/run", NoRootExec: true,
		Deliveries: []string{"sync", "remote_clone"},
		// The 0.1.6 create answers before the box is ready (the gateway
		// provisions the container after it answers, then the supervisor
		// dials back; G-L3 run 3 saw 0.3 s to over 1 s): the core waits up to
		// this long, polling the front's GetSandbox (a read, never one of the
		// gateway's admitted mutations).
		ReadyWaitSeconds: 180,
		// internal/openshellorg MaxOneShotStdin (a test pins them equal): the
		// gateway's 1 MiB gRPC decode limit (MAX_GRPC_DECODE_SIZE in the
		// 0.1.6 gateway's multiplex.rs) less 64 KiB for the rest of the
		// request (FX4 item 2, F-P6-2; FX3 had assumed 4 MiB).
		OneShotStdinBytes: 1<<20 - 64<<10,
	},
	// Docker's cloud sandboxes (lane SBX-DOCKER): the Docker Agentic
	// Platform's pay-as-you-go hosted microVMs, driven through the Sandboxes
	// API (OpenAPI 3.2, v1, labelled experimental). Every fact was read on
	// 2026-11-11 from the pages named per call; the client-level live smoke
	// of 2026-11-11 (three micro boxes, docs/sandboxed-terminals.md "Docker
	// Sandboxes", live smoke) checked the ones its comments say.
	VendorDockerSandboxes: {
		ID: VendorDockerSandboxes, Name: "Docker Sandboxes",
		// The API reference's server; the base keeps its /sandboxes path
		// prefix and every /v1 path is appended to it.
		DefaultEndpoint: "https://connect.docker.com/sandboxes",
		Domains:         []string{"docker.com"},
		KeystoreService: "sbo-sandbox-docker-v1",
		EnvCredential:   dockerSandboxesEnvNames,
		// Docker documents no region for cloud sandboxes: the one entry is
		// the provider's own choice, grounded by the FAQ (which names the
		// cloud endpoint and no region), so an org allowed_regions floor
		// refuses it (S7b).
		Regions: Regions{
			Kind: RegionSelectable, Default: ProviderChosen,
			Known: []string{ProviderChosen},
			Docs:  regionDocs("https://docs.docker.com/ai/sandboxes/faq/", ProviderChosen),
		},
		Tiers: map[vocab.Tier]TierMapping{
			// An inline network policy at create, "enforced before the first guest
			// process" (the API reference, CreateSandboxRequest.networkPolicies):
			// denyAll with explicit deny rules for every name and address. Live
			// 2026-11-11: denyAll alone left an installed default allow of "**"
			// in the effective policy and the box reached the internet; with the
			// deny rules it resolved no name and reached no address.
			vocab.TierNone:      blockAll("an inline denyAll network policy with deny rules for every name and address (**, 0.0.0.0/0, ::/0) at create; the relay carries only the hook stream", false),
			vocab.TierProxyOnly: blockAll("an inline denyAll network policy with deny rules for every name and address at create; the relay carries the hook stream and the model proxy", true),
			// The create request's inline policy has denyAll only, so the open
			// tier sends none and the account's own default policy decides
			// (sbx --cloud policy init allow-all|balanced|deny-all); the docs
			// do not say whether metadata or private ranges are refused:
			// claimed, and disclosed (NetworkNotes). Live 2026-11-11, on an
			// account whose default was denyAll plus a default-layer allow of
			// "**": public names and addresses answered, while 169.254.169.254
			// and 10.0.0.1 timed out (one account, one observation).
			vocab.TierInternet: {Mechanism: "the Docker account's default network policy (allow-all opens it), with an inline policy that only denies the private ranges unless they are allowed, plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		// SBXD-7: the inline NetworkPolicy (mode denyAll, the only mode an
		// inline policy takes) carries denyNetworks, "exact network names or
		// CIDRs denied by this document"; inline policies "restrict access
		// alongside account policy, so they cannot grant access that your
		// account denies" (the cookbook's "Control what a sandbox can
		// reach"). Live 2026-11-11: an inline denyAll alone left the account's
		// default allow of "**" in force (the box reached the internet), and
		// deny rules won over it, IPv6 (::/0) included. So on the internet
		// tier an inline denyAll with only the ranges' deny rules adds the
		// deny and leaves the account's allows as they are.
		DenyRanges: DenyCapability{
			How:    "an inline network policy {mode: denyAll, denyNetworks: the ranges} at create (no allow rule, so the account's own allows still decide the rest)",
			IPv6:   true,
			Source: "https://docs.docker.com/reference/api/sandboxes/api.yaml (NetworkPolicy, CreateSandboxRequest.networkPolicies) as docker/docs content/reference/api/sandboxes/api.yaml at f8d4abc33303, read 2026-11-18; the 2026-11-11 live smoke (deny rules win over the default allow)",
		},
		// "Extensions can't move expiration beyond 24 hours from creation"
		// (cloud usage page); the default is one hour, and the driver always
		// sends its own timeout.
		LifetimeCaps: []PlanCap{{"all plans", 1440}},
		// A stop preserves memory and the restart timeout action keeps it;
		// the driver sends onTimeout delete and never stops a box.
		MemoryImages: MemoryImagePolicy{AutoPauseExists: true, CanDisable: true, Note: "a stop keeps the box's memory; the driver sends onTimeout delete and never stops a box"},
		Price: Price{
			USDPerHour: 0.14, Size: "small: 2 vCPU, 4 GB, the size the driver asks for (billed per second from start to stop)",
			Date: "2026-11-11", Source: "https://www.docker.com/c/sbx-promo/ (rates current as of September 2026) and https://docs.docker.com/ai/sandboxes-api/limits/",
		},
		// The interactive process API documents a PTY, a resize frame and a
		// resume from a stream sequence, so the PTY is the vendor's and a
		// dropped stream re-attaches (the E2B shape, over a WebSocket). Live
		// 2026-11-11: a PTY took its initial size and a resize (stty size
		// 24 80, then 40 120); a pipe stream held 5.5 minutes, past its
		// five-minute grant, was re-attached once by the client and echoed
		// again; the default image runs as root (uid 0), so HOME is /root.
		RelayStdin: true, GuestPTY: false, Reattach: true, BoxHome: "/root",
		// The live tree uploaded once, or the box clones a public https
		// repository itself (lane CLONE; no git credential is sent).
		Deliveries: []string{"upload_snapshot", "remote_clone"},
		Docs: []EndpointDoc{
			{"exchange", "POST", "https://hub.docker.com/v2/auth/token (identifier and the account's access token) -> access_token", "https://docs.docker.com/ai/sandboxes-api/authentication/", "the management token's lifetime (re-exchanged on a 401)"},
			{"create", "POST", "/v1/sandboxes (Idempotency-Key; displayName, imageRef, resources cpus and memoryMib, labels, startupExecution.rawImage.start, features.timeouts onTimeout delete, networkPolicies denyAll below internet and a ranges-only denyAll on internet unless private ranges are allowed)", "https://docs.docker.com/reference/api/sandboxes/api.yaml (createSandbox, CreateSandboxRequest)", "whether a raw image stays running without a start command (the driver sends sleep infinity; with it the box ran and answered 201 or a running read within 16 s live)"},
			{"get", "GET", "/v1/sandboxes/{sandbox}", "api.yaml (getSandbox, Sandbox, SandboxStatus)", ""},
			{"list", "GET", "/v1/sandboxes (pageSize and a continuation token; no label filter, so the run label is matched in the client)", "api.yaml (listSandboxes); https://docs.docker.com/ai/sandboxes-api/concepts/", ""},
			{"delete", "DELETE", "/v1/sandboxes/{sandbox}?force=true (If-Match: the etag; 202 while deleting, 204 when gone)", "api.yaml (deleteSandbox); concepts page", ""},
			{"endpoint credential", "POST", "/v1/sandboxes/{sandbox}/endpoint-credentials (sandboxesExec, sandboxesFilesRead, sandboxesFilesWrite; ttl at most 300s)", "api.yaml (createEndpointCredential, EndpointCredential); authentication page", ""},
			{"create process", "POST", "{core.endpoint.uri}/v1/processes (cmd argv, env, workingDir, user, pty.initialSize; Idempotency-Key)", "api.yaml (createProcess, CreateProcessRequest)", ""},
			{"interact", "GET", "{core.endpoint.uri}/v1/processes/{process}/interact (WebSocket subprotocol sandboxes.v1: attach with resumeFrom, stdin, closeStdin, resize; chunk, exited, heartbeat)", "api.yaml (interact, x-websocket, InteractRequest, ProcessOutput)", ""},
			{"get process", "GET", "{core.endpoint.uri}/v1/processes/{process}", "api.yaml (getProcess, Process)", ""},
			{"signal", "POST", "{core.endpoint.uri}/v1/processes/{process}/signal (kill)", "api.yaml (signal, ProcessSignal)", ""},
			{"mkdir", "PUT", "{core.endpoint.uri}/v1/files/directories (parents true)", "api.yaml (mkdir, FilesMkdirRequest)", ""},
			{"upload", "POST", "{core.endpoint.uri}/v1/files/upload (multipart metadata and content pairs, streamed)", "api.yaml (upload, FileHeader)", "a size cap on one upload stream"},
			{"read file", "GET", "{core.endpoint.uri}/v1/files/content?path=", "api.yaml (readFile)", "the unary message cap above which a read is refused"},
		},
		// Settled by the live smoke of 2026-11-11 and so no longer listed: a
		// box's endpoint is https://<port>-<id>.sbx.sandboxes-cloud.docker.com
		// (under docker.com, as the client requires); the default image runs
		// as root; a box started with sleep infinity stays running through
		// the run; an open interact stream past its five-minute grant ends
		// and the client's re-attach resumes it; a forced delete answers at
		// once and the next read is a 404; a killed process reports exit -1.
		Unverified: []string{
			"whether a raw image box stays running without a start command (the driver always sends sleep infinity as startupExecution.rawImage.start)",
			"the management token's lifetime (re-exchanged once on a 401; a 6-minute run needed no second exchange)",
			"the account's default network policy on the internet tier on other accounts, and whether the metadata endpoint and private ranges are refused or only unrouted there",
			"whether an inline denyAll carrying only the ranges' deny rules leaves the internet open on an account whose default is allowAll mode with no allow rule (on the live smoke account the default was denyAll plus an allow of \"**\", and denyAll alone left the internet open)",
			"the isolation class of a cloud box (a VM by its evidence: its own kernel, 6.12.114, and an /init on vsock as pid 1; Docker documents none)",
			"file, upload and output retention caps, label key syntax and numeric rate limits",
			"the FAQ names https://api.sandboxes-cloud.docker.com as the cloud endpoint while the API reference names https://connect.docker.com/sandboxes (the driver uses the API reference's, which answered live)",
		},
		TemplateRule: "on Docker Sandboxes a template is an OCI image reference the service can pull (imageRef) that holds the agent tool, sh and git, runs as root (HOME /root) and is started with sleep infinity in place of its own command; name it in [terminal.sandbox.hosted.docker].template, or use the internet tier, where the tool installs at first start when the account's network policy lets the box reach its vendor",
		NetworkNotes: []string{
			"on the internet tier Docker applies your account's own default network policy (sbx --cloud policy init allow-all, balanced or deny-all); Observer cannot see or change it, and Docker's docs do not say whether the metadata address or private ranges are refused (in the 2026-11-11 live smoke they timed out while public hosts answered)",
		},
	},
	// InstaBox (instabox.sh). Every fact is InstaBox's public docs and
	// OpenAPI document (https://api.instabox.sh/v1/openapi.json, version
	// 1.0.0), read 2026-11-11, and an API-level live smoke of this client
	// on the operator's free account the same day (create, ready, exec,
	// root exec, files, two terminal streams, delete; no agent run, no
	// relay): see docs/sandboxed-terminals.md, InstaBox "Live smoke".
	VendorInstaBox: {
		ID: VendorInstaBox, Name: "InstaBox",
		DefaultEndpoint: "https://api.instabox.sh",
		Domains:         []string{"instabox.sh"},
		KeystoreService: "sbo-sandbox-instabox-v1",
		EnvCredential:   []string{"INSTABOX_API_KEY"},
		// The create takes no region (a region field is 400 unknown_field)
		// and the machine reports none: placement is the platform's.
		Regions: Regions{
			Kind: RegionSelectable, Default: ProviderChosen,
			Known: []string{ProviderChosen},
			Docs:  regionDocs("https://instabox.sh/docs/machines.md", ProviderChosen),
		},
		// InstaBox documents no network policy: no deny-all, no allowlist,
		// nothing that would make the none or proxy_only tier true, so the
		// row offers only internet. Whether its open egress refuses private,
		// link-local and metadata ranges is not documented: claimed.
		Tiers: map[vocab.Tier]TierMapping{
			vocab.TierInternet: {Mechanism: "InstaBox's own open egress (it documents no network policy) plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		// Free: a machine pauses after 480 minutes of continuous running
		// (only an InstaBox admin changes it), which ends the run. Paid
		// plans default to no max run; the run's timeout is the create's
		// deleteAfterSeconds, at most 86400.
		LifetimeCaps: []PlanCap{{"Free", 480}, {"Pro, Builder and Team", 1440}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: true, CanDisable: false, Note: "a running machine pauses into a memory image after 30 idle minutes (fixed on the free plan) and at its max run; the driver changes neither, and deleteAfterSeconds deletes the machine at the run's timeout whatever its state"},
		Price: Price{
			USDPerHour: 0.034, Size: "4 vCPU, 8 GiB, the default and the free plan's only size (a free machine is never billed; paid plans pay this beyond their monthly credit, by the second while running, plus disk past the included amount)",
			Date: "2026-11-11", Source: "https://instabox.sh/docs/pricing.md ($0.004 per vCPU-hour, $0.00225 per GiB-hour)",
		},
		// The relay and the guest helper each ride their own terminal
		// WebSocket session, in raw mode (the client's start script): no
		// non-PTY exec stream with a streaming stdin is documented.
		RelayStdin: true, GuestPTY: true, Reattach: false, GuestReattach: false, BoxHome: "/data/home",
		// The live tree uploaded once, or the box clones a public https
		// repository itself (lane CLONE; no git credential is sent).
		Deliveries: []string{"upload_snapshot", "remote_clone"},
		// The create answers 202 with an operation; the client waits for it,
		// and the core waits until the machine is ready (runtime.ready).
		ReadyWaitSeconds: 180,
		Docs: []EndpointDoc{
			{"create", "POST", "/v1/machines (Idempotency-Key; name, templateId, deleteAfterSeconds, metadata)", "https://instabox.sh/docs/api/machines.md; openapi.json createMachine", ""},
			{"operation", "GET", "/v1/operations/{id}?wait=25s (long poll)", "https://instabox.sh/docs/api/operations.md; openapi.json getOperation", ""},
			{"get", "GET", "/v1/machines/{id}", "https://instabox.sh/docs/api/machines.md; openapi.json getMachine", ""},
			{"list", "GET", "/v1/machines?metadata=key:value&cursor=", "https://instabox.sh/docs/api/machines.md; openapi.json listMachines", ""},
			{"delete", "DELETE", "/v1/machines/{id} (Idempotency-Key, X-Confirm-Delete)", "https://instabox.sh/docs/api/machines.md; openapi.json deleteMachine", ""},
			{"exec", "POST", "/v1/machines/{id}/exec (argv, cwd, envs, stdin, timeoutSeconds 600)", "https://instabox.sh/docs/api/commands.md; openapi.json execCommand", ""},
			{"upload", "PUT", "/v1/machines/{id}/files?path=&mode=&parents=true (raw body)", "https://instabox.sh/docs/api/commands.md; openapi.json writeMachineFile", "the mode of a parent directory parents=true creates"},
			{"download", "GET", "/v1/machines/{id}/files/content?path=", "https://instabox.sh/docs/api/commands.md; openapi.json downloadMachineFile", ""},
			{"terminal", "GET", "/v1/machines/{id}/terminal?session=&restart=1 (WebSocket: binary bytes, JSON controls)", "openapi.json openMachineTerminal", "the typed start line and the raw-mode PTY are Observer's own use of the documented terminal (byte-transparent in the 2026-11-11 live smoke; not yet under a real relay or agent)"},
		},
		Unverified: []string{
			"the terminal stream under a real relay and agent run (the 2026-11-11 live smoke carried 65,559 bytes, NUL, 0xff and the ^C, ^D and ^Z bytes unchanged both ways, and the exit code, but no relay or agent ran)",
			"the largest terminal message the server accepts (32 KiB messages were accepted live; the client sends no larger)",
			"passwordless sudo on templates other than agent-browser (sudo -n ran as root there, live 2026-11-11)",
			"whether terminal traffic alone keeps a machine out of idle pause while the agent waits silently (activity leases exist and are not used)",
			"what a run sees at the free plan's 480-minute max-run pause (the machine pauses with a cooldown; the run ends)",
			"refusal of the metadata endpoint and private ranges (no network policy is documented)",
			"a deny rule for address ranges (SBXD-7): the OpenAPI document's createMachine takes name, templateId, deleteAfterSeconds and metadata only, so the private ranges cannot be denied",
			"what the ci, android and omarchy templates hold (agent-browser, the default, has sha256sum but no git, gzip, node or npm on the standard PATH, live 2026-11-11, so a first-start npm install there fails and the staged diff has no git)",
		},
		TemplateRule: "InstaBox's free plan creates only from the agent-browser (the default), android, omarchy and ci templates (403 template_not_allowed otherwise); a paid plan may name any template GET /v1/templates lists as creatable, as an id or id@version, in [terminal.sandbox.hosted.instabox].template",
		NetworkNotes: []string{
			"InstaBox documents no network policy, so its machines reach the internet on every run; Observer's relay carries only the hook stream and the model proxy, and the box's own traffic goes through InstaBox's network, which Observer does not carry and cannot stop",
			"what a machine sends is capped at about 50 Mbit/s per machine (InstaBox's limits page)",
		},
	},
	// Daytona Cloud (a hosted vendor). Every fact below was read on
	// 2026-11-11 from Daytona's public documentation: the main API spec
	// https://www.daytona.io/docs/openapi.json (Apache-2.0, info.version
	// 1.0), the toolbox API spec https://www.daytona.io/docs/toolbox-openapi.json,
	// and the guide pages cited per fact. A client-level live smoke on
	// 2026-11-11 (one box on the operator's own account, TestLiveSmoke
	// behind SBO_DAYTONA_LIVE, docs/sandboxed-terminals.md "Daytona") settled
	// the facts marked "live 2026-11-11"; the hosted register (REM-1 to
	// REM-12, REM-DAY-1 to REM-DAY-3) is still owed, so the row stays doc.
	VendorDaytona: {
		ID: VendorDaytona, Name: "Daytona",
		// The authentication page: the API URL defaults to
		// https://app.daytona.io/api; every request sends the key as a bearer
		// token.
		DefaultEndpoint: "https://app.daytona.io/api",
		Domains:         []string{"daytona.io"},
		KeystoreService: "sbo-sandbox-daytona-v1",
		// The authentication page names the key's variable; its URL and
		// target variables are not read (the endpoint and region come from
		// [terminal.sandbox.hosted.daytona]).
		EnvCredential: []string{"DAYTONA_API_KEY"},
		// The sandboxes page, "Regions": targets us and eu; the
		// authentication page lists no default target, so an unpinned run
		// records provider chosen.
		Regions: Regions{
			Kind: RegionSelectable, Default: ProviderChosen,
			Known: []string{"us", "eu"},
			Docs:  regionDocs("https://www.daytona.io/docs/en/sandboxes/", "us", "eu"),
		},
		Tiers: map[vocab.Tier]TierMapping{
			// The network limits page: networkBlockAll blocks all outbound
			// traffic. Whether DNS is blocked too is not stated (Unverified).
			vocab.TierNone:      blockAll("networkBlockAll = true (all outbound traffic blocked); the relay carries only the hook stream", false),
			vocab.TierProxyOnly: blockAll("networkBlockAll = true; the relay carries the hook stream and the model proxy", true),
			// The network limits page: Tier 1 and 2 organizations get a
			// restricted network (essential services only) that no sandbox
			// setting widens; Tier 3 and 4 get full internet. Private,
			// link-local and metadata ranges are not said to be refused:
			// claimed, and disclosed (NetworkNotes).
			vocab.TierInternet: {Mechanism: "the organization's own tier network policy (essential services only on Daytona Tier 1 and 2, full internet on Tier 3 and 4) plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		// Daytona documents no plan lifetime cap: ttlMinutes is "subject to
		// the maximum sandbox lifespan configured for the organization
		// region and sandbox class", whose value is not published. 1440
		// minutes is Observer's own cap (the top of max_run_minutes), not a
		// vendor fact.
		LifetimeCaps: []PlanCap{{"no plan cap documented (Observer's own cap)", 1440}},
		// Auto-pause is for VM sandbox classes only and is not allowed for
		// an ephemeral sandbox (CreateSandbox.autoPauseInterval); every box
		// is created ephemeral (autoDeleteInterval 0), so a stop deletes it
		// and leaves no archive.
		MemoryImages: MemoryImagePolicy{AutoPauseExists: false, Note: "no pause on the container class; every box is ephemeral (autoDeleteInterval 0), so a stop deletes it and nothing is archived"},
		Price: Price{
			USDPerHour: 0.0666, Size: "1 vCPU, 1 GiB, 3 GiB disk (the default sandbox; the first 5 GiB of disk are free)",
			Date: "2026-11-11", Source: "https://www.daytona.io/pricing ($0.0504 per vCPU-hour, $0.0162 per GiB-hour of memory, billed per second) and https://www.daytona.io/docs/en/sandboxes/ (the default size)",
		},
		// A second exec stream with a streaming stdin is a second SSH exec
		// channel; no PTY resize is used (the PTY WebSocket's framing is not
		// documented), so the guest helper owns the PTY.
		RelayStdin: true, GuestPTY: true, Reattach: false, GuestReattach: false,
		// The file system guide: "File operations assume you are operating
		// in the sandbox user's home directory"; the default user is
		// "daytona" (CreateSandbox.user's example), so its home is
		// /home/daytona (live 2026-11-11: the default snapshot
		// daytonaio/sandbox:0.11.0 runs SSH sessions as daytona, uid 1001,
		// HOME /home/daytona, with passwordless sudo).
		BoxHome: "/home/daytona",
		// The live tree uploaded once, or the box clones a public https
		// repository itself (lane CLONE; no git credential is sent).
		Deliveries: []string{"upload_snapshot", "remote_clone"},
		// Create answers the Sandbox, possibly before it reaches started
		// (states creating, pending_build, pulling_snapshot): the core waits.
		// Live 2026-11-11: the default snapshot answered started in 1.3 s.
		ReadyWaitSeconds: 300,
		Docs: []EndpointDoc{
			{"create", "POST", "/sandbox (name, labels, env, target, snapshot, autoStopInterval 0, autoDeleteInterval 0, ttlMinutes, public false, networkBlockAll)", "https://www.daytona.io/docs/openapi.json (createSandbox, CreateSandbox); https://www.daytona.io/docs/en/sandboxes/ (Auto-stop, Wall-clock TTL, Ephemeral)", "the answer to a repeated name (the spec lists only 200) and to a snapshot that does not exist"},
			{"get", "GET", "/sandbox/{sandboxIdOrName}", "openapi.json (getSandbox, Sandbox, SandboxState)", ""},
			{"list", "GET", "/sandbox?labels={json}&limit=&cursor=", "openapi.json (listSandboxes, ListSandboxesResponse)", "the list is documented as eventually consistent"},
			{"delete", "DELETE", "/sandbox/{sandboxIdOrName}", "openapi.json (deleteSandbox)", ""},
			{"ssh access", "POST", "/sandbox/{sandboxIdOrName}/ssh-access?expiresInMinutes=", "openapi.json (createSshAccess, SshAccessDto); https://www.daytona.io/docs/en/ssh-access/", "the gateway's host key (not published; live 2026-11-11: ssh.app.daytona.io:22, ssh-ed25519 SHA256:A1Q6sAQohGVYSNJt8rInS/gjF3Hd0Yp33d0HymhdEV8) and which auth method the gateway takes besides the token as the user name"},
			{"exec", "SSH", "an exec channel on ssh.app.daytona.io as <token>@ (stdin, stdout, stderr, exit status, stdin EOF: RFC 4254)", "https://www.daytona.io/docs/en/ssh-access/", "exec channels are not documented (the page shows interactive and IDE sessions only); live 2026-11-11: exit statuses, stderr apart, stdin EOF, a SIGTERM kill (143), user daytona and sudo -n all work"},
			{"upload", "POST", "{toolboxProxyUrl}/{sandboxId}/files/upload-v2?path= (raw application/octet-stream body)", "https://www.daytona.io/docs/toolbox-openapi.json (UploadFile)", "an upload size limit"},
			{"mode", "POST", "{toolboxProxyUrl}/{sandboxId}/files/permissions?path=&mode=", "toolbox-openapi.json (SetFilePermissions)", ""},
			{"download", "GET", "{toolboxProxyUrl}/{sandboxId}/files/download?path=", "toolbox-openapi.json (DownloadFile)", ""},
		},
		Unverified: []string{
			"the SSH gateway's host key (not published; the client trusts the first key a run sees and refuses a change, ledger SBX-DAY-1; the key seen live 2026-11-11 is recorded in the endpoint table)",
			"exec channels on the SSH gateway are not documented (they worked in the live smoke of 2026-11-11: exit statuses, stderr, stdin EOF, kill)",
			"whether networkBlockAll is honoured on every tier (live 2026-11-11 on the operator's organization: DNS and an HTTPS fetch both failed from the box; the organization's tier was not recorded)",
			"refusal of the metadata endpoint and private ranges on the internet tier",
			"a deny rule for address ranges (SBXD-7): https://www.daytona.io/docs/en/network-limits (searched 2026-11-18) documents networkAllowList (up to 5 IPv4 CIDRs, an allow list) and networkBlockAll, mutually exclusive, and no deny list, so the private ranges cannot be denied while the rest stays open",
			"the maximum sandbox lifespan per organization, region and class",
			"the Tier 1 memory quota (the limits page lists 10 GiB in one table and 20 GiB in another)",
			"an upload size limit on the toolbox",
			"the create's answer to a repeated name or a missing snapshot",
			"whether the default snapshot has bash, curl and tar (what a vendor install script needs); the host helper checks the box before the upload",
		},
		// Live 2026-11-18 on the operator's node: OpenCode's first-start
		// install (npm install -g) exited 127 in a box made from the default
		// snapshot, which has no npm (docs/audits/hosted-sandbox-key-custody-2026-11-18.md,
		// "Live check").
		DefaultImageLacks: []ImageFact{
			{Program: "npm", Source: "live 2026-11-18: npm install exited 127 in a box made from Daytona's default snapshot (docs/audits/hosted-sandbox-key-custody-2026-11-18.md)"},
		},
		NetworkNotes: []string{
			"on the internet tier the box's network is your Daytona organization's own tier policy: on Tier 1 and 2 only Daytona's essential services (package registries, git hosts, model providers) are reachable, on Tier 3 and 4 the full internet; that traffic goes through Daytona's network, which Observer does not carry and cannot stop",
		},
	},
}

// dockerSandboxesEnvNames are the Docker Sandboxes row's environment
// variable names: the Docker account's access token (made with "Allow Cloud
// Sandboxes access", scope sandbox:use) and the Docker ID it belongs to. The
// authentication page's example reads DOCKER_PAT and DOCKER_ID; the row
// names its own, so another tool's Docker variables are never sent by
// surprise.
var dockerSandboxesEnvNames = []string{"DOCKER_SANDBOXES_TOKEN", "DOCKER_SANDBOXES_ID"}

// VendorFor returns the vendor of a registry row id.
func VendorFor(id string) (Vendor, bool) {
	v, ok := vendors[id]
	return v, ok
}

// VendorIDs returns the vendor ids, sorted.
func VendorIDs() []string {
	out := make([]string, 0, len(vendors))
	for id := range vendors {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// TierList returns the tiers the vendor can express, most open first (host is
// never one: unsatisfiable remotely).
func (v Vendor) TierList() []vocab.Tier {
	var out []vocab.Tier
	for _, t := range vocab.Tiers() {
		if m, ok := v.Tiers[t]; ok && m.Mechanism != "" {
			out = append(out, t)
		}
	}
	return out
}

// MinLifetimeMinutes is the shortest plan cap the vendor documents (the
// registry row's LifetimeCapSeconds, S13).
func (v Vendor) MinLifetimeMinutes() int {
	m := 0
	for _, c := range v.LifetimeCaps {
		if m == 0 || c.Minutes < m {
			m = c.Minutes
		}
	}
	return m
}

// ResolveRegion returns the region a run records and the API endpoint it
// uses, for the configured region ("" means the vendor default). ok is false
// for a region the vendor does not list.
func (v Vendor) ResolveRegion(configured string) (region, endpoint string, ok bool) {
	r := strings.TrimSpace(configured)
	if r == "" {
		r = v.Regions.Default
	}
	if r != ProviderChosen && !contains(v.Regions.Known, r) {
		return "", "", false
	}
	endpoint = v.DefaultEndpoint
	if v.Regions.Kind == RegionByEndpoint {
		endpoint = v.Regions.Endpoints[r]
	}
	return r, endpoint, true
}

// RegionOrgPublished is the region a run records when it uses an
// org-published endpoint (SBX-GOV-2).
const RegionOrgPublished = "org-published"

// RegionCustomEndpoint is the region a run records for a configured
// endpoint on the vendor's own domain that no listed region names.
const RegionCustomEndpoint = "custom-endpoint"

// ResolveEndpoint is ResolveRegion with a configured API endpoint (E2B's
// endpoint key, lane SBX-UPD): "" is the region's own endpoint. Only a
// vendor whose region IS its endpoint takes one. A local endpoint must be on
// the vendor's own domain (the P-090 F1 rule); only an org-published one
// (orgPublished, set by the managed pull on a managed node) may leave it,
// and a credential is still sent there only when it was connected for it
// (CheckBinding, SBX-GOV-4). ok is false otherwise.
func (v Vendor) ResolveEndpoint(configuredRegion, endpoint string, orgPublished bool) (region, ep string, ok bool) {
	endpoint = strings.TrimSuffix(strings.TrimSpace(endpoint), "/")
	if v.OrgEndpoint {
		// Only the organization's published endpoint, never a default or a
		// local value; the region is the org's own label (section 8.2).
		return v.resolveOrgEndpoint(configuredRegion, endpoint, orgPublished)
	}
	if endpoint == "" {
		return v.ResolveRegion(configuredRegion)
	}
	if v.Regions.Kind != RegionByEndpoint {
		return "", "", false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return "", "", false
	}
	if orgPublished {
		return RegionOrgPublished, endpoint, true
	}
	if !v.OwnsHost(u.Hostname()) {
		return "", "", false
	}
	for r, e := range v.Regions.Endpoints {
		if strings.EqualFold(strings.TrimSuffix(e, "/"), endpoint) {
			return r, endpoint, true
		}
	}
	return RegionCustomEndpoint, endpoint, true
}

// resolveOrgEndpoint is ResolveEndpoint for an OrgEndpoint row: an https
// origin the org published, recorded with the org's region label (empty is
// kept empty, so an allowed_regions floor refuses it, S7b).
func (v Vendor) resolveOrgEndpoint(region, endpoint string, orgPublished bool) (string, string, bool) {
	if !orgPublished || endpoint == "" {
		return "", "", false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(endpoint, "?#") {
		return "", "", false
	}
	return strings.TrimSpace(region), endpoint, true
}

// OwnsHost reports whether host is one of the vendor's own domains or under
// one.
func (v Vendor) OwnsHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, d := range v.Domains {
		d = strings.ToLower(d)
		if host == d || strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}

// Estimate is a labelled cost estimate.
type Estimate struct {
	Minutes int     `json:"minutes"`
	USD     float64 `json:"usd"`
	Price   Price   `json:"price"`
}

// EstimateCost prices minutes of the default box size.
func (v Vendor) EstimateCost(minutes int) Estimate {
	return Estimate{Minutes: minutes, USD: v.Price.USDPerHour * float64(minutes) / 60, Price: v.Price}
}

// Label renders the estimate with its source and date, always marked an
// estimate. no-bare-usd:allow: a remote sandbox vendor's compute list price
// (box-minutes), not model spend, so the token display has no equivalent.
func (e Estimate) Label() string {
	return "about $" + strconv.FormatFloat(e.USD, 'f', 2, 64) + " for " + strconv.Itoa(e.Minutes) +
		" box-minutes (estimate: " + e.Price.Size + ", list price read " + e.Price.Date + "; the vendor's bill is the truth)"
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// BoxLayout is where the driver puts things in a box.
type BoxLayout struct {
	// Home is HOME for every process the driver starts.
	Home string
	// Workspace is the workspace's path in the box: the SAME absolute path
	// as on the host (the bind_same_path rule of section 6), so a hook's
	// cwd, a transcript's project root and the relay's run roots agree with
	// no translation. The driver creates it as root and hands it to the box
	// user.
	Workspace string
	Binary    string
	// RunDir holds the relay's per-run files (the mux secret).
	RunDir string
}

// Layout returns the box paths for a workspace at hostRoot (an absolute,
// cleaned slash path).
func (v Vendor) Layout(hostRoot string) BoxLayout {
	root := v.BoxHome + "/.observer-box"
	l := BoxLayout{Home: v.BoxHome, Workspace: hostRoot, Binary: root + "/bin/observer", RunDir: root + "/run"}
	if v.BoxWorkspace != "" {
		l.Workspace = v.BoxWorkspace
	}
	if v.BoxRunDir != "" {
		l.RunDir = v.BoxRunDir
		l.Binary = v.BoxRunDir + "/bin/observer"
	}
	return l
}
