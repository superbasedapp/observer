package sandboxremote

import (
	"net/url"
	"sort"
	"strconv"
	"strings"

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
			vocab.TierInternet: {Mechanism: "the default allow-all egress plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		LifetimeCaps: []PlanCap{{"Hobby", 60}, {"Pro", 1440}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: true, CanDisable: true, Note: "autoPause is false by default and the driver sends false"},
		Price: Price{
			USDPerHour: 0.1656, Size: "2 vCPU, 4 GiB (the pricing page default; docs also name 2 vCPU and 512 MiB)",
			Date: "2026-10-22", Source: "https://e2b.dev/pricing and https://docs.e2b.dev/faq/calculate-sandbox-price",
		},
		RelayStdin: true, GuestPTY: false, Reattach: true, BoxHome: "/home/user",
		Docs: []EndpointDoc{
			{"create", "POST", "/v2/sandboxes", "https://docs.e2b.dev/api-reference/sandboxes; spec/openapi.yml (NewSandboxV2) at e2b-dev/E2B db8d80dad5be", ""},
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
			vocab.TierInternet: {Mechanism: "networkPolicy allow-all plus the relay for the model proxy", Source: vocab.SourceClaimed, Relay: true},
		},
		LifetimeCaps: []PlanCap{{"Hobby", 45}, {"Pro", 1440}, {"Enterprise", 1440}},
		MemoryImages: MemoryImagePolicy{AutoPauseExists: false, Note: "no live pause; the filesystem snapshot on stop is switched off with persistent = false"},
		Price: Price{
			USDPerHour: 0.17, Size: "2 vCPU, 4 GB at full CPU in iad1 (active CPU is billed, so most runs cost less)",
			Date: "2026-10-22", Source: "https://vercel.com/docs/sandbox/pricing",
		},
		RelayStdin: true, GuestPTY: true, Reattach: false, GuestReattach: false, BoxHome: "/vercel/sandbox",
		Docs: []EndpointDoc{
			{"create", "POST", "/v3/sandboxes?teamId= (projectId, name, image, timeout ms, persistent false, networkPolicy, region, tags in the body; no ports)", "https://vercel.com/docs/rest-api/sandboxes/create-a-named-sandbox-1; openapi.vercel.sh createSandboxesV3", "the shape of tags (sent as an object of strings, matching the list filter's key:value)"},
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
}

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
	return BoxLayout{Home: v.BoxHome, Workspace: hostRoot, Binary: root + "/bin/observer", RunDir: root + "/run"}
}
