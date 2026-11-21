package dashapi

import "context"

// ScannerDBStatus is the dependency scanners' OSV database download state
// for the Code security page's Scanners card (operator ruling PT-19 (2):
// ask once, then automatic).
type ScannerDBStatus struct {
	// Accepted reports the developer's one-time accept of the download;
	// AcceptedAt (RFC3339), AcceptedOn (dashboard or cli) and By (the
	// local account) say when, where and who.
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	By         string `json:"by,omitempty"`
	// ApproxMB and Source are what the confirm dialog shows: the first
	// download's size, about, and the host it comes from.
	ApproxMB int    `json:"approx_mb"`
	Source   string `json:"source"`
	// Text is the accept text, the same words the CLI shows.
	Text string `json:"text"`
	// Managed reports a managed node: its databases come from the org
	// mirror, so there is nothing to accept.
	Managed bool `json:"managed"`
	// Blocked is the download gate's first closed reason ("" when the
	// download may run).
	Blocked string `json:"blocked,omitempty"`
	// Installed is how many ecosystems have a database on disk.
	Installed int `json:"installed"`
	// DBSource is the [security.deps] db_source setting (auto, feed,
	// upstream, import); SourceOrder is the sources it tries, in order
	// (org_mirror, import, feed, upstream).
	DBSource    string   `json:"db_source,omitempty"`
	SourceOrder []string `json:"source_order,omitempty"`
	// LastSource is the source that served the last refresh ("" when none
	// could), LastSourceAt when (RFC3339), Fallback why each earlier
	// source did not serve, and SourceError why none did.
	LastSource   string `json:"last_source,omitempty"`
	LastSourceAt string `json:"last_source_at,omitempty"`
	Fallback     string `json:"fallback,omitempty"`
	SourceError  string `json:"source_error,omitempty"`
	// OS is the OS release databases' state (OS-2, ruling Q1 (b)): their
	// one accept and the releases installed; nil in a build or a seam that
	// carries none.
	OS *ScannerOSDBStatus `json:"os,omitempty"`
	// Image is the image OS package driver's state (lane OS-2 T): the
	// driver in force, each driver's build and install state, and Trivy's
	// database accept and age; nil in a build or a seam that carries none.
	Image *ScannerImageStatus `json:"image,omitempty"`
	// Exploit is the exploit data's state (CISA KEV and FIRST EPSS, plan
	// section 14.7 item 5): filled by the dashboard from the OSV store's
	// exploit directory (osvdb.ExploitStatuses), never by the seam, so a
	// Status func leaves it nil.
	Exploit *ScannerExploitStatus `json:"exploit,omitempty"`
	// Lookup is the package lookup posture (lane RM-2), which the Scanners
	// card shows read-only with a link to the Privacy page's card; nil in a
	// seam that carries none.
	Lookup *PackageLookupStatus `json:"lookup,omitempty"`
}

// PackageLookupStatus is the package lookup posture (OS and CI
// vulnerability scanning plan section 13.10, lane RM-2): whether this node
// downloads the OSV databases or looks its dependencies up at SuperBased,
// what each choice sends, and the consent records behind each.
type PackageLookupStatus struct {
	// Mode is the effective lookup mode: "local", "remote", "both", or ""
	// when nothing is chosen yet (a fresh install). Configured is
	// [security.deps] match as written ("" when unset).
	Mode       string `json:"mode"`
	Configured string `json:"configured"`
	// Via is how a remote lookup is answered ("shards"); ViaChoices the
	// values this build serves.
	Via        string   `json:"via"`
	ViaChoices []string `json:"via_choices"`
	// Kinds are the package kinds a remote lookup covers; KindChoices the
	// kinds this build serves.
	Kinds       []string `json:"kinds"`
	KindChoices []string `json:"kind_choices"`
	// Private is [security.deps] remote_private ("withhold" or "send");
	// PrivateSending is true only when it is send AND its own consent is
	// recorded.
	Private        string `json:"private"`
	PrivateSending bool   `json:"private_sending"`
	// Managed reports a managed node: the organization decides the
	// posture, and the card is not a control.
	Managed bool `json:"managed"`
	// Download, Remote and RemotePrivate are the three consent records: the
	// database accept, the SuperBased lookup, and sending private names.
	Download      LookupConsent `json:"download"`
	Remote        LookupConsent `json:"remote"`
	RemotePrivate LookupConsent `json:"remote_private"`
	// Blocked is why a dependency scan would not run now ("" when it may):
	// lookup_not_chosen, database_not_accepted, remote_not_accepted.
	Blocked string `json:"blocked,omitempty"`
	// RemoteBlocked is the remote lookup gate's first closed reason ("" when
	// a lookup may run).
	RemoteBlocked string `json:"remote_blocked,omitempty"`
	// RemoteHosts are the hosts a remote lookup reaches; ApproxMB the
	// database download's size, for the first-run card's side-by-side
	// offer.
	RemoteHosts []string `json:"remote_hosts"`
	ApproxMB    int      `json:"approx_mb"`
	// Sets are the shard sets the last verified manifest lists (empty until
	// a lookup has run); CacheBytes what the node-local shard cache holds.
	Sets       []LookupSet `json:"sets,omitempty"`
	CacheBytes int64       `json:"cache_bytes"`
	// Drivers says, per driver, whether it can use a remote lookup in this
	// build (osv-scanner, Trivy and image OS packages cannot yet).
	Drivers []LookupDriver `json:"drivers"`
	// Org is a managed node's posture as its organization's signed
	// security policy decides it (lane RM-3); nil on an individual node.
	Org *OrgLookupStatus `json:"org,omitempty"`
}

// OrgLookupStatus is a managed node's org-decided package lookup posture
// (OS and CI vulnerability scanning plan 13.10, lane RM-3): read-only, from
// the signed security policy in force (package_lookup and its two
// companions).
type OrgLookupStatus struct {
	// On is package_lookup = org_mirror: the node looks the ecosystems its
	// org mirror's databases do not cover up in the org mirror's shards.
	On bool `json:"on"`
	// Private is the org's private-names rule: "withhold" or "send".
	Private string `json:"private"`
	// Kinds are the package kinds the lookup covers.
	Kinds []string `json:"kinds"`
	// OrgName names the org server the lookups go to (the enrolment's).
	OrgName string `json:"org_name,omitempty"`
	// Version is the signed security policy document's version (0 when
	// none is stored).
	Version int64 `json:"version"`
	// Source labels where the posture comes from ("org", the share keys'
	// "org state" label on the Privacy page).
	Source string `json:"source"`
}

// LookupConsent is one consent record's state: accepted or not, when and on
// which surface, and the text the developer accepts.
type LookupConsent struct {
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	By         string `json:"by,omitempty"`
	Text       string `json:"text"`
}

// LookupSet is one shard set the verified manifest lists.
type LookupSet struct {
	Set       string `json:"set"`
	Ecosystem string `json:"ecosystem"`
	Epoch     int64  `json:"epoch"`
	Bits      int    `json:"bits"`
}

// LookupDriver is one driver's remote lookup support.
type LookupDriver struct {
	Driver string `json:"driver"`
	Remote bool   `json:"remote"`
	Note   string `json:"note,omitempty"`
}

// PackageLookupChange is one PUT /api/security/lookup: each field set is a
// change; a mode or a private-names choice that sends data needs its
// consent in the same request (Accept*) unless it is already recorded.
type PackageLookupChange struct {
	Mode            *string   `json:"mode,omitempty"`
	Kinds           *[]string `json:"kinds,omitempty"`
	Private         *string   `json:"private,omitempty"`
	AcceptDownload  bool      `json:"accept_download,omitempty"`
	AcceptRemote    bool      `json:"accept_remote,omitempty"`
	AcceptPrivate   bool      `json:"accept_private,omitempty"`
	WithdrawRemote  bool      `json:"withdraw_remote,omitempty"`
	WithdrawPrivate bool      `json:"withdraw_private,omitempty"`
}

// ArtifactFolder is one candidate build-artifact folder of a project, for
// the Scanners card's artifact row (OS and CI vulnerability scanning plan
// section 14.6, item 4, operator ruling 2026-11-05): discovered by folder
// names and file headers only, off until the developer turns it on.
type ArtifactFolder struct {
	// Dir is the folder, relative to the project root, forward slashes.
	Dir string `json:"dir"`
	// Enabled reports that the developer turned the folder on: its
	// executables, JARs and wheels are read by every scan of the project.
	Enabled bool `json:"enabled"`
	// Default marks a folder of the default list (bin, dist,
	// target/release).
	Default bool `json:"default,omitempty"`
	// Present is false for an enabled folder that no longer exists.
	Present bool `json:"present"`
	// Summary is what the folder's file headers say it holds ("2 ELF
	// executables, 1 JAR"); Counts the same by kind; Bytes their size.
	Summary string         `json:"summary"`
	Counts  map[string]int `json:"counts,omitempty"`
	Bytes   int64          `json:"bytes,omitempty"`
	// Truncated reports that a discovery bound ended the look early.
	Truncated bool `json:"truncated,omitempty"`
}

// ArtifactFolders is GET /api/security/artifacts: one project's candidate
// artifact folders and which are on.
type ArtifactFolders struct {
	Project string           `json:"project"`
	Folders []ArtifactFolder `json:"folders"`
	// Text says what turning a folder on does, the words the CLI shows.
	Text string `json:"text"`
	// DriverCompiled is false where the SCALIBR driver is not linked (it
	// reads the artifacts), so a folder cannot be turned on usefully.
	DriverCompiled bool `json:"driver_compiled"`
}

// ArtifactChange is one PUT /api/security/artifacts: turn one folder of the
// project on or off.
type ArtifactChange struct {
	Dir     string `json:"dir"`
	Enabled bool   `json:"enabled"`
}

// ReachSourceStatus is GET /api/security/reach/go-source: one project's Go
// source check (plan section 14.5 item 3b, 3b-src): the opt-in, the
// isolation, the caps, whether a run is going, and the stored answers.
type ReachSourceStatus struct {
	Project string `json:"project"`
	// Compiled is false in a build without the check; Selected whether
	// security.reach.go is selected.
	Compiled bool `json:"compiled"`
	Selected bool `json:"selected"`
	// OptedIn, AllowUnisolated, OptedAt and Surface are the project's
	// signed opt-in.
	OptedIn         bool   `json:"opted_in"`
	AllowUnisolated bool   `json:"allow_unisolated"`
	OptedAt         string `json:"opted_at,omitempty"`
	Surface         string `json:"surface,omitempty"`
	// IsolationAvailable says whether this host can run it isolated.
	IsolationAvailable bool `json:"isolation_available"`
	// Text is what opting in means, the words the CLI shows.
	Text string `json:"text"`
	// The developer's caps ([security.reach.go]).
	MemoryMiB      int64 `json:"memory_mib"`
	TimeoutSeconds int64 `json:"timeout_seconds"`
	MaxModules     int   `json:"max_modules"`
	// Running is set while a run started here is going; LastError is the
	// last such run's refusal or failure ("" after a success).
	Running   bool   `json:"running"`
	LastError string `json:"last_error,omitempty"`
	// Runs are the stored answers, one per go.mod.
	Runs []ReachSourceRun `json:"runs"`
}

// ReachSourceRun is one go.mod's stored answer.
type ReachSourceRun struct {
	Target string `json:"target"`
	// Reason and ReasonText say why it decided nothing ("" when it did).
	Reason     string `json:"reason,omitempty"`
	ReasonText string `json:"reason_text,omitempty"`
	// Called and NotCalled count the packages (module@version) with a
	// listed function called, and with none called.
	Called    int `json:"called"`
	NotCalled int `json:"not_called"`
	// AssumedGo is the Go release the standard library was evaluated at.
	AssumedGo string `json:"assumed_go,omitempty"`
}

// ReachSourceChange is one PUT /api/security/reach/go-source: opt the
// project in (with the isolation override) or out.
type ReachSourceChange struct {
	Enabled         bool `json:"enabled"`
	AllowUnisolated bool `json:"allow_unisolated"`
}

// ScannerExploitStatus is the exploit data's state for the Scanners card.
// The two kinds download with the OSV databases after their accept (no
// consent of their own); a kind that is missing, stale or changed reads
// unavailable, never "not exploited".
type ScannerExploitStatus struct {
	// Kinds is each kind's state, KEV first, then EPSS.
	Kinds []ScannerExploitKind `json:"kinds"`
	// EPSSCitation is FIRST's requested citation, set only while the EPSS
	// data is available (secexploit.EPSSCitation); KEVNotice the plain-words
	// source line, set only while the KEV data is available
	// (secexploit.KEVNotice). No CISA branding is used.
	EPSSCitation string `json:"epss_citation,omitempty"`
	KEVNotice    string `json:"kev_notice,omitempty"`
}

// ScannerExploitKind is one exploit kind's install state.
type ScannerExploitKind struct {
	// Kind is the content kind (security.kev or security.epss); Name its
	// words ("CISA KEV", "FIRST EPSS").
	Kind string `json:"kind"`
	Name string `json:"name"`
	// Installed reports a record on disk; Available that the reader passes
	// the kind to every lookup now; Reason why not (not_installed, stale,
	// file_mismatch, unreadable).
	Installed bool   `json:"installed"`
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Version is the data's own version (the catalog version, the EPSS
	// model); Source where it came from (feed or org_mirror); VouchedAt
	// (RFC3339) the newest signed manifest that vouched for it, the age
	// floor's clock; Bytes the artifact's size.
	Version   string `json:"version,omitempty"`
	Source    string `json:"source,omitempty"`
	VouchedAt string `json:"vouched_at,omitempty"`
	Bytes     int64  `json:"bytes,omitempty"`
	// CheckedAt (RFC3339) is the node's last download attempt for the kind
	// ("" before the first one), LastError why it brought no verified set
	// ("" when it did), and Blocked the fetch gate's reason when nothing was
	// asked (database_not_accepted, database_missing, feed_unavailable):
	// what the card says instead of "after the accept" once the accept is
	// given and the download still fails or is not allowed.
	CheckedAt string `json:"checked_at,omitempty"`
	LastError string `json:"last_error,omitempty"`
	Blocked   string `json:"blocked,omitempty"`
}

// ScannerOSDBStatus is the OS release databases' state for the Scanners
// card: one accept covers every distribution release the scanned images
// use, each fetched on demand from SuperBased's signed mirror only.
type ScannerOSDBStatus struct {
	// Accepted reports the developer's OS accept; AcceptedAt (RFC3339),
	// AcceptedOn (dashboard or cli) and By say when, where and who.
	Accepted   bool   `json:"accepted"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	AcceptedOn string `json:"accepted_on,omitempty"`
	By         string `json:"by,omitempty"`
	// Text is the accept text, the same words the CLI shows; Source the one
	// host the databases come from.
	Text   string `json:"text"`
	Source string `json:"source"`
	// Sizes is each distribution's approximate per-release download.
	Sizes []ScannerOSDistroSize `json:"sizes"`
	// Managed reports a managed node: its OS databases come from the org
	// mirror, so there is nothing to accept.
	Managed bool `json:"managed"`
	// Blocked is the fetch gate's first closed reason ("" when a release
	// may be fetched).
	Blocked string `json:"blocked,omitempty"`
	// Installed lists the releases on disk, in table order.
	Installed []ScannerOSRelease `json:"installed"`
	// DiskBytes is what the OS databases take on disk.
	DiskBytes int64 `json:"disk_bytes"`
}

// ScannerOSDistroSize is one distribution's approximate per-release size.
type ScannerOSDistroSize struct {
	Name     string `json:"name"`
	ApproxMB int64  `json:"approx_mb"`
}

// ScannerOSRelease is one installed OS release database.
type ScannerOSRelease struct {
	// Distro and Version are the os-release ID and version the row answers;
	// Artifact its name in the feed.
	Distro   string `json:"distro"`
	Version  string `json:"version"`
	Artifact string `json:"artifact"`
	// Epoch is what a finding records; Source where it came from (feed or
	// org_mirror).
	Epoch  string `json:"epoch"`
	Source string `json:"source,omitempty"`
	// Bytes is the installed export's size.
	Bytes     int64  `json:"bytes"`
	FetchedAt string `json:"fetched_at,omitempty"`
	CheckedAt string `json:"checked_at,omitempty"`
	// LastError is the last refresh's fixed reason ("" after a success);
	// the installed database stays in use.
	LastError string `json:"last_error,omitempty"`
	// FixedOnly and KnownGap are the release's coverage labels.
	FixedOnly bool   `json:"fixed_only,omitempty"`
	KnownGap  string `json:"known_gap,omitempty"`
}

// ScannerDB is the dashboard seam of the scanner database accept, wired
// from cmd/observer/security_scan_dash.go. Status reads; Accept records the
// developer's accept given in the dashboard's confirm dialog. A nil
// ScannerDB (a build without the component, a test) makes the accept route
// answer 404 and the Scanners card show no accept.
// AcceptOS records the OS release databases' accept (a POST whose body
// is {"os":true}); nil answers 404 for it.
type ScannerDB struct {
	Status   func(ctx context.Context) (ScannerDBStatus, error)
	Accept   func(ctx context.Context) error
	AcceptOS func(ctx context.Context) error
	// AcceptTrivyDB records Trivy's database accept (POST
	// /api/security/scanners/trivydb); nil answers 404 for it.
	AcceptTrivyDB func(ctx context.Context) error
	// Lookup reads the package lookup posture and SetLookup changes it
	// (GET and PUT /api/security/lookup, lane RM-2); nil answers 404.
	Lookup    func(ctx context.Context) (PackageLookupStatus, error)
	SetLookup func(ctx context.Context, change PackageLookupChange) error
	// Artifacts lists a project's candidate artifact folders and
	// SetArtifact turns one on or off (GET and PUT /api/security/artifacts,
	// M3L-2 item 4); the project is its root folder. nil answers 404.
	Artifacts   func(ctx context.Context, projectRoot string) (ArtifactFolders, error)
	SetArtifact func(ctx context.Context, projectRoot string, change ArtifactChange) error
	// ReachSource reads a project's Go source check, SetReachSource records
	// or withdraws its opt-in, and RunReachSource starts a run in the
	// background (GET, PUT and POST .../run on /api/security/reach/go-source,
	// 3b-src); nil answers 404.
	ReachSource    func(ctx context.Context, projectRoot string) (ReachSourceStatus, error)
	SetReachSource func(ctx context.Context, projectRoot string, change ReachSourceChange) error
	RunReachSource func(ctx context.Context, projectRoot string) error
}
