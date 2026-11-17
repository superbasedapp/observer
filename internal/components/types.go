package components

// Class is a component's kind (plan section 3.1). Artifacts are not a Class
// value: they live in their own ArtifactComponent table (plan 3.3.2).
type Class string

// The closed Class vocabulary.
const (
	// ClassCore is L0: never removable. If core needs something, it is core.
	ClassCore Class = "core"
	// ClassFeature is a product capability with its own goroutines, routes,
	// verbs or tables.
	ClassFeature Class = "feature"
	// ClassAdapter is one row per integration-registry tool id.
	ClassAdapter Class = "adapter"
	// ClassIntegration writes into another product's config or the OS. It is
	// split from the feature that uses it because "may Observer edit my
	// tools' config files" is a separate decision from "may Observer read
	// their transcripts".
	ClassIntegration Class = "integration"
	// ClassServer is an org-side module or image.
	ClassServer Class = "server"
)

// Classes returns the closed Class vocabulary in display order.
func Classes() []Class {
	return []Class{ClassCore, ClassFeature, ClassAdapter, ClassIntegration, ClassServer}
}

// Valid reports whether c is in the closed vocabulary.
func (c Class) Valid() bool {
	for _, k := range Classes() {
		if c == k {
			return true
		}
	}
	return false
}

// Binary names the Go binary (or image) a component ships in.
type Binary string

// The closed Binary vocabulary.
const (
	BinaryNode      Binary = "node"      // cmd/observer
	BinaryOrg       Binary = "org"       // cmd/observer-org
	BinaryMCPGW     Binary = "mcpgw"     // cmd/observer-mcpgw (separate image)
	BinaryAIGateway Binary = "aigateway" // cmd/observer-aigateway (separate image)
	BinaryEdge      Binary = "edge"      // cmd/observer-edge (separate image)
	BinaryHarness   Binary = "harness"   // harness-gateway (separate image)
)

// Binaries returns the closed Binary vocabulary.
func Binaries() []Binary {
	return []Binary{BinaryNode, BinaryOrg, BinaryMCPGW, BinaryAIGateway, BinaryEdge, BinaryHarness}
}

// Valid reports whether b is in the closed vocabulary.
func (b Binary) Valid() bool {
	for _, k := range Binaries() {
		if b == k {
			return true
		}
	}
	return false
}

// CmdPath is the main package that builds the binary, "" for an image that
// is not built from this repository's cmd tree.
func (b Binary) CmdPath() string {
	switch b {
	case BinaryNode:
		return "cmd/observer"
	case BinaryOrg:
		return "cmd/observer-org"
	case BinaryMCPGW:
		return "cmd/observer-mcpgw"
	case BinaryAIGateway:
		return "cmd/observer-aigateway"
	case BinaryEdge:
		return "cmd/observer-edge"
	}
	return ""
}

// Level is a removal level (plan section 4).
type Level string

// The closed Level vocabulary.
const (
	// L0 is core: always present.
	L0 Level = "L0"
	// L1 is compiled out: the component's packages and the modules it alone
	// brings are absent from the binary, proved by go list -deps.
	L1 Level = "L1"
	// L2 is installed but inert: compiled in, but nothing runs, listens,
	// egresses or writes.
	L2 Level = "L2"
	// L3 is a runtime toggle: today's config enabled keys.
	L3 Level = "L3"
)

// Levels records which removal levels a component supports. Implemented is
// what the code delivers TODAY; Target is where the plan takes it, with the
// phase that delivers it. The UI and docs always show Implemented, so nobody
// mistakes a planned level for a shipped one.
type Levels struct {
	// Implemented is the set of levels that exist in this build's code.
	Implemented []Level
	// Target is the set of levels the plan delivers for this component.
	Target []Level
	// Phase names the plan phase that delivers the highest Target level
	// ("P1", "P2", "P5", ...), "" when Target is already implemented.
	Phase string
}

// Has reports whether l is in the implemented set.
func (ls Levels) Has(l Level) bool {
	for _, x := range ls.Implemented {
		if x == l {
			return true
		}
	}
	return false
}

// Targets reports whether l is in the target set.
func (ls Levels) Targets(l Level) bool {
	for _, x := range ls.Target {
		if x == l {
			return true
		}
	}
	return false
}

// Stability mirrors the integration lifecycle for adapters and the OTel
// stability vocabulary for everything else.
type Stability string

// The closed Stability vocabulary.
const (
	StabilityExperimental Stability = "experimental"
	StabilityPreview      Stability = "preview"
	StabilityStable       Stability = "stable"
	StabilityDeprecated   Stability = "deprecated"
)

// Valid reports whether s is in the closed vocabulary.
func (s Stability) Valid() bool {
	switch s {
	case StabilityExperimental, StabilityPreview, StabilityStable, StabilityDeprecated:
		return true
	}
	return false
}

// Distro is a named, prebuilt node component selection (plan 5.2).
type Distro string

// The four prebuilt node distros.
const (
	DistroMinimal   Distro = "minimal"
	DistroDeveloper Distro = "developer"
	DistroManaged   Distro = "managed"
	DistroFull      Distro = "full"
)

// Distros returns the prebuilt node distros, smallest first.
func Distros() []Distro {
	return []Distro{DistroMinimal, DistroDeveloper, DistroManaged, DistroFull}
}

// Valid reports whether d is a prebuilt distro.
func (d Distro) Valid() bool {
	for _, k := range Distros() {
		if d == k {
			return true
		}
	}
	return false
}

// Default is a component's cell in a distro column (plan 3.3).
type Default string

// The closed Default vocabulary.
const (
	// DefaultOn: compiled in and active by default.
	DefaultOn Default = "on"
	// DefaultOff: compiled in, inactive until selected.
	DefaultOff Default = "off"
	// DefaultCond: compiled in, activates on a stated condition (enrolment).
	DefaultCond Default = "cond"
	// DefaultOut: compiled out ("-" in the plan table).
	DefaultOut Default = "out"
)

// Compiled reports whether the cell means the component is in the binary.
func (d Default) Compiled() bool { return d == DefaultOn || d == DefaultOff || d == DefaultCond }

// Valid reports whether d is in the closed vocabulary.
func (d Default) Valid() bool {
	switch d {
	case DefaultOn, DefaultOff, DefaultCond, DefaultOut:
		return true
	}
	return false
}

// Image is a prebuilt org-server image (plan 3.4): exactly two coarse
// images in this plan, full and core.
type Image string

// The two org images.
const (
	ImageFull Image = "full"
	ImageCore Image = "core"
)

// Images returns the org images.
func Images() []Image { return []Image{ImageFull, ImageCore} }

// ImageDefault is a server component's cell in an image column.
type ImageDefault string

// The closed ImageDefault vocabulary.
const (
	// ImageIn: compiled into the image and active by default.
	ImageIn ImageDefault = "in"
	// ImageOff: compiled into the image, inactive until configured.
	ImageOff ImageDefault = "off"
	// ImagePerDeploy: compiled in, chosen by the deployment's config.
	ImagePerDeploy ImageDefault = "per_deploy"
	// ImageOut: absent from the image.
	ImageOut ImageDefault = "out"
	// ImageSeparate: ships as its own image, never inside observer-org.
	ImageSeparate ImageDefault = "separate"
)

// Valid reports whether d is in the closed vocabulary.
func (d ImageDefault) Valid() bool {
	switch d {
	case ImageIn, ImageOff, ImagePerDeploy, ImageOut, ImageSeparate:
		return true
	}
	return false
}

// Trigger says when a surface item happens (plan rev F9).
type Trigger string

// The closed Trigger vocabulary.
const (
	TriggerAutomatic     Trigger = "automatic"
	TriggerUserTriggered Trigger = "user_triggered"
	TriggerGenerated     Trigger = "generated_artifact"
	TriggerOptIn         Trigger = "opt_in"
)

// Valid reports whether t is in the closed vocabulary.
func (t Trigger) Valid() bool {
	switch t {
	case TriggerAutomatic, TriggerUserTriggered, TriggerGenerated, TriggerOptIn:
		return true
	}
	return false
}

// Listener is one socket a component binds.
type Listener struct {
	// Proto is "tcp", "unix" or "pipe".
	Proto string
	// Addr is the default bind ("127.0.0.1:8820"), a path template for a
	// unix socket, or a pipe name template.
	Addr string
	// Loopback reports whether the default bind is loopback-only.
	Loopback bool
	// Auth names the authentication on the socket ("none", "local token",
	// "owner-only ACL", "dashboard capability").
	Auth string
	// ConfigKey is the dotted config key that moves it ("" when fixed).
	ConfigKey string
	// Trigger says whether it binds on every start or only when opted in.
	Trigger Trigger
}

// Egress is one outbound destination a component may contact.
type Egress struct {
	// Host is a host or host pattern ("superbased.app", "<configured>").
	Host string
	// Purpose is a one-line honest reason.
	Purpose string
	// Gate names the consent or config gate ("default on", "consent",
	// "enrolment", "config").
	Gate string
	// Trigger says when it happens.
	Trigger Trigger
}

// Surface is everything a component touches outside its own memory
// (plan 3.2). An empty Surface is a claim: the component does none of it.
type Surface struct {
	Listeners     []Listener
	Egress        []Egress
	FilesWritten  []string // path templates under ~/.observer or elsewhere
	VendorConfigs []string // other products' config files it edits
	OSIntegration []string // registry keys, eBPF capabilities, scheduled tasks
	Processes     []string // exec'd binaries
	Credentials   []string // OS secret stores it reads or writes
}

// Empty reports whether the surface declares nothing.
func (s Surface) Empty() bool {
	return len(s.Listeners) == 0 && len(s.Egress) == 0 && len(s.FilesWritten) == 0 &&
		len(s.VendorConfigs) == 0 && len(s.OSIntegration) == 0 && len(s.Processes) == 0 &&
		len(s.Credentials) == 0
}

// MigrationClass is the side-effect class of a migration (plan 5.7, rev F3).
type MigrationClass string

// The closed MigrationClass vocabulary.
const (
	MigrationSchemaOnly          MigrationClass = "schema_only"
	MigrationSingletonSeed       MigrationClass = "singleton_seed"
	MigrationFeatureBackfill     MigrationClass = "feature_backfill"
	MigrationSharedDataMutation  MigrationClass = "shared_data_mutation"
	MigrationSharedAuthorization MigrationClass = "shared_authorization_mutation"
)

// Valid reports whether c is in the closed vocabulary.
func (c MigrationClass) Valid() bool {
	switch c {
	case MigrationSchemaOnly, MigrationSingletonSeed, MigrationFeatureBackfill,
		MigrationSharedDataMutation, MigrationSharedAuthorization:
		return true
	}
	return false
}

// MigrationRef is one migration a component owns, with its side-effect
// class. File is the path relative to the repository root.
type MigrationRef struct {
	File  string
	Class MigrationClass
	Note  string
}

// DataOwnership is the catalog's declaration of the rows a component owns
// (plan 3.2.1). It is a declaration, never a delete generator: purge is a
// typed, hand-reviewed plan in the store seam (lane MP-GATE).
type DataOwnership struct {
	Table string
	// Ownership is "exclusive" or "shared".
	Ownership string
	// Selector names the row selector for a shared table ("tool = 'zed'").
	Selector string
}

// TeardownStep is one ordered step that undoes a component's writes,
// referencing the existing owner that performs it.
type TeardownStep struct {
	// Owner is the package or verb that performs the step
	// ("internal/clientwire Remover hooks").
	Owner string
	// What is the honest one-line description.
	What string
}

// Component is one catalog row (plan 3.2).
type Component struct {
	ID     string
	Class  Class
	Binary Binary
	Title  string
	About  string
	Levels Levels
	// Packages are the import paths (relative to the module root) this
	// component owns. A package is owned by at most one component per
	// binary; an unowned package is core.
	Packages []string
	// HostedIn lists packages owned by ANOTHER component that currently
	// host this component's code until the boundary refactor (phase PB)
	// splits them, e.g. the xlsx export living in the dashboard package.
	HostedIn []string
	// DirectModules are the third-party modules its own (or hosted)
	// packages import directly: expected consumers, never exclusive
	// ownership (plan rev M5). Checked against go list -deps.
	DirectModules []string
	// Requires: this component cannot be active without these.
	Requires []string
	// RequiresCompiled: needs another component's code but not its
	// activity.
	RequiresCompiled []string
	// Bundles: compiled together with these (one package serves several
	// ids).
	Bundles []string
	// Recommends: suggested together, never forced.
	Recommends []string
	// Conflicts: cannot both be active.
	Conflicts []string
	Surface   Surface
	// Tables are node-local or server tables the component owns.
	Tables []string
	// Data is the row-level ownership declaration (plan 3.2.1).
	Data []DataOwnership
	// Migrations it owns, classified (plan 5.7).
	Migrations []MigrationRef
	// Routes are dashboard or org route prefixes it owns.
	Routes []string
	// Verbs are top-level CLI verbs it owns.
	Verbs []string
	// ConfigKeys are top-level config sections it reads.
	ConfigKeys []string
	// Teardown is the ordered undo of its writes.
	Teardown []TeardownStep
	// Ledger lists docs/security.md row ids.
	Ledger    []string
	Stability Stability
	// Distros is the node distro column set (node components only).
	Distros map[Distro]Default
	// Images is the org image column set (server components only).
	Images map[Image]ImageDefault
	// RestartClass is hot, soft or restart (configschema vocabulary).
	RestartClass string
	// Note carries anything the row needs to say that has no field yet.
	Note string
	// Reach is which deployment shapes the component reaches and how far it
	// is on by default in pooled SaaS (plan 06 18.3.3). A grandfathered row
	// gets it at build time (reach.go); a new row sets ReachOf(stability).
	Reach Reach
}

// BuildTag returns the opt-out build tag for the component ("" for core):
// "sbo_omit_" plus the id with dots and dashes as underscores.
func (c Component) BuildTag() string {
	if c.Class == ClassCore {
		return ""
	}
	return BuildTagFor(c.ID)
}

// BuildTagFor derives the opt-out build tag for an id.
func BuildTagFor(id string) string {
	b := []byte(id)
	for i, ch := range b {
		if ch == '.' || ch == '-' {
			b[i] = '_'
		}
	}
	return "sbo_omit_" + string(b)
}

// ArtifactKind is the kind of an external artifact.
type ArtifactKind string

// The closed ArtifactKind vocabulary.
const (
	ArtifactBrowserExtension ArtifactKind = "browser_extension"
	ArtifactHelperBinary     ArtifactKind = "helper_binary"
	// ArtifactEditorExtension is an editor extension installed through the
	// editor's own marketplace (the VS Code extension, lane MP-ART).
	ArtifactEditorExtension ArtifactKind = "editor_extension"
	// ArtifactPluginShim is a file Observer renders into another tool's
	// in-process plugin directory (internal/hook/pluginshim).
	ArtifactPluginShim ArtifactKind = "plugin_shim"
)

// ArtifactComponent is anything installed outside the Observer binary whose
// lifecycle Observer does not control (plan 3.3.2). Artifacts never appear
// in the distro columns.
type ArtifactComponent struct {
	ID        string
	Kind      ArtifactKind
	Title     string
	About     string
	Platforms []string
	Source    string
	Signer    string
	Protocol  string
	States    []string
	Requires  []string
	Surface   Surface
	Ownership string
	// NotInstalled says what "not installed" means for this artifact (plan
	// 3.3.1): what Observer can and cannot see (lane MP-ART, T-601).
	NotInstalled string
	// Removal says how the artifact is removed and what Observer reports as
	// a leftover when its component is inactive.
	Removal string
	// Lockstep says how the artifact's version relates to the observer
	// release (what the version-lockstep checks pin).
	Lockstep string
	// VersionFile is the repo path whose "version" the release stamp
	// (scripts/sync-npm-version.sh) writes, or "" when the artifact has no
	// version file of its own. tests/invariant/artifact_lockstep_test.go
	// pins that the stamp script names it and that it agrees with the
	// release version.
	VersionFile string
}
