package sandboxvocab

// IsoClass is the isolation class ladder (section 4.1): the strongest
// boundary a layer puts between the agent and the host. Its rank orders
// floors; the zero value is not a class.
type IsoClass string

// The closed IsoClass vocabulary, weakest first.
const (
	ClassNone            IsoClass = "none"
	ClassProcess         IsoClass = "process"
	ClassContainer       IsoClass = "container"
	ClassUserspaceKernel IsoClass = "userspace_kernel"
	ClassHWVM            IsoClass = "hw_vm"
)

var classRank = map[IsoClass]int{ClassNone: 0, ClassProcess: 1, ClassContainer: 2, ClassUserspaceKernel: 3, ClassHWVM: 4}

// Classes returns the ladder, weakest first.
func Classes() []IsoClass {
	return []IsoClass{ClassNone, ClassProcess, ClassContainer, ClassUserspaceKernel, ClassHWVM}
}

// Rank is the class's position on the ladder; -1 for an unknown value.
func (c IsoClass) Rank() int {
	if r, ok := classRank[c]; ok {
		return r
	}
	return -1
}

// Valid reports whether c is in the vocabulary.
func (c IsoClass) Valid() bool { return c.Rank() >= 0 }

// ClassSource says how a class is known (section 4.1). For floors a
// claimed class counts as none.
type ClassSource string

// The closed ClassSource vocabulary.
const (
	SourceMeasured   ClassSource = "measured"
	SourceDocumented ClassSource = "documented"
	SourceClaimed    ClassSource = "claimed"
)

// CountsForFloor reports whether a class or tier known this way may meet a
// floor (measured or documented; never claimed or unknown).
func (s ClassSource) CountsForFloor() bool {
	return s == SourceMeasured || s == SourceDocumented
}

// CaptureLevel is what Observer captures of a run (section 4.4). It is
// COMPUTED per run, never read from a row. The zero value is not a level.
type CaptureLevel string

// The closed CaptureLevel vocabulary, weakest first.
const (
	CaptureNone                CaptureLevel = "none"
	CaptureTranscriptsOnly     CaptureLevel = "transcripts_only"
	CaptureProxyAndTranscripts CaptureLevel = "proxy_and_transcripts"
	CaptureFull                CaptureLevel = "full"
)

var captureRank = map[CaptureLevel]int{CaptureNone: 0, CaptureTranscriptsOnly: 1, CaptureProxyAndTranscripts: 2, CaptureFull: 3}

// CaptureLevels returns the levels, weakest first.
func CaptureLevels() []CaptureLevel {
	return []CaptureLevel{CaptureNone, CaptureTranscriptsOnly, CaptureProxyAndTranscripts, CaptureFull}
}

// Rank orders capture levels; -1 for an unknown value.
func (c CaptureLevel) Rank() int {
	if r, ok := captureRank[c]; ok {
		return r
	}
	return -1
}

// Valid reports whether c is in the vocabulary.
func (c CaptureLevel) Valid() bool { return c.Rank() >= 0 }

// MinCapture returns the weaker of two levels; an unknown level is the
// weakest of all (CaptureNone).
func MinCapture(a, b CaptureLevel) CaptureLevel {
	if !a.Valid() || !b.Valid() {
		return CaptureNone
	}
	if a.Rank() <= b.Rank() {
		return a
	}
	return b
}

// CaptureOrigin says where the rows of a run could have been written from
// (section 8.4): the host attested them, a box on this machine could have
// written them, or a remote box could have.
type CaptureOrigin string

// The closed CaptureOrigin vocabulary.
const (
	OriginLocal         CaptureOrigin = "local"
	OriginSandboxed     CaptureOrigin = "sandboxed"
	OriginRemoteSandbox CaptureOrigin = "remote_sandbox"
)

// Valid reports whether o is in the closed vocabulary.
func (o CaptureOrigin) Valid() bool {
	switch o {
	case OriginLocal, OriginSandboxed, OriginRemoteSandbox:
		return true
	}
	return false
}

// Verification is the grounding of a backend on one host (section 4.2):
// live (proven on a real host, with an in-repo receipt), doc (built from
// vendor docs only, labelled "beta" everywhere), fixture, inferred.
type Verification string

// The closed Verification vocabulary.
const (
	VerifiedLive     Verification = "live"
	VerifiedDoc      Verification = "doc"
	VerifiedFixture  Verification = "fixture"
	VerifiedInferred Verification = "inferred"
)

// Valid reports whether v is in the closed vocabulary.
func (v Verification) Valid() bool {
	switch v {
	case VerifiedLive, VerifiedDoc, VerifiedFixture, VerifiedInferred:
		return true
	}
	return false
}

// IsBeta reports whether a surface must render the grounding as "beta":
// anything that is not live.
func (v Verification) IsBeta() bool { return v != VerifiedLive }

// KeyCustody is where the model credential of a run sits (section 7.2).
type KeyCustody string

// The closed KeyCustody vocabulary. CustodyHostBound is the local-row case
// the plan describes as "bound real tool state holding an OAuth token": the
// agent reads its own credential from the host's tool state.
const (
	CustodyHomeRelay        KeyCustody = "home_relay"
	CustodyProviderInjected KeyCustody = "provider_injected"
	CustodyInBoxAPIKey      KeyCustody = "in_box_api_key" //nolint:gosec // a custody mode name, not a credential
	CustodyInBoxOAuthSeed   KeyCustody = "in_box_oauth_seed"
	CustodyHostBound        KeyCustody = "host_bound"
)

// CustodyAuto is a CONFIGURATION value of [terminal.sandbox.hosted]
// .key_custody, never a run's custody (decision SBXD-1): per launch and per
// tool it resolves to home_relay when this machine can add the key for that
// tool, otherwise to in_box_api_key (internal/sandboxcred ResolveCustody,
// the one owner). A run's evidence and plan record the resolved value, so
// Valid stays the closed set of run custodies and does not accept it.
const CustodyAuto KeyCustody = "auto"

// Valid reports whether k is in the closed vocabulary.
func (k KeyCustody) Valid() bool {
	switch k {
	case CustodyHomeRelay, CustodyProviderInjected, CustodyInBoxAPIKey, CustodyInBoxOAuthSeed, CustodyHostBound:
		return true
	}
	return false
}

// NativeSandboxState records what Observer did with the agent's own
// sandbox (section 4.4).
type NativeSandboxState string

// The closed NativeSandboxState vocabulary. NativeNotApplicable is a tool
// with no native sandbox.
const (
	NativeOn                  NativeSandboxState = "on"
	NativeWeak                NativeSandboxState = "weak"
	NativeDisabledByObserver  NativeSandboxState = "disabled_by_observer"
	NativeDisabledByUser      NativeSandboxState = "disabled_by_user"
	NativeOrgForced           NativeSandboxState = "org_forced"
	NativeUnavailableFellBack NativeSandboxState = "unavailable_fell_back"
	NativeNotApplicable       NativeSandboxState = "not_applicable"
)

// Valid reports whether n is in the closed vocabulary.
func (n NativeSandboxState) Valid() bool {
	switch n {
	case NativeOn, NativeWeak, NativeDisabledByObserver, NativeDisabledByUser, NativeOrgForced, NativeUnavailableFellBack, NativeNotApplicable:
		return true
	}
	return false
}

// Tier is an egress tier spelling (the shipped internal/sandbox table owns
// what each tier builds; these are its names for core readers).
type Tier string

// The closed Tier vocabulary, most open first.
const (
	TierHost      Tier = "host"
	TierInternet  Tier = "internet"
	TierProxyOnly Tier = "proxy_only"
	TierNone      Tier = "none"
)

var tierStrictness = map[Tier]int{TierHost: 0, TierInternet: 1, TierProxyOnly: 2, TierNone: 3}

// Tiers returns the tiers, most open first.
func Tiers() []Tier { return []Tier{TierHost, TierInternet, TierProxyOnly, TierNone} }

// Strictness orders tiers (a higher value lets less out); -1 when unknown.
func (t Tier) Strictness() int {
	if r, ok := tierStrictness[t]; ok {
		return r
	}
	return -1
}

// Valid reports whether t is in the vocabulary.
func (t Tier) Valid() bool { return t.Strictness() >= 0 }

// Location is where a box runs (section 4.1).
type Location string

// The closed Location vocabulary.
const (
	LocationLocal  Location = "local"
	LocationRemote Location = "remote"
)

// Seccomp is the syscall filter a layer puts on the agent (gap G16, lane
// N2): the registry's grounded field and the state a run's seccomp
// read-back names. The zero value means not grounded.
type Seccomp string

// The closed Seccomp vocabulary.
const (
	// SeccompNone: the layer adds no syscall filter of its own.
	SeccompNone Seccomp = "none"
	// SeccompEngineDefault: the container engine's own default profile,
	// read back from the engine (the OCI rows).
	SeccompEngineDefault Seccomp = "engine_default"
	// SeccompObserverProfile: Observer's own profile
	// (internal/sandboxseccomp), loaded by the layer when
	// [terminal.sandbox].seccomp is on and read back from /proc before the
	// agent runs (bwrap, process_lite).
	SeccompObserverProfile Seccomp = "observer_profile"
)

// Valid reports whether s is in the closed vocabulary.
func (s Seccomp) Valid() bool {
	switch s {
	case SeccompNone, SeccompEngineDefault, SeccompObserverProfile:
		return true
	}
	return false
}

// SeccompRun is what one run's agent got from the syscall filter (tracker
// F-002, lane FU4): the per-run evidence (terminal_run.seccomp) and the
// posture bucket. A filter that was applied is named by its id, so the one
// value says both whether a filter was applied and which one. The empty
// value means not recorded (a run from before the column).
type SeccompRun string

// The closed SeccompRun vocabulary.
const (
	// SeccompRunObserverDefault: Observer's profile observer_default
	// (internal/sandboxseccomp.ProfileObserverDefault, pinned equal by a
	// test) was planned and is enforced: the value is recorded when the run
	// is created, before the host helper's read-back, and a run whose
	// read-back refuses is ended with that refusal (fail closed) while its
	// row keeps this value (audit FU4-A4). A recorded observer_default
	// therefore means "planned, and enforced on every run that went on".
	// Nothing on the run row tells a refused run apart (tracker F-035): on
	// bwrap the refusal reaches the run only as the host helper's exit 125
	// and the refusal text in the run's terminal (which names
	// built_below_plan and the state), and the sandbox posture still counts
	// the run as filtered.
	SeccompRunObserverDefault SeccompRun = "observer_default"
	// SeccompRunObserverSeizePIDNS and SeccompRunObserverSeizeYama: Observer's
	// profile with PTRACE_SEIZE lifted, because [terminal.sandbox]
	// .seccomp_allow_seize was on and a containment ground held at launch (lane
	// ptrace, PT-96): the sandbox's own pid namespace, or Yama ptrace_scope 1
	// or more. The value names the ground. Each equals its profile id
	// (internal/sandboxseccomp, pinned by a test) and is enforced like
	// observer_default: the host helper re-checks the ground and reads the
	// filter back before the run goes on, or refuses it.
	SeccompRunObserverSeizePIDNS SeccompRun = "observer_seize_pidns"
	SeccompRunObserverSeizeYama  SeccompRun = "observer_seize_yama"
	// SeccompRunEngineDefault: the container engine's own default profile,
	// read back from the engine.
	SeccompRunEngineDefault SeccompRun = "engine_default"
	// SeccompRunOff: the row loads Observer's profile on request, and
	// [terminal.sandbox].seccomp was off.
	SeccompRunOff SeccompRun = "off"
	// SeccompRunNotApplicable: [terminal.sandbox].seccomp was on, but no
	// layer of the row loads Observer's profile or carries a grounded
	// engine filter (macOS, Windows, VM, hosted and openshell rows; a
	// backend may apply its own filter Observer has not grounded): the run
	// was not filtered by Observer, and the launch said so (audit N2-A9).
	SeccompRunNotApplicable SeccompRun = "not_applicable"
	// SeccompRunNone: the key was off and no layer carries a grounded
	// filter.
	SeccompRunNone SeccompRun = "none"
)

// SeccompRuns lists the vocabulary, applied filters first.
func SeccompRuns() []SeccompRun {
	return []SeccompRun{SeccompRunObserverDefault, SeccompRunObserverSeizePIDNS, SeccompRunObserverSeizeYama, SeccompRunEngineDefault, SeccompRunOff, SeccompRunNotApplicable, SeccompRunNone}
}

// Valid reports whether s is in the closed vocabulary.
func (s SeccompRun) Valid() bool {
	for _, v := range SeccompRuns() {
		if s == v {
			return true
		}
	}
	return false
}

// Applied reports whether the value names a filter that was on the agent.
func (s SeccompRun) Applied() bool {
	return s == SeccompRunObserverDefault || s.LiftsSeize() || s == SeccompRunEngineDefault
}

// LiftsSeize reports whether the value names Observer's profile with
// PTRACE_SEIZE lifted (lane ptrace, PT-96).
func (s SeccompRun) LiftsSeize() bool {
	return s == SeccompRunObserverSeizePIDNS || s == SeccompRunObserverSeizeYama
}
