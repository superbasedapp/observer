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
