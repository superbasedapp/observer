package sandboxcred

import "github.com/marmutapp/superbased-observer/internal/sandboxkey"

// keyalias.go re-exports internal/sandboxkey, the pure model-key rules every
// hosted row needs (the provider table, the key custody table HomeKey and its
// auto resolution, the per-run provider binding and the opt-in in-box key
// sources), so the injection code here keeps its own spellings. The rules
// moved out so a build without the credential injection component
// (sbo_omit_terminals_sandbox_credentials) links no injection code at all:
// the hosted driver and the setup facts import sandboxkey directly.

// The re-exported types.
type (
	AuthForm          = sandboxkey.AuthForm
	BindFacts         = sandboxkey.BindFacts
	Broker            = sandboxkey.Broker
	BrokerStatus      = sandboxkey.BrokerStatus
	CustodyResolution = sandboxkey.CustodyResolution
	HomeKeyFacts      = sandboxkey.HomeKeyFacts
	HomeKeyVerdict    = sandboxkey.HomeKeyVerdict
	InjectedFacts     = sandboxkey.InjectedFacts
	LocalBindFacts    = sandboxkey.LocalBindFacts
	LoginSeedResult   = sandboxkey.LoginSeedResult
	LoginSeedSpec     = sandboxkey.LoginSeedSpec
	Provider          = sandboxkey.Provider
	SavedKeyField     = sandboxkey.SavedKeyField
	ToolRoute         = sandboxkey.ToolRoute
)

// The re-exported constants.
const (
	AuthBearer               = sandboxkey.AuthBearer
	AuthGoogKey              = sandboxkey.AuthGoogKey
	AuthXAPIKey              = sandboxkey.AuthXAPIKey
	BrokerBuilt              = sandboxkey.BrokerBuilt
	BrokerDocumentedNotBuilt = sandboxkey.BrokerDocumentedNotBuilt
	CodeCustodyNotAllowed    = sandboxkey.CodeCustodyNotAllowed
	CodeCustodyNotOffered    = sandboxkey.CodeCustodyNotOffered
	CustodyRuleHomeServes    = sandboxkey.CustodyRuleHomeServes
	CustodyRuleNodeSetting   = sandboxkey.CustodyRuleNodeSetting
	CustodyRuleNodeWide      = sandboxkey.CustodyRuleNodeWide
	CustodyRuleNothingHome   = sandboxkey.CustodyRuleNothingHome
	CustodyRuleRowKeepsKey   = sandboxkey.CustodyRuleRowKeepsKey
	CustodyRuleToolSetting   = sandboxkey.CustodyRuleToolSetting
	HomeKeyCustodyNotOffered = sandboxkey.HomeKeyCustodyNotOffered
	HomeKeyInBoxNoKey        = sandboxkey.HomeKeyInBoxNoKey
	HomeKeyInjectionNotBuilt = sandboxkey.HomeKeyInjectionNotBuilt
	HomeKeyLoginNotBuilt     = sandboxkey.HomeKeyLoginNotBuilt
	HomeKeyNothingServes     = sandboxkey.HomeKeyNothingServes
	HomeKeyRowKeepsKeyHome   = sandboxkey.HomeKeyRowKeepsKeyHome
	HomeKeyServedAuto        = sandboxkey.HomeKeyServedAuto
	HomeKeyServedInBox       = sandboxkey.HomeKeyServedInBox
	HomeKeyServedInjection   = sandboxkey.HomeKeyServedInjection
	HomeKeyServedOrgRoute    = sandboxkey.HomeKeyServedOrgRoute
	HomeKeyToolKeyMissing    = sandboxkey.HomeKeyToolKeyMissing
	HomeKeyToolProvider      = sandboxkey.HomeKeyToolProvider
	InjectedCaptureCeiling   = sandboxkey.InjectedCaptureCeiling
	KeystoreService          = sandboxkey.KeystoreService
	LoginSeedExpired         = sandboxkey.LoginSeedExpired
	LoginSeedNoExpiry        = sandboxkey.LoginSeedNoExpiry
	LoginSeedNoLogin         = sandboxkey.LoginSeedNoLogin
	LoginSeedOK              = sandboxkey.LoginSeedOK
	LoginSeedUnreadable      = sandboxkey.LoginSeedUnreadable
	VerdictCode              = sandboxkey.VerdictCode
)

// The re-exported functions.
var (
	BindLocal           = sandboxkey.BindLocal
	BindProviders       = sandboxkey.BindProviders
	BrokerFor           = sandboxkey.BrokerFor
	Brokers             = sandboxkey.Brokers
	CredEnvProvider     = sandboxkey.CredEnvProvider
	CustodySetting      = sandboxkey.CustodySetting
	Disclosure          = sandboxkey.Disclosure
	HomeKey             = sandboxkey.HomeKey
	InBoxDisclosure     = sandboxkey.InBoxDisclosure
	InBoxEnvProvider    = sandboxkey.InBoxEnvProvider
	InBoxKeyEnv         = sandboxkey.InBoxKeyEnv
	InjectableProviders = sandboxkey.InjectableProviders
	InjectedRefusal     = sandboxkey.InjectedRefusal
	Intersect           = sandboxkey.Intersect
	KeepHomeOffers      = sandboxkey.KeepHomeOffers
	KeyName             = sandboxkey.KeyName
	Known               = sandboxkey.Known
	MayPutKeyInBox      = sandboxkey.MayPutKeyInBox
	Offered             = sandboxkey.Offered
	OptInDisclosure     = sandboxkey.OptInDisclosure
	ProviderFor         = sandboxkey.ProviderFor
	ProviderForHost     = sandboxkey.ProviderForHost
	ProviderLabels      = sandboxkey.ProviderLabels
	Providers           = sandboxkey.Providers
	ResolveCustody      = sandboxkey.ResolveCustody
	ResolvedFacts       = sandboxkey.ResolvedFacts
	SavedKeys           = sandboxkey.SavedKeys
	SeedLogin           = sandboxkey.SeedLogin
	UsableProviders     = sandboxkey.UsableProviders
)

// hostIs is the provider table's host comparison (sandboxkey.HostIs).
func hostIs(host, want string) bool { return sandboxkey.HostIs(host, want) }
