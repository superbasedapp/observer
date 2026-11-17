package attachrule

// Kind is the kind of a destination.
type Kind int

// Destination kinds. KindNone is the zero value: no destination.
const (
	// KindNone means data stays local.
	KindNone Kind = iota
	// KindPersonal is the user's personal org.
	KindPersonal
	// KindTeamOrg is a team org on the SaaS.
	KindTeamOrg
	// KindPrivateServer is a customer-run server.
	KindPrivateServer
)

// Tenancy is how a destination treats the machine.
type Tenancy int

// Tenancy values; the zero value is individual.
const (
	// TenancyIndividual is a node-controlled, metadata-only attachment.
	TenancyIndividual Tenancy = iota
	// TenancyManaged is an org-controlled attachment.
	TenancyManaged
)

// Intent is what the user asked for.
type Intent int

// Intents. The zero value is invalid and is refused by row 10.
const (
	// IntentInvalid is the zero value.
	IntentInvalid Intent = iota
	// IntentIdentityOnly signs in or out without touching the destination.
	IntentIdentityOnly
	// IntentAttach attaches to, or switches to, a destination.
	IntentAttach
	// IntentDisconnect leaves the current destination.
	IntentDisconnect
)

// Destination names a place data can go.
type Destination struct {
	// Kind is the destination kind.
	Kind Kind
	// Tenancy is the tenancy in force (for the current destination).
	Tenancy Tenancy
	// OrgID identifies the org or server; with Kind it is the identity.
	OrgID string
	// Name is the display name shown to the user.
	Name string
}

// Lock is a company-config lock to one destination.
type Lock struct {
	// Destination is the only allowed destination.
	Destination Destination
	// AskWho names who to ask to change it.
	AskWho string
}

// Input is everything Decide needs.
type Input struct {
	// Current is the destination now in force.
	Current Destination
	// Lock is the company-config lock, nil when none.
	Lock *Lock
	// Intent is what the user asked for.
	Intent Intent
	// Requested is the asked-for destination; Kind none means unspecified.
	Requested Destination
	// Listed is the orgs the control plane lists for this user. It may be
	// empty and may be incomplete.
	Listed []Destination
	// MultiEnabled reports whether several destinations are enabled (M10).
	MultiEnabled bool
	// PolicyAllowsSecondDestination reports whether company policy allows a
	// second destination (D-34).
	PolicyAllowsSecondDestination bool
}

// Outcome is the closed set of results.
type Outcome int

// Outcomes. The zero value is invalid.
const (
	// OutcomeInvalid is the zero value and is never returned by Decide.
	OutcomeInvalid Outcome = iota
	// OutcomeAllow proceeds.
	OutcomeAllow
	// OutcomeAllowWithConfirmation proceeds after an explicit confirmation.
	OutcomeAllowWithConfirmation
	// OutcomeRefuse stops, with a Refusal.
	OutcomeRefuse
	// OutcomeOfferOne offers the single listed org, with a preview.
	OutcomeOfferOne
	// OutcomeShowChooser lists several orgs.
	OutcomeShowChooser
	// OutcomeOfferCreatePersonal offers to create the personal org.
	OutcomeOfferCreatePersonal
)

// RefusalReason is why a request was refused.
type RefusalReason int

// Refusal reasons. The zero value means not refused.
const (
	// RefusalNone is the zero value.
	RefusalNone RefusalReason = iota
	// RefusalLocked is row 1: company config locks the destination.
	RefusalLocked
	// RefusalPersonalOnManaged is row 5: a managed machine cannot also use
	// the personal org (before M10).
	RefusalPersonalOnManaged
	// RefusalPolicyNoSecondDestination is row 5 after M10 when the company
	// policy does not allow a second destination.
	RefusalPolicyNoSecondDestination
	// RefusalAlreadyAttached is row 10: the requested destination is the
	// current one.
	RefusalAlreadyAttached
	// RefusalUnsupported is row 10: nothing else matched.
	RefusalUnsupported
)

// Refusal carries what the UI must say for a refusal.
type Refusal struct {
	// Reason is the closed reason.
	Reason RefusalReason
	// LockOrgName names the locking org (row 1).
	LockOrgName string
	// AskWho names who to ask (row 1).
	AskWho string
}

// Decision is the result of Decide.
type Decision struct {
	// Row is the matched row number, 1-10.
	Row int
	// Outcome is the closed outcome.
	Outcome Outcome
	// DestinationUnchanged is true when only identity changes (rows 1, 2).
	DestinationUnchanged bool
	// Drain is true when the drain must run before leaving the current
	// destination (5.6).
	Drain bool
	// ConfirmOrgName is the old org the user confirms against (row 4).
	ConfirmOrgName string
	// ShowLeftBehind is true when the UI must state how many sessions stay
	// behind (rows 4, 6).
	ShowLeftBehind bool
	// Refusal is set when Outcome is OutcomeRefuse.
	Refusal *Refusal
	// Target is the destination to attach to, when one is determined.
	Target Destination
	// Choices is the orgs to show (rows 7, 8).
	Choices []Destination
	// ChooserMayBeIncomplete is true when the UI must say the list may be
	// incomplete.
	ChooserMayBeIncomplete bool
	// OfferEnterAddress is true when the UI also offers "Is your company's
	// org missing? Enter its address" (row 9).
	OfferEnterAddress bool
}

// Row is one rule in the precedence table.
type Row struct {
	// ID is the row number, 1-10.
	ID int
	// Situation is a short description of the row.
	Situation string
	// Match reports whether the row applies.
	Match func(Input) bool
	// Decide builds the decision for a matching input.
	Decide func(Input) Decision
}

// Decide walks table top-down and returns the first matching row's decision.
// Row 10 matches everything, so a decision is always returned.
func Decide(in Input) Decision {
	for _, r := range table {
		if r.Match(in) {
			d := r.Decide(in)
			d.Row = r.ID
			return d
		}
	}
	return refuse(RefusalUnsupported) // unreachable: row 10 matches all
}

func refuse(reason RefusalReason) Decision {
	return Decision{Outcome: OutcomeRefuse, Refusal: &Refusal{Reason: reason}}
}

func same(a, b Destination) bool { return a.Kind == b.Kind && a.OrgID == b.OrgID }

func hasRequest(in Input) bool { return in.Requested.Kind != KindNone }

func isManaged(d Destination) bool { return d.Kind != KindNone && d.Tenancy == TenancyManaged }

func isIndividual(d Destination) bool { return d.Kind != KindNone && d.Tenancy == TenancyIndividual }

// switchRequested reports an attach to a destination other than the current.
func switchRequested(in Input) bool {
	return in.Intent == IntentAttach && hasRequest(in) && !same(in.Current, in.Requested)
}

// discovery is the shared guard of rows 7-9: attach, no destination, and no
// requested destination (the connect-without-argument path).
func discovery(in Input) bool {
	return in.Intent == IntentAttach && in.Current.Kind == KindNone && !hasRequest(in)
}

// table is the ordered precedence table (plan 06 section 19.3 rule 3).
var table = []Row{
	{
		ID: 1, Situation: "company config locks the destination",
		Match: func(in Input) bool { return in.Lock != nil },
		Decide: func(in Input) Decision {
			l := in.Lock
			if in.Intent == IntentIdentityOnly {
				return Decision{Outcome: OutcomeAllow, DestinationUnchanged: true}
			}
			if in.Intent == IntentAttach && (!hasRequest(in) || same(in.Requested, l.Destination)) {
				return Decision{Outcome: OutcomeAllow, Target: l.Destination}
			}
			return Decision{Outcome: OutcomeRefuse, Refusal: &Refusal{
				Reason: RefusalLocked, LockOrgName: l.Destination.Name, AskWho: l.AskWho,
			}}
		},
	},
	{
		ID: 2, Situation: "intent is identity only",
		Match: func(in Input) bool { return in.Intent == IntentIdentityOnly },
		Decide: func(Input) Decision {
			return Decision{Outcome: OutcomeAllow, DestinationUnchanged: true}
		},
	},
	{
		ID: 3, Situation: "intent is disconnect",
		Match: func(in Input) bool { return in.Intent == IntentDisconnect },
		Decide: func(in Input) Decision {
			return Decision{Outcome: OutcomeAllow, Drain: in.Current.Kind != KindNone}
		},
	},
	{
		ID: 4, Situation: "managed, not locked; a different team org or private server requested",
		Match: func(in Input) bool {
			return isManaged(in.Current) && switchRequested(in) &&
				(in.Requested.Kind == KindTeamOrg || in.Requested.Kind == KindPrivateServer)
		},
		Decide: func(in Input) Decision {
			return Decision{
				Outcome: OutcomeAllowWithConfirmation, Drain: true, ShowLeftBehind: true,
				ConfirmOrgName: in.Current.Name, Target: in.Requested,
			}
		},
	},
	{
		ID: 5, Situation: "managed; the personal org requested",
		Match: func(in Input) bool {
			return isManaged(in.Current) && in.Intent == IntentAttach && in.Requested.Kind == KindPersonal
		},
		Decide: func(in Input) Decision {
			switch {
			case !in.MultiEnabled:
				return refuse(RefusalPersonalOnManaged)
			case !in.PolicyAllowsSecondDestination:
				return refuse(RefusalPolicyNoSecondDestination)
			}
			return Decision{Outcome: OutcomeAllow, Target: in.Requested}
		},
	},
	{
		ID: 6, Situation: "individual or no destination; a different one requested",
		Match: func(in Input) bool {
			return (isIndividual(in.Current) || in.Current.Kind == KindNone) && switchRequested(in)
		},
		Decide: func(in Input) Decision {
			had := in.Current.Kind != KindNone
			return Decision{Outcome: OutcomeAllow, Drain: had, ShowLeftBehind: had, Target: in.Requested}
		},
	},
	{
		ID: 7, Situation: "no destination; exactly one org listed",
		Match: func(in Input) bool { return discovery(in) && len(in.Listed) == 1 },
		Decide: func(in Input) Decision {
			return Decision{
				Outcome: OutcomeOfferOne, Target: in.Listed[0],
				Choices: in.Listed, ChooserMayBeIncomplete: true,
			}
		},
	},
	{
		ID: 8, Situation: "no destination; several orgs listed",
		Match: func(in Input) bool { return discovery(in) && len(in.Listed) > 1 },
		Decide: func(in Input) Decision {
			return Decision{Outcome: OutcomeShowChooser, Choices: in.Listed, ChooserMayBeIncomplete: true}
		},
	},
	{
		ID: 9, Situation: "no destination; no orgs listed",
		Match: func(in Input) bool { return discovery(in) && len(in.Listed) == 0 },
		Decide: func(Input) Decision {
			return Decision{
				Outcome: OutcomeOfferCreatePersonal, OfferEnterAddress: true,
				ChooserMayBeIncomplete: true,
			}
		},
	},
	{
		ID: 10, Situation: "anything else",
		Match: func(Input) bool { return true },
		Decide: func(in Input) Decision {
			if in.Intent == IntentAttach && hasRequest(in) && same(in.Current, in.Requested) {
				return refuse(RefusalAlreadyAttached)
			}
			return refuse(RefusalUnsupported)
		},
	},
}
