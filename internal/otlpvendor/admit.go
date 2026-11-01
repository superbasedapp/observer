package otlpvendor

// Admission is what one vendor's export may write on this node.
type Admission struct {
	Tokens  bool
	Tools   bool
	Content bool
	// Timing: the export's per-call generation durations (Result.GenTimings)
	// may be stamped onto the tool's own transcript token rows. Only while
	// the transcript adapter captures (it owns those rows; with it off the
	// export's turn carries its own duration) and only for a row that
	// declares the join (Vendor.TranscriptTiming). The stamp fills a row
	// with no timing of its own and never replaces the transcript's.
	Timing bool
	// Refused, when set, says why nothing from this export lands here.
	Refused string
	// TokensOwner, when set, says why the export's token rows do not land
	// although the rest of the export may (TokensOwnedByProxy).
	TokensOwner string
}

// RefusedTeamGrain is the refusal for a team-grain export.
const RefusedTeamGrain = "team-grain export (sent once per team from the vendor's cloud): its destination is the org server, not one developer's node"

// TokensOwnedByProxy is Admission.TokensOwner when the tool's proxy route is
// active and the export's turns cannot merge into the proxy's own rows
// (operator ruling D-343, "proxy owns tokens"; T-536).
const TokensOwnedByProxy = "the tool's proxy route is active: the proxy owns its token rows (the export carries no id equal to the proxy's request id, so the same call would land twice); tool calls and content from the export still land"

// AdmitInput is what the node resolved at its boundary about one export.
// Every field is read from configuration or from the export's own resource
// (never from previously stored rows), so a decision cannot race the data.
type AdmitInput struct {
	// TranscriptCapture: the tool's own transcript adapter is enabled on
	// this node ([observer.watch].enabled_adapters).
	TranscriptCapture bool
	// ProxyRouted: the tool's calls go through this node's proxy: its
	// persisted route points at the proxy, or the export's resource
	// carries the launcher's route marker (RouteResourceAttr).
	ProxyRouted bool
}

// admitRule is one row of the ordered admission table.
type admitRule struct {
	when func(v Vendor, in AdmitInput) bool
	then func(v Vendor, in AdmitInput) Admission
}

// admitRules is walked top-down; the first row whose condition holds decides.
//  1. A team-grain export never lands on a node.
//  2. With the tool's proxy route active, the proxy owns the tokens unless
//     the export's turns merge into the proxy's rows by request id (the row
//     declares TokensMergeWithProxy): the export's token rows are dropped
//     and its other kinds follow the transcript rule below (T-536).
//  3. Otherwise the transcript rule decides (transcriptAdmission): with the
//     tool's own transcript capture off (adapter disabled, or the tool has
//     none) the export owns every kind; with it on, only the kinds the row
//     declares dedup-safe land (tokens fold against the transcript twin);
//     tool calls never do, because actions have no cross-path dedup. With
//     it on, the export's generation timing may stamp the transcript's own
//     token rows (Admission.Timing); the proxy route does not change that,
//     because a stamp adds no row.
var admitRules = []admitRule{
	{
		when: func(v Vendor, _ AdmitInput) bool { return v.Grain == GrainTeam },
		then: func(Vendor, AdmitInput) Admission { return Admission{Refused: RefusedTeamGrain} },
	},
	{
		when: func(v Vendor, in AdmitInput) bool { return in.ProxyRouted && !v.Owner.TokensMergeWithProxy },
		then: func(v Vendor, in AdmitInput) Admission {
			a := transcriptAdmission(v, in.TranscriptCapture)
			a.Tokens, a.TokensOwner = false, TokensOwnedByProxy
			return a
		},
	},
	{
		when: func(Vendor, AdmitInput) bool { return true },
		then: func(v Vendor, in AdmitInput) Admission { return transcriptAdmission(v, in.TranscriptCapture) },
	},
}

// transcriptAdmission is the transcript rule: what lands given only whether
// the tool's transcript capture is active.
func transcriptAdmission(v Vendor, transcriptCapture bool) Admission {
	if !transcriptCapture {
		return Admission{Tokens: true, Tools: true, Content: true}
	}
	return Admission{
		Tokens: v.Owner.TokensWithTranscript, Content: v.Owner.ContentWithTranscript,
		Timing: v.TranscriptTiming != "",
	}
}

// AdmitWith resolves what a vendor's export may write on this node.
func AdmitWith(v Vendor, in AdmitInput) Admission {
	for _, r := range admitRules {
		if r.when(v, in) {
			return r.then(v, in)
		}
	}
	return Admission{}
}

// Admit resolves what a vendor's export may write, given only whether the
// tool's own transcript capture is active (no proxy route).
func Admit(v Vendor, transcriptCapture bool) Admission {
	return AdmitWith(v, AdmitInput{TranscriptCapture: transcriptCapture})
}
