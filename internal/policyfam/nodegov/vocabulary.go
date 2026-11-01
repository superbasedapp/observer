package nodegov

// Vocabulary() is the ONE source of truth the admin console's node.governance
// form is populated from (Phase-1b mini-spec §5.1). It returns the compiler's
// OWN tables, so an admin cannot compose a body the compiler rejects: every
// picker in the form is filled from the same data the publish lint and the
// agent accept path enforce against.
//
// There is deliberately no hand-authored list in the server handler and none
// in the SPA. That is the anti-drift property; a second list would eventually
// disagree with this one and the disagreement would surface as a fleet of
// nodes reporting decode_failed.

// VocabSection is one hideable/lockable section id with its display label
// and its T8 unhideable flag.
type VocabSection struct {
	ID         string `json:"id"`
	Label      string `json:"label"`
	Unhideable bool   `json:"unhideable"`
	// ManagedDefault is the level a MANAGED developer machine applies when
	// the org publishes nothing for this id (ManagedNavDefaults /
	// ManagedSettingsDefaults); ManagedWhy is that row's reason. The org's
	// Developer dashboards card marks the default from these two fields, so
	// the admin console cannot disagree with what nodes actually apply.
	ManagedDefault Visibility `json:"managed_default"`
	ManagedWhy     string     `json:"managed_why,omitempty"`
}

// VocabPinnableKey is the wire shape of one PinnableKeys row.
type VocabPinnableKey struct {
	Key       string `json:"key"`
	Kind      string `json:"kind"`
	Enum      []any  `json:"enum,omitempty"`
	Direction string `json:"direction"`
	Safe      any    `json:"safe,omitempty"`
	// Min / Max are an int row's inclusive bounds (omitted when unbounded).
	Min   int64  `json:"min,omitempty"`
	Max   int64  `json:"max,omitempty"`
	Label string `json:"label"`
	// Help is the row's optional plain-language note (PinnableKey.Help).
	Help string `json:"help,omitempty"`
}

// VocabNotPinnable is the wire shape of one NotPinnableYet row.
type VocabNotPinnable struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Reason string `json:"reason"`
}

// VocabShareKey is the wire shape of one ShareKeys row. Direction is always
// "lowering_only" — it is a property of the whole block (§2.1), restated per
// row so a form renderer never has to know that out of band.
type VocabShareKey struct {
	Key       string `json:"key"`
	Kind      string `json:"kind"`
	Direction string `json:"direction"`
	Label     string `json:"label"`
}

// VocabFeature is the wire shape of one Features row, INCLUDING the pin it
// expands to, so the admin can see a feature lock is not a separate power.
type VocabFeature struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Direction string `json:"direction"`
	Label     string `json:"label"`
}

// VocabAuthority pairs an authority token with the directive classes it
// unlocks. A RETIRED token is listed with an empty directive list and
// retired:true rather than omitted: an admin looking at an older grant must
// be able to see that the token exists and grants nothing.
type VocabAuthority struct {
	Token      string   `json:"token"`
	Directives []string `json:"directives"`
	Retired    bool     `json:"retired,omitempty"`
}

// VocabTab is one page tab (per-tab visibility, T-132). ID is the value an org
// body names in sections.hidden ("security/prompt-guard"); Page and Tab are its
// two halves, so a form renders the tab under its page without parsing the id.
// A tab can only be hidden; it has no managed default (it follows its page).
type VocabTab struct {
	ID    string `json:"id"`
	Page  string `json:"page"`
	Tab   string `json:"tab"`
	Label string `json:"label"`
}

// Vocab is the whole payload.
type Vocab struct {
	Family           string             `json:"family"`
	Schema           int                `json:"schema"`
	NavSections      []VocabSection     `json:"nav_sections"`
	NavTabs          []VocabTab         `json:"nav_tabs"`
	SettingsSections []VocabSection     `json:"settings_sections"`
	PinnableKeys     []VocabPinnableKey `json:"pinnable_keys"`
	// NotPinnableYet lists keys the pin panel shows as "not pinnable yet",
	// each with its reason (NotPinnableYet in pinnable.go). Omitted when
	// empty, so an older console that does not read it sees nothing new.
	NotPinnableYet  []VocabNotPinnable `json:"not_pinnable_yet,omitempty"`
	ShareKeys       []VocabShareKey    `json:"share_keys"`
	Features        []VocabFeature     `json:"features"`
	AuthorityTokens []VocabAuthority   `json:"authority_tokens"`
}

// The authority-token literals are duplicated here rather than imported from
// internal/govern for the same dependency-graph reason internal/govern
// duplicates nothing in the other direction: govern depends on THIS package,
// never the reverse (pinned by imports_test.go). vocab_source_test.go pins
// the two lists together.
const (
	authorityDashboardVisibility = "dashboard.visibility"
	authoritySettingsPin         = "settings.pin"
	authorityCapturePin          = "capture.pin"
	authorityCaptureRaise        = "capture.raise"
	authorityFeatureLock         = "feature.lock"
)

// Vocabulary returns the closed vocabularies of the current body schema.
func Vocabulary() Vocab {
	v := Vocab{Family: "node.governance", Schema: MaxSchema}
	for _, id := range NavSectionIDs {
		v.NavSections = append(v.NavSections, VocabSection{
			ID: id, Label: SectionLabel(id), Unhideable: IsUnhideableNavSection(id),
			ManagedDefault: ManagedNavDefault(id), ManagedWhy: managedDefaultWhy(managedNavIndex, id),
		})
	}
	for _, p := range NavTabs {
		for _, t := range p.Tabs {
			v.NavTabs = append(v.NavTabs, VocabTab{ID: NavTabID(p.Page, t.ID), Page: p.Page, Tab: t.ID, Label: t.Label})
		}
	}
	for _, id := range SettingsSectionIDs {
		v.SettingsSections = append(v.SettingsSections, VocabSection{
			ID: id, Label: SectionLabel(id), Unhideable: IsUnhideableSettingsSection(id),
			ManagedDefault: ManagedSettingsDefault(id), ManagedWhy: managedDefaultWhy(managedSettingsIndex, id),
		})
	}
	for _, k := range PinnableKeys {
		v.PinnableKeys = append(v.PinnableKeys, VocabPinnableKey{
			Key: k.Key, Kind: k.Kind, Enum: k.Enum,
			Direction: string(k.Direction), Safe: k.Safe, Min: k.Min, Max: k.Max, Label: k.Label, Help: k.Help,
		})
	}
	for _, k := range NotPinnableYet {
		v.NotPinnableYet = append(v.NotPinnableYet, VocabNotPinnable{Key: k.Key, Label: k.Label, Reason: k.Reason})
	}
	for _, k := range ShareKeys {
		v.ShareKeys = append(v.ShareKeys, VocabShareKey{
			Key: k.Key, Kind: k.Kind, Direction: string(DirLoweringOnly), Label: k.Label,
		})
	}
	for _, f := range Features {
		dir := DirFree
		if row, ok := LookupPinnableKey(f.Key); ok {
			dir = row.Direction
		}
		v.Features = append(v.Features, VocabFeature{
			ID: f.ID, Key: f.Key, Direction: string(dir), Label: f.Label,
		})
	}
	v.AuthorityTokens = []VocabAuthority{
		{Token: authorityDashboardVisibility, Directives: []string{"sections"}},
		{Token: authoritySettingsPin, Directives: []string{"pinned"}},
		{Token: authorityCapturePin, Directives: []string{"share"}},
		{Token: authorityFeatureLock, Directives: []string{"features"}},
		{Token: authorityCaptureRaise, Directives: []string{}, Retired: true},
	}
	return v
}

// SectionLabel renders a section id as a display label. Ids are lowercase
// single words or snake_case; the label is the id title-cased, with the
// handful of ids whose natural label differs spelled out.
func SectionLabel(id string) string {
	if page, _, ok := SplitNavTab(id); ok {
		return SectionLabel(page) + " › " + navTabLabel[id]
	}
	if l, ok := sectionLabels[id]; ok {
		return l
	}
	return titleCase(id)
}

var sectionLabels = map[string]string{
	"otel":          "OpenTelemetry",
	"mcp":           "MCP",
	"cachetrack":    "Cache tracking",
	"codeintel":     "Code intelligence",
	"org":           "Organization",
	"enrolment":     "Enrolment",
	"observability": "Observability",
	"agent-config":  "AI tool settings",
}

func titleCase(id string) string {
	out := []rune(id)
	upper := true
	for i, r := range out {
		switch {
		case r == '_' || r == '-':
			out[i] = ' '
			upper = true
		case upper && r >= 'a' && r <= 'z':
			out[i] = r - 32
			upper = false
		default:
			upper = false
		}
	}
	return string(out)
}
