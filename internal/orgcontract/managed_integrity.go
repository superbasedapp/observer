package orgcontract

import (
	"sort"
	"strings"
	"time"
)

const maxManagedIntegrityLabels = 16

// NormalizeLabels reduces every managed-integrity detail array to the closed,
// content-free wire vocabulary. Both client and server call it so paths,
// usernames, commands, config values, and error strings cannot cross the wire
// through these fields or enter server persistence through a custom client.
func (r ManagedIntegrityReport) NormalizeLabels() ManagedIntegrityReport {
	r.SiblingDetail = normalizeManagedLabels(r.SiblingDetail, validManagedSiblingLabel)
	r.DriftedTools = normalizeManagedLabels(r.DriftedTools, validDriftedToolLabel)
	r.RoutesWritten = normalizeManagedLabels(r.RoutesWritten, validDriftedToolLabel)
	r.UnroutableTools = normalizeManagedLabels(r.UnroutableTools, validDriftedToolLabel)
	r.UnselectedTools = normalizeManagedLabels(r.UnselectedTools, validDriftedToolLabel)
	r.RoutingOffTools = normalizeManagedLabels(r.RoutingOffTools, validDriftedToolLabel)
	r.InactiveProviderTools = nilIfEmpty(normalizeManagedLabels(r.InactiveProviderTools, validDriftedToolLabel))
	r = r.normalizeRouteObservation()
	r = r.normalizeConfigLayers()
	if r.CaptureCheckVersion != ManagedCaptureCheckVersion {
		r.CaptureCheckVersion = 0
		r.CaptureRisks = nil
		r.UnknownChecks = nil
		r.CaptureRiskItems = nil
		r.CaptureRiskItemsOmitted = 0
		return r
	}
	r.CaptureCheckVersion = ManagedCaptureCheckVersion
	r.CaptureRisks = normalizeManagedLabels(r.CaptureRisks, validCaptureRisk)
	r.CaptureRisks = r.syncDerivedRisks(r.CaptureRisks)
	r.UnknownChecks = normalizeManagedLabels(r.UnknownChecks, validUnknownCheck)
	items, omitted := NormalizeCaptureRiskItemsCounted(r.CaptureRiskItems)
	r.CaptureRiskItems = items
	r.CaptureRiskItemsOmitted = AddCaptureRiskItemsOmitted(r.CaptureRiskItemsOmitted, omitted)
	return r
}

// maxCaptureRiskItemsOmitted bounds the omitted-item count a report or a
// stored detail carries, a defensive floor on a node-supplied number.
const maxCaptureRiskItemsOmitted = 4096

// AddCaptureRiskItemsOmitted adds more omitted located risks to a carried
// count (T-873). A negative carried count is read as zero and the sum is
// bounded, so a custom client cannot store an arbitrary number.
func AddCaptureRiskItemsOmitted(carried, more int) int {
	if carried < 0 {
		carried = 0
	}
	if more > 0 {
		carried += more
	}
	if carried > maxCaptureRiskItemsOmitted {
		carried = maxCaptureRiskItemsOmitted
	}
	return carried
}

// ManagedIntegrityChangeWindow is how long a server-derived
// CaptureRiskChange stays in the stored detail (and so keeps the per-event
// fleet finding open) after it first appeared.
const ManagedIntegrityChangeWindow = 24 * time.Hour

// maxCaptureRiskChanges bounds the stored RecentChanges list.
const maxCaptureRiskChanges = 16

// ManagedIntegrityKnownWindow is how long the server remembers a risk the
// machine reported (ManagedIntegrityDetail.KnownRisks). A STANDING condition
// that reappears within it is not raised as a new event.
const ManagedIntegrityKnownWindow = 7 * 24 * time.Hour

// maxKnownCaptureRisks bounds ManagedIntegrityDetail.KnownRisks; the entries
// with the newest LastSeen are kept.
const maxKnownCaptureRisks = 32

// captureRiskClass says how a capture-risk label is judged when it appears in
// a report. The zero value is captureRiskAct, so a label this table does not
// name (a future one) is judged on the loud side.
type captureRiskClass int

const (
	// captureRiskAct is a one-off event (a deletion, a repair). It is judged
	// against the immediately prior report only, so the same act happening
	// again later is a new event.
	captureRiskAct captureRiskClass = iota
	// captureRiskStanding is a condition that holds until fixed. A
	// reappearance within ManagedIntegrityKnownWindow is the same condition
	// seen again, not a new event: it can vanish from a report for reasons
	// that are not a fix (the registry that detects it was deleted).
	captureRiskStanding
)

// captureRiskClasses classifies every capture-risk label (CLAUDE.md #5). A
// test pins that every CaptureRisk* constant has a row.
var captureRiskClasses = map[string]captureRiskClass{
	CaptureRiskHookBinaryMismatch:        captureRiskStanding,
	CaptureRiskHookConfigChanged:         captureRiskStanding,
	CaptureRiskCodexHookUntrusted:        captureRiskStanding,
	CaptureRiskHookRegistrationError:     captureRiskStanding,
	CaptureRiskHookRegistryEntryMissing:  captureRiskStanding,
	CaptureRiskAgentConfigDrift:          captureRiskStanding,
	CaptureRiskHookRepaired:              captureRiskAct,
	CaptureRiskRouteRepaired:             captureRiskAct,
	CaptureRiskRouteBypassObserved:       captureRiskStanding,
	CaptureRiskHookSilentSurface:         captureRiskStanding,
	CaptureRiskHookSwitchedOff:           captureRiskStanding,
	CaptureRiskConfigLayerOverride:       captureRiskStanding,
	CaptureRiskRouteInactiveProvider:     captureRiskStanding,
	CaptureRiskShellWrapMissing:          captureRiskStanding,
	CaptureRiskVendorPolicyBlocksMCP:     captureRiskStanding,
	CaptureRiskVendorPolicyPinsRoute:     captureRiskStanding,
	CaptureRiskSandboxGatewayConfigDrift: captureRiskStanding,
	CaptureRiskHookRegistrationFailed:    captureRiskAct,
	CaptureRiskHookRegistryMissing:       captureRiskAct,
	CaptureRiskHookConfigMissing:         captureRiskAct,
	CaptureRiskHookRegistrationDrift:     captureRiskAct,
}

// captureRiskPriority orders the capture-risk labels from the most to the
// least actionable (T-873, guard tamper re-test 2026-10-17 E1). The located
// risk bound (maxCaptureRiskItems) keeps items in this order, and the reasons
// list changes in it, so a node with many standing items still names the
// hook that could not be installed or was just put back. The order:
//
//   - a gate that is off or weakened right now (a registration error, a dry
//     run that would rewrite the hook, a hook file that is gone);
//   - a one-off act that was healed (the hash registry deleted, a failed
//     registration that has since cleared (T-887), a hook repaired);
//   - a standing condition, the long-lived binary path mismatch last
//     because one install spelled two ways reports it on every tool.
//
// A label with no row (a future one) sorts first, the loud side, like
// captureRiskClasses. A test pins that every CaptureRisk* constant has a row.
var captureRiskPriority = []string{
	CaptureRiskHookRegistrationError,
	CaptureRiskHookRegistrationDrift,
	CaptureRiskHookConfigMissing,
	CaptureRiskHookRegistryMissing,
	CaptureRiskHookRegistrationFailed,
	CaptureRiskHookRepaired,
	CaptureRiskRouteRepaired,
	CaptureRiskRouteBypassObserved,
	CaptureRiskRouteInactiveProvider,
	CaptureRiskVendorPolicyPinsRoute,
	CaptureRiskShellWrapMissing,
	CaptureRiskHookSwitchedOff,
	CaptureRiskVendorPolicyBlocksMCP,
	CaptureRiskConfigLayerOverride,
	CaptureRiskSandboxGatewayConfigDrift,
	CaptureRiskHookSilentSurface,
	CaptureRiskHookConfigChanged,
	CaptureRiskHookRegistryEntryMissing,
	CaptureRiskCodexHookUntrusted,
	CaptureRiskAgentConfigDrift,
	CaptureRiskHookBinaryMismatch,
}

// captureRiskRank is captureRiskPriority indexed by label.
var captureRiskRank = func() map[string]int {
	m := make(map[string]int, len(captureRiskPriority))
	for i, label := range captureRiskPriority {
		m[label] = i + 1
	}
	return m
}()

// CaptureRiskItemLess orders located risks by captureRiskPriority, then by
// Key, so the order is total and deterministic.
func CaptureRiskItemLess(a, b CaptureRiskItem) bool {
	ra, rb := captureRiskRank[a.Risk], captureRiskRank[b.Risk]
	if ra != rb {
		return ra < rb
	}
	return a.Key() < b.Key()
}

// isStandingCaptureRisk reports whether label is a standing condition.
func isStandingCaptureRisk(label string) bool {
	return captureRiskClasses[label] == captureRiskStanding
}

// OccurrenceKey is the identity of one occurrence of a located risk (T-886):
// Key, plus the act time for an act label that carries one (At). Two reports
// carrying the same Key but a different At describe two acts on the same
// artifact (a hook repaired, put back, and repaired again), so the second is
// a new event. A standing label, and an act without a time (an older node),
// is identified by Key alone.
func (it CaptureRiskItem) OccurrenceKey() string {
	if it.At == "" || isStandingCaptureRisk(it.Risk) {
		return it.Key()
	}
	return it.Key() + "@" + it.At
}

// normalizeRiskAt reduces an item's act time to the content floor: RFC3339
// UTC to the second on an act label, "" on a standing label or a value that
// does not parse.
func normalizeRiskAt(risk, at string) string {
	at = strings.TrimSpace(at)
	if at == "" || isStandingCaptureRisk(risk) {
		return ""
	}
	t, err := time.Parse(time.RFC3339, at)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// normalizeRiskKeptCopy reduces the copy a repair kept (T-884) to the content
// floor: a valid file label on an act label, "" on a standing label or an
// invalid label, exactly where normalizeRiskAt blanks the act time.
func normalizeRiskKeptCopy(risk, keptCopy string) string {
	keptCopy = strings.TrimSpace(keptCopy)
	if keptCopy == "" || isStandingCaptureRisk(risk) || !ValidRiskFileLabel(keptCopy) {
		return ""
	}
	return keptCopy
}

// priorReportIndex is the prior stored report, indexed the way
// DeriveCaptureRiskChanges asks: by label, by located Key, by OccurrenceKey,
// and the Keys of items stored without an act time.
type priorReportIndex struct {
	labels      map[string]bool
	keys        map[string]bool
	occurrences map[string]bool
	undated     map[string]bool
	byKey       bool
}

func indexPriorReport(prior ManagedIntegrityDetail) priorReportIndex {
	idx := priorReportIndex{
		labels: map[string]bool{}, keys: map[string]bool{},
		occurrences: map[string]bool{}, undated: map[string]bool{},
		byKey: len(prior.CaptureRiskItems) > 0,
	}
	for _, l := range prior.CaptureRisks {
		idx.labels[l] = true
	}
	for _, it := range prior.CaptureRiskItems {
		idx.keys[it.Key()] = true
		idx.occurrences[it.OccurrenceKey()] = true
		if it.At == "" {
			idx.undated[it.Key()] = true
		}
	}
	return idx
}

// itemIsNew reports whether a located item was not in the prior report: by
// label when the prior report carried no located items, else by Key, and for
// a dated act by OccurrenceKey, where a prior item without a time matches
// any time (T-886).
func (p priorReportIndex) itemIsNew(it CaptureRiskItem) bool {
	if !p.byKey {
		return !p.labels[it.Risk]
	}
	if !p.keys[it.Key()] {
		return true
	}
	if it.OccurrenceKey() == it.Key() {
		return false
	}
	return !p.occurrences[it.OccurrenceKey()] && !p.undated[it.Key()]
}

// supersedesChange reports whether next is a later occurrence of the act a
// stored change records: a dated act whose time differs from the change's.
func supersedesChange(next CaptureRiskItem, prior CaptureRiskChange) bool {
	return next.OccurrenceKey() != next.Key() && next.OccurrenceKey() != prior.OccurrenceKey()
}

// knownRiskIndex is the in-window part of a KnownRisks memory, indexed the
// way DeriveCaptureRiskChanges asks: by located Key, by label of a
// label-only entry, and by any label.
type knownRiskIndex struct {
	keys      map[string]bool
	labelOnly map[string]bool
	labels    map[string]bool
}

func indexKnownRisks(known []KnownCaptureRisk, now time.Time) knownRiskIndex {
	idx := knownRiskIndex{keys: map[string]bool{}, labelOnly: map[string]bool{}, labels: map[string]bool{}}
	for _, k := range known {
		if !knownInWindow(k, now) {
			continue
		}
		idx.keys[k.Key()] = true
		idx.labels[k.Risk] = true
		if k.Tool == "" && k.File == "" {
			idx.labelOnly[k.Risk] = true
		}
	}
	return idx
}

// knownInWindow reports whether a memory entry was last seen within
// ManagedIntegrityKnownWindow of now. An unparsable stamp is out of the
// window: forgetting only risks a duplicate event, never a missed one.
func knownInWindow(k KnownCaptureRisk, now time.Time) bool {
	last, err := time.Parse(time.RFC3339, k.LastSeen)
	return err == nil && now.Sub(last) <= ManagedIntegrityKnownWindow
}

// MergeKnownCaptureRisks returns the KnownRisks memory to store with a new
// report: the prior memory still inside ManagedIntegrityKnownWindow, plus
// every risk in this report (each located item, and each bare label as a
// label-only item) stamped now. Event names are not kept (the memory is an
// identity, not a description). Newest LastSeen first, bounded.
func MergeKnownCaptureRisks(prior []KnownCaptureRisk, labels []string, items []CaptureRiskItem, now time.Time) []KnownCaptureRisk {
	stamp := now.UTC().Format(time.RFC3339)
	byKey := map[string]KnownCaptureRisk{}
	for _, k := range prior {
		if !knownInWindow(k, now) {
			continue
		}
		k.Events = nil
		k.At = ""
		k.KeptCopy = ""
		if cur, ok := byKey[k.Key()]; ok && cur.LastSeen >= k.LastSeen {
			continue
		}
		byKey[k.Key()] = k
	}
	located := map[string]bool{}
	for _, it := range items {
		located[it.Risk] = true
		it.Events = nil
		it.At = ""
		it.KeptCopy = ""
		byKey[it.Key()] = KnownCaptureRisk{CaptureRiskItem: it, LastSeen: stamp}
	}
	for _, l := range labels {
		if located[l] {
			continue
		}
		it := CaptureRiskItem{Risk: l}
		byKey[it.Key()] = KnownCaptureRisk{CaptureRiskItem: it, LastSeen: stamp}
	}
	out := make([]KnownCaptureRisk, 0, len(byKey))
	for _, k := range byKey {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen != out[j].LastSeen {
			return out[i].LastSeen > out[j].LastSeen
		}
		return out[i].Key() < out[j].Key()
	})
	if len(out) > maxKnownCaptureRisks {
		out = out[:maxKnownCaptureRisks]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// DeriveCaptureRiskChanges returns the RecentChanges to store with a new
// report: every located risk in next that the prior stored detail did not
// carry, stamped now, plus the prior changes still inside
// ManagedIntegrityChangeWindow.
//
// A risk is "new" by its Key when the prior detail carried located items. A
// prior detail without any (written by an older node or server) is compared
// by risk LABEL only, so the first report after an upgrade does not turn every
// long-standing risk into a fresh event. A new risk label carried without any
// located item (an older node) becomes an item with only its label. hadPrior
// false (the node's first report) yields no change: the ordinary integrity
// finding opens for those.
//
// A STANDING label (captureRiskClasses) must ALSO be absent from the prior
// detail's KnownRisks memory within ManagedIntegrityKnownWindow to be new,
// matched by Key against a located memory entry and by label against a
// label-only one. An ACT label is judged against the prior report only.
//
// An act item that carries its act time (At, T-886) is judged by
// OccurrenceKey: the same artifact reported with a NEWER act time is a new
// event even though the prior report carried the item (a node reports a
// repair for 24 hours, so a second repair inside that day used to hide inside
// the first). The new change replaces the stored change for the same Key, so
// the reason names the artifact once, with the newer first_seen. A prior item
// with no act time (written by an older node or server) matches any time, so
// an upgrade does not turn a standing report into a fresh event.
func DeriveCaptureRiskChanges(prior ManagedIntegrityDetail, hadPrior bool, nextLabels []string, nextItems []CaptureRiskItem, now time.Time) []CaptureRiskChange {
	stamp := now.UTC().Format(time.RFC3339)
	var kept []CaptureRiskChange
	keptByKey := map[string]CaptureRiskChange{}
	for _, c := range prior.RecentChanges {
		first, err := time.Parse(time.RFC3339, c.FirstSeen)
		if err != nil || now.Sub(first) > ManagedIntegrityChangeWindow {
			continue
		}
		if _, dup := keptByKey[c.Key()]; dup {
			continue
		}
		keptByKey[c.Key()] = c
		kept = append(kept, c)
	}
	out := []CaptureRiskChange{}
	fresh := map[string]bool{}
	// add records a new change unless the window already holds one for the
	// same Key that this occurrence does not supersede.
	add := func(it CaptureRiskItem) {
		if fresh[it.Key()] {
			return
		}
		if c, ok := keptByKey[it.Key()]; ok && !supersedesChange(it, c) {
			return
		}
		fresh[it.Key()] = true
		out = append(out, CaptureRiskChange{CaptureRiskItem: it, FirstSeen: stamp})
	}
	if hadPrior {
		pr := indexPriorReport(prior)
		known := indexKnownRisks(prior.KnownRisks, now)
		located := map[string]bool{}
		for _, it := range nextItems {
			located[it.Risk] = true
			isNew := pr.itemIsNew(it)
			if isNew && isStandingCaptureRisk(it.Risk) && (known.keys[it.Key()] || known.labelOnly[it.Risk]) {
				isNew = false
			}
			if isNew {
				add(it)
			}
		}
		for _, l := range nextLabels {
			if located[l] || pr.labels[l] || (isStandingCaptureRisk(l) && known.labels[l]) {
				continue
			}
			add(CaptureRiskItem{Risk: l})
		}
	}
	for _, c := range kept {
		if !fresh[c.Key()] {
			out = append(out, c)
		}
	}
	// Newest first, so a bound drops the oldest event; within one report the
	// most actionable first (captureRiskPriority, T-873).
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].FirstSeen != out[j].FirstSeen {
			return out[i].FirstSeen > out[j].FirstSeen
		}
		return CaptureRiskItemLess(out[i].CaptureRiskItem, out[j].CaptureRiskItem)
	})
	if len(out) > maxCaptureRiskChanges {
		out = out[:maxCaptureRiskChanges]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// maxCaptureRiskItems bounds the located risks a report carries and the
// server stores.
const maxCaptureRiskItems = 32

// maxCaptureRiskEvents bounds the event names one located risk carries.
const maxCaptureRiskEvents = 8

// NormalizeCaptureRiskItems reduces located risks to the content floor
// CaptureRiskItem documents: a closed risk label, a target-shaped tool token,
// a home-relative file label, event-name tokens and, on an act label, an
// RFC3339 act time. An item whose risk label
// is unknown is dropped; an invalid tool, file or event is blanked rather than
// passed through. The result is de-duplicated, ordered by
// CaptureRiskItemLess and bounded to the first maxCaptureRiskItems in that
// order.
func NormalizeCaptureRiskItems(items []CaptureRiskItem) []CaptureRiskItem {
	out, _ := NormalizeCaptureRiskItemsCounted(items)
	return out
}

// NormalizeCaptureRiskItemsCounted is NormalizeCaptureRiskItems that also
// returns how many valid, distinct items the bound left out (T-873), so a
// report can say its list is partial.
func NormalizeCaptureRiskItemsCounted(items []CaptureRiskItem) ([]CaptureRiskItem, int) {
	if len(items) == 0 {
		return nil, 0
	}
	seen := map[string]bool{}
	out := make([]CaptureRiskItem, 0, len(items))
	for _, it := range items {
		it.Risk = strings.TrimSpace(it.Risk)
		if !validCaptureRisk(it.Risk) {
			continue
		}
		it.Tool = strings.TrimSpace(it.Tool)
		if !validRiskToolToken(it.Tool) {
			it.Tool = ""
		}
		it.File = strings.TrimSpace(it.File)
		if !ValidRiskFileLabel(it.File) {
			it.File = ""
		}
		it.KeptCopy = normalizeRiskKeptCopy(it.Risk, it.KeptCopy)
		it.Events = normalizeManagedLabels(it.Events, validRiskEventToken)
		if len(it.Events) > maxCaptureRiskEvents {
			it.Events = it.Events[:maxCaptureRiskEvents]
		}
		if len(it.Events) == 0 {
			it.Events = nil
		}
		it.At = normalizeRiskAt(it.Risk, it.At)
		key := it.Key()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return CaptureRiskItemLess(out[i], out[j]) })
	omitted := 0
	if len(out) > maxCaptureRiskItems {
		omitted = len(out) - maxCaptureRiskItems
		out = out[:maxCaptureRiskItems]
	}
	if len(out) == 0 {
		return nil, 0
	}
	return out, omitted
}

// Key is the identity of a located risk: risk, tool and file. Two reports
// carrying the same key describe the same observation.
func (it CaptureRiskItem) Key() string {
	return it.Risk + "|" + it.Tool + "|" + it.File
}

// String renders the item for a finding reason: "risk (tool file: events)",
// plus "; previous bytes kept at COPY" inside the parentheses when a repair
// kept a copy (T-884).
func (it CaptureRiskItem) String() string {
	var where []string
	if it.Tool != "" {
		where = append(where, it.Tool)
	}
	if it.File != "" {
		where = append(where, it.File)
	}
	s := it.Risk
	if len(where) > 0 {
		s += " (" + strings.Join(where, " ")
		if len(it.Events) > 0 {
			s += ": " + strings.Join(it.Events, ",")
		}
		if it.KeptCopy != "" {
			s += "; previous bytes kept at " + it.KeptCopy
		}
		s += ")"
	}
	return s
}

// validRiskToolToken accepts a registration target id: lower-case letters,
// digits and hyphens, starting with a letter or digit.
func validRiskToolToken(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && i > 0:
		default:
			return false
		}
	}
	return true
}

// validRiskEventToken accepts a native hook event name (PreToolUse,
// beforeShellExecution, pre_run_command, ...).
func validRiskEventToken(s string) bool {
	if s == "" || len(s) > 48 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '_' || c == '-' || c == '.') && i > 0:
		default:
			return false
		}
	}
	return true
}

// riskFileRoots are the closed prefixes of a CaptureRiskItem.File label.
var riskFileRoots = []string{"~/", "~win/", "?/"}

// ValidRiskFileLabel reports whether label is a home-relative file label in
// the CaptureRiskItem content floor: one of the closed roots, then one or more
// path elements of a conservative character set, no "." or ".." element, at
// most 160 bytes.
func ValidRiskFileLabel(label string) bool {
	if label == "" || len(label) > 160 {
		return false
	}
	rest := ""
	for _, root := range riskFileRoots {
		if strings.HasPrefix(label, root) {
			rest = label[len(root):]
			break
		}
	}
	if rest == "" {
		return false
	}
	for _, elem := range strings.Split(rest, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
		for i := 0; i < len(elem); i++ {
			c := elem[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '.' || c == '_' || c == '-' || c == '+' || c == '@' || c == ' ':
			default:
				return false
			}
		}
	}
	return true
}

func normalizeManagedLabels(labels []string, allowed func(string) bool) []string {
	seen := map[string]bool{}
	for _, raw := range labels {
		label := strings.TrimSpace(raw)
		if label != "" && allowed(label) {
			seen[label] = true
		}
	}
	out := make([]string, 0, len(seen))
	for label := range seen {
		out = append(out, label)
	}
	sort.Strings(out)
	if len(out) > maxManagedIntegrityLabels {
		out = out[:maxManagedIntegrityLabels]
	}
	return out
}

// driftedToolLabels is the CLOSED `drifted_tools` vocabulary: the adapter
// ids a node can report a proxy-route drift for.
//
// WIDENED ADDITIVELY by Track C item 2
// (docs/plans/org-guardrail-control-wave-2026-09-21.md) from the original
// claude-code/codex pair to every adapter whose PERSISTED proxy route
// internal/proxyroute owns a guarded writer for, because the route inspector
// now dispatches on the integration registry's RouteKind rather than on two
// hand-listed tools.
//
// ONE OWNER, two halves, held together by a test:
// proxyroute.InspectedTools() decides what a node CAN report, this table
// decides what the wire ACCEPTS, and
// proxyroute.TestInspectedToolsAreValidWireLabels fails if they diverge. The
// table lives here rather than being imported from proxyroute because
// orgcontract is the wire vocabulary and the org SERVER validates against it
// — the server must not have to link the node's config writers.
//
// Adding a row is safe in both directions: an older server drops a label it
// does not know (NormalizeLabels is applied on BOTH sides), and an older node
// simply never sends one.
var driftedToolLabels = map[string]bool{
	"claude-code": true,
	"codex":       true,
	"crush":       true,
	"kimi-code":   true,
	"qwen-code":   true,
}

// validDriftedToolLabel reports whether label is in the closed
// `drifted_tools` vocabulary.
func validDriftedToolLabel(label string) bool { return driftedToolLabels[label] }

// DriftedToolLabels returns the closed `drifted_tools` vocabulary, sorted —
// for surfaces (and tests) that need to enumerate it.
func DriftedToolLabels() []string {
	out := make([]string, 0, len(driftedToolLabels))
	for label := range driftedToolLabels {
		out = append(out, label)
	}
	sort.Strings(out)
	return out
}

func validManagedSiblingLabel(label string) bool {
	parts := strings.Split(label, "/")
	if len(parts) != 2 {
		return false
	}
	originOK := parts[0] == "native-alt" || parts[0] == "wsl-mnt" || parts[0] == "wslhost" || parts[0] == "other"
	osOK := parts[1] == "windows" || parts[1] == "linux" || parts[1] == "darwin" || parts[1] == "other"
	return originOK && osOK
}

func validCaptureRisk(label string) bool {
	switch label {
	case CaptureRiskHookRegistrationError,
		CaptureRiskHookBinaryMismatch,
		CaptureRiskHookConfigMissing,
		CaptureRiskCodexHookUntrusted,
		CaptureRiskHookConfigChanged,
		CaptureRiskAgentConfigDrift,
		CaptureRiskHookRegistrationDrift,
		CaptureRiskHookRegistryMissing,
		CaptureRiskHookRegistryEntryMissing,
		CaptureRiskHookRepaired,
		CaptureRiskHookRegistrationFailed,
		CaptureRiskRouteRepaired,
		CaptureRiskRouteBypassObserved,
		CaptureRiskHookSilentSurface,
		CaptureRiskHookSwitchedOff,
		CaptureRiskConfigLayerOverride,
		CaptureRiskRouteInactiveProvider,
		CaptureRiskShellWrapMissing,
		CaptureRiskVendorPolicyBlocksMCP,
		CaptureRiskVendorPolicyPinsRoute,
		CaptureRiskSandboxGatewayConfigDrift:
		return true
	default:
		return false
	}
}

func validUnknownCheck(label string) bool {
	switch label {
	case CaptureUnknownRegistryMissing,
		CaptureUnknownRegistryUnreadable,
		CaptureUnknownRegistryInvalid,
		CaptureUnknownRegistryEmpty,
		CaptureUnknownConfigUnreadable,
		CaptureUnknownChecksumMissing,
		CaptureUnknownBinaryPath,
		CaptureUnknownRecordedBinary,
		CaptureUnknownCodexTrust,
		CaptureUnknownSandboxGatewayConfig:
		return true
	default:
		return false
	}
}
