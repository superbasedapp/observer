package secassess

import "strings"

// The system half of a threat model in the Markdown export: the index that
// gives ids their names, and one table per collection of the system.

// mdNames resolves the ids of a model to the names it gives them. The names
// are raw (the agent's); a caller escapes them with mdLabel. The first row of
// a repeated id wins.
type mdNames struct {
	zone   map[string]string
	byKind map[string]map[string]string
}

// element kinds as the model writes them (EnumElementKind).
const (
	mdKindComponent  = "component"
	mdKindActor      = "actor"
	mdKindFlow       = "flow"
	mdKindEntryPoint = "entry_point"
	mdKindAsset      = "asset"
)

// newMDNames indexes a system. A flow has no name of its own and reads as its
// two ends; an entry point reads as its kind on its component.
func newMDNames(s System) *mdNames {
	n := &mdNames{zone: map[string]string{}, byKind: map[string]map[string]string{}}
	for _, k := range []string{mdKindComponent, mdKindActor, mdKindFlow, mdKindEntryPoint, mdKindAsset} {
		n.byKind[k] = map[string]string{}
	}
	for _, z := range s.Zones {
		mdSetFirst(n.zone, z.ID, z.Name)
	}
	for _, c := range s.Components {
		mdSetFirst(n.byKind[mdKindComponent], c.ID, c.Name)
	}
	for _, a := range s.Actors {
		mdSetFirst(n.byKind[mdKindActor], a.ID, a.Name)
	}
	for _, a := range s.Assets {
		mdSetFirst(n.byKind[mdKindAsset], a.ID, a.Name)
	}
	for _, f := range s.Flows {
		mdSetFirst(n.byKind[mdKindFlow], f.ID, n.endpoint(f.From)+" to "+n.endpoint(f.To))
	}
	for _, e := range s.EntryPoints {
		mdSetFirst(n.byKind[mdKindEntryPoint], e.ID, strings.ReplaceAll(e.Kind, "_", " ")+" on "+n.componentName(e.Component))
	}
	return n
}

// mdSetFirst stores v under k unless k is already there.
func mdSetFirst(m map[string]string, k, v string) {
	if _, ok := m[k]; !ok {
		m[k] = v
	}
}

// componentName is the raw name of a component, or its id when it has none.
func (n *mdNames) componentName(id string) string {
	if name := n.byKind[mdKindComponent][id]; name != "" {
		return name
	}
	return id
}

// endpoint is the raw name of a flow's end: a component, else an actor, else
// the id as written.
func (n *mdNames) endpoint(id string) string {
	if name := n.byKind[mdKindComponent][id]; name != "" {
		return name
	}
	if name := n.byKind[mdKindActor][id]; name != "" {
		return name
	}
	return id
}

// label writes a name with its id for an element kind ("" kind looks in the
// components, then the actors), escaped.
func (n *mdNames) label(kind, id string) string {
	if kind == "" {
		return mdLabel(id, n.endpoint(id))
	}
	return mdLabel(id, n.byKind[kind][id])
}

// elementMD says what a threat or a waived pair is about: the kind in words
// and the element's name with its id.
func (n *mdNames) elementMD(e Element) string {
	return mdWords(e.Kind) + " " + n.label(e.Kind, e.ID)
}

// zoneMD writes a zone by its name and id.
func (n *mdNames) zoneMD(id string) string { return mdLabel(id, n.zone[id]) }

// listMD writes ids as labels, joined by commas.
func (n *mdNames) listMD(kind string, ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if s := n.label(kind, id); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ", ")
}

// mdTMSystem writes the system as tables, one per collection that has rows.
func mdTMSystem(w *mdWriter, s System, n *mdNames) {
	w.heading(2, "System")
	w.para("The system as the agent describes it. Types are named by Observer's table where it has the word; everything else is the agent's.")
	mdTMComponents(w, s.Components, n)
	mdTMZones(w, s.Zones)
	mdTMActors(w, s.Actors)
	mdTMAssets(w, s.Assets, n)
	mdTMEntryPoints(w, s.EntryPoints, n)
	mdTMFlows(w, s.Flows, n)
}

// mdComponentType is a component's type by the type table's name, else as
// written.
func mdComponentType(id string) string {
	if t, ok := ComponentTypeByID(id); ok {
		return t.Name
	}
	return mdWords(id)
}

// mdTMComponents writes the components table.
func mdTMComponents(w *mdWriter, cs []Component, n *mdNames) {
	if len(cs) == 0 {
		return
	}
	rows := make([][]string, 0, len(cs))
	for _, c := range cs {
		var refs []string
		for _, r := range c.Paths {
			refs = append(refs, mdRef(r))
		}
		rows = append(rows, []string{
			mdText(c.ID), mdText(c.Name), mdComponentType(c.Type), n.zoneMD(c.Zone),
			mdText(strings.Join(c.Tech, ", ")), strings.Join(refs, "; "), mdText(c.Description),
		})
	}
	w.heading(3, "Components")
	w.table([]string{"Id", "Name", "Type", "Zone", "Technology", "Cited places", "Description"}, rows)
}

// mdTMZones writes the trust zones table.
func mdTMZones(w *mdWriter, zs []Zone) {
	if len(zs) == 0 {
		return
	}
	rows := make([][]string, 0, len(zs))
	for _, z := range zs {
		rows = append(rows, []string{mdText(z.ID), mdText(z.Name), mdText(z.Description)})
	}
	w.heading(3, "Trust zones")
	w.table([]string{"Id", "Name", "Description"}, rows)
}

// mdTMActors writes the actors table.
func mdTMActors(w *mdWriter, as []Actor) {
	if len(as) == 0 {
		return
	}
	rows := make([][]string, 0, len(as))
	for _, a := range as {
		rows = append(rows, []string{mdText(a.ID), mdText(a.Name), mdWords(a.Kind)})
	}
	w.heading(3, "Actors")
	w.table([]string{"Id", "Name", "Kind"}, rows)
}

// mdTMAssets writes the assets table.
func mdTMAssets(w *mdWriter, as []Asset, n *mdNames) {
	if len(as) == 0 {
		return
	}
	rows := make([][]string, 0, len(as))
	for _, a := range as {
		rows = append(rows, []string{
			mdText(a.ID), mdText(a.Name), mdWords(a.Sensitivity),
			mdText(strings.Join(a.DataClasses, ", ")), n.listMD(mdKindComponent, a.StoredIn),
		})
	}
	w.heading(3, "Assets")
	w.table([]string{"Id", "Name", "Sensitivity", "Data classes", "Stored in"}, rows)
}

// mdTMEntryPoints writes the entry points table.
func mdTMEntryPoints(w *mdWriter, es []EntryPoint, n *mdNames) {
	if len(es) == 0 {
		return
	}
	rows := make([][]string, 0, len(es))
	for _, e := range es {
		ref := ""
		if e.Ref != nil {
			ref = mdRef(*e.Ref)
		}
		rows = append(rows, []string{mdText(e.ID), n.label(mdKindComponent, e.Component), mdWords(e.Kind), ref, mdWords(e.Authn), mdWords(e.Exposure)})
	}
	w.heading(3, "Entry points")
	w.table([]string{"Id", "Component", "Kind", "Cited place", "Authentication", "Exposure"}, rows)
}

// mdYesNo writes a bool as a word.
func mdYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// mdTMFlows writes the flows table.
func mdTMFlows(w *mdWriter, fs []Flow, n *mdNames) {
	if len(fs) == 0 {
		return
	}
	rows := make([][]string, 0, len(fs))
	for _, f := range fs {
		rows = append(rows, []string{
			mdText(f.ID), n.label("", f.From), n.label("", f.To), n.listMD(mdKindAsset, f.Data),
			mdText(f.Protocol), mdText(strings.Join(f.Crosses, ", ")), mdWords(f.Authn), mdWords(f.Encrypted), mdYesNo(f.PersonalData),
		})
	}
	w.heading(3, "Flows")
	w.table([]string{"Id", "From", "To", "Data", "Protocol", "Crosses", "Authentication", "Encrypted", "Personal data"}, rows)
}
