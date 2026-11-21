package secassess

import (
	"fmt"
	"sort"
	"strings"
)

// Rows V3 to V7 of the rule table: collection caps, ids, closed enums, text
// cleaning and references between items. Items are marked dead in place so
// the file positions in issue paths stay true; the compaction step after V7
// removes them.

// deadSet returns the dead flags of a collection, created on first use.
func (v *validator) deadSet(coll string, n int) []bool {
	d := v.dead[coll]
	if len(d) != n {
		d = make([]bool, n)
		v.dead[coll] = d
	}
	return d
}

func (v *validator) isDead(coll string, i int) bool {
	d := v.dead[coll]
	return i < len(d) && d[i]
}

// scan runs check on every live item of a collection; an item check rejects
// is marked dead and counted as refused.
func scan[T any](v *validator, row, coll string, items []T, check func(i int, t *T) (code, msg string)) {
	dead := v.deadSet(coll, len(items))
	for i := range items {
		if dead[i] {
			continue
		}
		if code, msg := check(i, &items[i]); code != "" {
			dead[i] = true
			v.refuseItem(row, coll, i, code, msg)
		}
	}
}

// liveIDs returns the ids of the live items of a collection.
func liveIDs[T any](v *validator, coll string, items []T, id func(*T) string) map[string]bool {
	out := map[string]bool{}
	for i := range items {
		if !v.isDead(coll, i) {
			out[id(&items[i])] = true
		}
	}
	return out
}

// compact returns the live items of a collection.
func compact[T any](v *validator, coll string, items []T) []T {
	d := v.dead[coll]
	if len(d) != len(items) {
		return items
	}
	out := make([]T, 0, len(items))
	for i := range items {
		if !d[i] {
			out = append(out, items[i])
		}
	}
	return out
}

// readAll counts a collection that is bounded only by the file's size cap.
func readAll[T any](v *validator, coll string, s []T) []T {
	v.read(coll, len(s))
	return s
}

// capSlice truncates a top-level collection to its cap, counting what it
// leaves out.
func capSlice[T any](v *validator, coll string, s []T, limit int) []T {
	v.read(coll, len(s))
	if len(s) > limit {
		v.leftOut(coll, len(s)-limit)
		v.issue("V3", "cap_exceeded", SevRefused, coll,
			fmt.Sprintf("%s: %d items past the cap of %d were left out.", coll, len(s)-limit, limit))
		return s[:limit]
	}
	return s
}

// trimNested truncates a per-item list, tallying what it leaves out under
// path.
func trimNested[T any](v *validator, path string, s []T, limit int) []T {
	if len(s) > limit {
		v.trims[path] += len(s) - limit
		return s[:limit]
	}
	return s
}

// ---- V3: collection caps ----

func ruleV3(v *validator) {
	switch {
	case v.tm != nil:
		v3TM(v, v.tm)
	case v.pt != nil:
		v3PT(v, v.pt)
	}
	v.flushTrims("V3")
}

func v3TM(v *validator, m *ThreatModelDoc) {
	s := &m.System
	s.Components = capSlice(v, "components", s.Components, maxComponents)
	s.Zones = capSlice(v, "zones", s.Zones, maxZones)
	s.Actors = capSlice(v, "actors", s.Actors, maxActors)
	s.Assets = capSlice(v, "assets", s.Assets, maxAssets)
	s.EntryPoints = capSlice(v, "entry_points", s.EntryPoints, maxEntryPoints)
	s.Flows = capSlice(v, "flows", s.Flows, maxFlows)
	m.Threats = readAll(v, "threats", m.Threats)
	m.NoThreat = readAll(v, "no_threat", m.NoThreat)
	m.AttackTrees = capSlice(v, "attack_trees", m.AttackTrees, maxAttackTrees)
	m.Scope.InScope = trimNested(v, "scope.in_scope", m.Scope.InScope, maxScopePaths)
	m.Scope.OutOfScope = trimNested(v, "scope.out_of_scope", m.Scope.OutOfScope, maxScopePaths)
	m.Scope.Assumptions = trimNested(v, "scope.assumptions", m.Scope.Assumptions, maxAssumptions)
	m.OpenQuestions = trimNested(v, "open_questions", m.OpenQuestions, maxOpenQuestions)
	m.Limits = trimNested(v, "limits", m.Limits, maxLimits)
	for i := range s.Components {
		c := &s.Components[i]
		c.Paths = trimNested(v, "components.paths", c.Paths, maxPerItemList)
		c.Tech = trimNested(v, "components.tech", c.Tech, maxTechList)
	}
	for i := range s.Assets {
		a := &s.Assets[i]
		a.DataClasses = trimNested(v, "assets.data_classes", a.DataClasses, maxTechList)
		a.StoredIn = trimNested(v, "assets.stored_in", a.StoredIn, maxTechList)
	}
	for i := range s.Flows {
		f := &s.Flows[i]
		f.Data = trimNested(v, "flows.data", f.Data, maxTechList)
		f.Crosses = trimNested(v, "flows.crosses", f.Crosses, maxTechList)
	}
	for i := range m.Threats {
		t := &m.Threats[i]
		for j := range t.Existing {
			t.Existing[j].Refs = trimNested(v, "threats.existing.refs", t.Existing[j].Refs, maxPerItemList)
		}
		for j := range t.Missing {
			t.Missing[j].Refs = trimNested(v, "threats.missing.refs", t.Missing[j].Refs, maxPerItemList)
		}
		t.CWE = trimNested(v, "threats.cwe", t.CWE, maxSmallList)
		t.CAPEC = trimNested(v, "threats.capec", t.CAPEC, maxSmallList)
		t.ASVS = trimNested(v, "threats.asvs", t.ASVS, maxSmallList)
		if t.AbuseCase != nil {
			t.AbuseCase.Steps = trimNested(v, "threats.abuse_case.steps", t.AbuseCase.Steps, maxPerItemList)
		}
	}
	for i := range m.AttackTrees {
		tr := &m.AttackTrees[i]
		v.read("tree_nodes", len(tr.Nodes))
		if len(tr.Nodes) > maxTreeNodes {
			v.leftOut("tree_nodes", len(tr.Nodes)-maxTreeNodes)
			v.issue("V3", "cap_exceeded", SevRefused, fmt.Sprintf("attack_trees[%d]", i),
				fmt.Sprintf("attack_trees[%d]: %d nodes past the cap of %d were left out.", i, len(tr.Nodes)-maxTreeNodes, maxTreeNodes))
			tr.Nodes = tr.Nodes[:maxTreeNodes]
		}
	}
}

func v3PT(v *validator, p *PentestDoc) {
	p.Coverage = capSlice(v, "coverage", p.Coverage, maxCoverageRows)
	p.Findings = readAll(v, "findings", p.Findings)
	p.Limits = trimNested(v, "limits", p.Limits, maxLimits)
	p.Target.Start.Argv = trimNested(v, "target.start.argv", p.Target.Start.Argv, maxArgv)
	p.Target.Accounts = trimNested(v, "target.accounts", p.Target.Accounts, maxAccounts)
	for i := range p.Coverage {
		p.Coverage[i].Probes = trimNested(v, "coverage.probes", p.Coverage[i].Probes, maxSmallList)
	}
	for i := range p.Findings {
		f := &p.Findings[i]
		f.CWE = trimNested(v, "findings.cwe", f.CWE, maxSmallList)
		f.Where.Refs = trimNested(v, "findings.where.refs", f.Where.Refs, maxPerItemList)
		f.Evidence = trimNested(v, "findings.evidence", f.Evidence, maxPerItemList)
		f.Reproduction = trimNested(v, "findings.reproduction", f.Reproduction, maxPerItemList)
		v3Evidence(v, f)
	}
}

// ---- V4: ids ----

func idScan[T any](v *validator, coll string, items []T, id func(*T) string) {
	seen := map[string]bool{}
	scan(v, "V4", coll, items, func(_ int, t *T) (string, string) {
		k := id(t)
		switch {
		case !ValidItemID(k):
			return "bad_id", "The id is empty, too long, or uses characters outside letters, digits, dot, underscore and hyphen."
		case seen[k]:
			return "duplicate_id", "Another item in this list already has the id " + clip(k, 48) + "."
		}
		seen[k] = true
		return "", ""
	})
}

func ruleV4(v *validator) {
	if m := v.tm; m != nil {
		s := &m.System
		idScan(v, "components", s.Components, func(x *Component) string { return x.ID })
		idScan(v, "zones", s.Zones, func(x *Zone) string { return x.ID })
		idScan(v, "actors", s.Actors, func(x *Actor) string { return x.ID })
		idScan(v, "assets", s.Assets, func(x *Asset) string { return x.ID })
		idScan(v, "entry_points", s.EntryPoints, func(x *EntryPoint) string { return x.ID })
		idScan(v, "flows", s.Flows, func(x *Flow) string { return x.ID })
		idScan(v, "threats", m.Threats, func(x *Threat) string { return x.ID })
		for i := range m.AttackTrees {
			tr := &m.AttackTrees[i]
			idScan(v, fmt.Sprintf("tree_nodes#%d", i), tr.Nodes, func(x *TreeNode) string { return x.ID })
		}
	}
	if p := v.pt; p != nil {
		seen := map[string]bool{}
		scan(v, "V4", "coverage", p.Coverage, func(_ int, c *PTCoverageClaim) (string, string) {
			if seen[c.Category] {
				return "duplicate_category", "Another coverage row already covers the category " + clip(c.Category, 12) + "."
			}
			seen[c.Category] = true
			return "", ""
		})
		idScan(v, "findings", p.Findings, func(x *PTFinding) string { return x.ID })
	}
}

// ---- V5: closed enums ----

// optEnum clears an optional enum field whose value is not in the list.
func (v *validator) optEnum(path, field string, val *string, e Enum) {
	if *val == "" || e.Has(*val) {
		return
	}
	v.issue("V5", "bad_enum_dropped", SevDropped, path,
		fmt.Sprintf("The value %q of %s is not one of the accepted words, so it was left out.", clip(*val, 40), field))
	*val = ""
}

// shapeList keeps the entries of a list that pass ok and warns about the rest.
func (v *validator) shapeList(path, field string, in []string, ok func(string) bool) []string {
	var out []string
	for _, s := range in {
		if ok(s) {
			out = append(out, s)
			continue
		}
		v.issue("V5", "bad_standard_id", SevDropped, path,
			fmt.Sprintf("The entry %q of %s is not a well-formed id, so it was left out.", clip(s, 30), field))
	}
	return out
}

var frameworkEnum = Enum{FrameworkSTRIDE, FrameworkLINDDUN, FrameworkOWASPLLM, FrameworkOWASPAgentic}

// categoryOK reports whether cat is a valid category of the framework.
func categoryOK(framework, cat string) bool {
	switch framework {
	case FrameworkSTRIDE:
		_, ok := StrideCategoryByID(cat)
		return ok
	case FrameworkLINDDUN:
		_, ok := LinddunCategoryByID(cat)
		return ok
	}
	return ValidAICategory(framework, cat)
}

// frameworkOfCategory returns the framework a category id belongs to. The ids
// of the four frameworks do not overlap.
func frameworkOfCategory(cat string) string {
	for _, fw := range frameworkEnum {
		if categoryOK(fw, cat) {
			return fw
		}
	}
	return ""
}

func ruleV5(v *validator) {
	if m := v.tm; m != nil {
		s := &m.System
		scan(v, "V5", "components", s.Components, func(_ int, c *Component) (string, string) {
			if _, ok := ComponentTypeByID(c.Type); !ok {
				return "bad_enum", "The component type " + clip(c.Type, 30) + " is not one of the accepted types."
			}
			return "", ""
		})
		scan(v, "V5", "actors", s.Actors, func(_ int, a *Actor) (string, string) {
			if !EnumActorKind.Has(a.Kind) {
				return "bad_enum", "The actor kind " + clip(a.Kind, 30) + " is not one of the accepted kinds."
			}
			return "", ""
		})
		scan(v, "V5", "assets", s.Assets, func(_ int, a *Asset) (string, string) {
			if !EnumSensitivity.Has(a.Sensitivity) {
				return "bad_enum", "The sensitivity " + clip(a.Sensitivity, 30) + " is not one of the accepted words."
			}
			return "", ""
		})
		scan(v, "V5", "entry_points", s.EntryPoints, func(i int, e *EntryPoint) (string, string) {
			if !EnumEntryKind.Has(e.Kind) {
				return "bad_enum", "The entry point kind " + clip(e.Kind, 30) + " is not one of the accepted kinds."
			}
			p := fmt.Sprintf("entry_points[%d]", i)
			v.optEnum(p, "authn", &e.Authn, EnumAuthn)
			v.optEnum(p, "exposure", &e.Exposure, EnumExposure)
			return "", ""
		})
		scan(v, "V5", "flows", s.Flows, func(i int, f *Flow) (string, string) {
			p := fmt.Sprintf("flows[%d]", i)
			v.optEnum(p, "authn", &f.Authn, EnumAuthn)
			v.optEnum(p, "encrypted", &f.Encrypted, EnumEncrypted)
			return "", ""
		})
		scan(v, "V5", "threats", m.Threats, func(i int, t *Threat) (string, string) {
			switch {
			case !frameworkEnum.Has(t.Framework):
				return "bad_enum", "The framework " + clip(t.Framework, 30) + " is not one of the accepted frameworks."
			case !categoryOK(t.Framework, t.Category):
				return "bad_category", "The category " + clip(t.Category, 40) + " does not belong to the framework " + t.Framework + "."
			case !EnumElementKind.Has(t.Element.Kind):
				return "bad_enum", "The element kind " + clip(t.Element.Kind, 30) + " is not one of the accepted kinds."
			case !ValidRating(t.Rating):
				return "bad_rating", "Likelihood and impact must each be a whole number from 1 to 5."
			}
			p := fmt.Sprintf("threats[%d]", i)
			v.optEnum(p, "status", &t.Status, EnumThreatState)
			for j := range t.Missing {
				v.optEnum(fmt.Sprintf("%s.missing[%d]", p, j), "effort", &t.Missing[j].Effort, EnumEffort)
			}
			t.CWE = v.shapeList(p, "cwe", t.CWE, ValidCWE)
			t.CAPEC = v.shapeList(p, "capec", t.CAPEC, ValidCAPEC)
			t.ASVS = v.shapeList(p, "asvs", t.ASVS, ValidASVS)
			return "", ""
		})
		scan(v, "V5", "no_threat", m.NoThreat, func(_ int, n *NoThreat) (string, string) {
			switch {
			case !EnumElementKind.Has(n.Element.Kind):
				return "bad_enum", "The element kind " + clip(n.Element.Kind, 30) + " is not one of the accepted kinds."
			case frameworkOfCategory(n.Category) == "":
				return "bad_category", "The category " + clip(n.Category, 40) + " is not a category of any accepted framework."
			}
			return "", ""
		})
		for i := range m.AttackTrees {
			tr := &m.AttackTrees[i]
			for j := range tr.Nodes {
				v.optEnum(fmt.Sprintf("attack_trees[%d].nodes[%d]", i, j), "op", &tr.Nodes[j].Op, EnumTreeOp)
			}
		}
	}
	if p := v.pt; p != nil {
		scan(v, "V5", "coverage", p.Coverage, func(_ int, c *PTCoverageClaim) (string, string) {
			switch {
			case !isWSTG(c.Category):
				return "bad_category", "The category " + clip(c.Category, 12) + " is not one of the twelve test categories."
			case !EnumCoverageStatus.Has(c.Status):
				return "bad_enum", "The coverage status " + clip(c.Status, 30) + " is not one of the accepted words."
			}
			return "", ""
		})
		scan(v, "V5", "findings", p.Findings, func(i int, f *PTFinding) (string, string) {
			switch {
			case !isWSTG(f.Category):
				return "bad_category", "The category " + clip(f.Category, 12) + " is not one of the twelve test categories."
			case !EnumBasis.Has(f.Basis):
				return "bad_enum", "The basis " + clip(f.Basis, 30) + " must be observed or inferred."
			case !ValidRating(f.Rating):
				return "bad_rating", "Likelihood and impact must each be a whole number from 1 to 5."
			}
			pth := fmt.Sprintf("findings[%d]", i)
			v.optEnum(pth, "status", &f.Status, EnumFindingState)
			f.CWE = v.shapeList(pth, "cwe", f.CWE, ValidCWE)
			v.cvssVector(pth, f)
			return "", ""
		})
	}
}

// ---- V6: text ----

// cleanList cleans and caps a list of texts and drops the ones left empty.
func (v *validator) cleanList(in []string, limit int, kind string) []string {
	var out []string
	for _, s := range in {
		if t := v.cleanText(s, limit, kind); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// cleanRef normalizes a reference's path and cleans its needle. A path that
// cannot be normalized is kept cleaned so V8 can say why it is invalid.
func (v *validator) cleanRef(r *Ref) {
	if p, why := relPath(strings.TrimSpace(r.Path)); why == "" {
		r.Path = p
	} else {
		r.Path = v.cleanText(r.Path, capPath, "path")
	}
	// The quoted text is searched for in the project's files, so a redactor that
	// rewrote it changes what is looked for. The reference is remembered by the
	// key the check memoises on (a model type carries no unexported field), so the
	// check can say how many references that touched.
	var changed bool
	r.Needle, changed = v.cleanTextChanged(r.Needle, capNeedle, "needle")
	if changed {
		v.hidden[refKey{r.Path, r.Needle, r.Line, r.EndLine}] = true
	}
}

func (v *validator) cleanRefs(refs []Ref) {
	for i := range refs {
		v.cleanRef(&refs[i])
	}
}

// needText cleans a required text; a text that is empty after cleaning
// refuses its item.
func (v *validator) needText(s *string, limit int, kind, what string) (code, msg string) {
	*s = v.cleanText(*s, limit, kind)
	if *s == "" {
		return "empty_text", "The " + what + " is empty."
	}
	return "", ""
}

func ruleV6(v *validator) {
	if m := v.tm; m != nil {
		v6TM(v, m)
	}
	if p := v.pt; p != nil {
		v6PT(v, p)
	}
	kinds := make([]string, 0, len(v.text))
	for k := range v.text {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		v.issue("V6", "text_truncated", SevDropped, k,
			fmt.Sprintf("%d %s texts were longer than their limit and were cut.", v.text[k], k))
	}
}

func v6TM(v *validator, m *ThreatModelDoc) {
	m.Summary = v.cleanText(m.Summary, capSummary, "summary")
	m.PromptVersion = v.cleanText(m.PromptVersion, 20, "prompt_version")
	m.Generator.Tool = v.cleanText(m.Generator.Tool, capName, "generator")
	m.Generator.Model = v.cleanText(m.Generator.Model, capName, "generator")
	m.Scope.Assumptions = v.cleanList(m.Scope.Assumptions, capShort, "assumption")
	m.Scope.InScope = v.scopePaths(m.Scope.InScope)
	m.Scope.OutOfScope = v.scopePaths(m.Scope.OutOfScope)
	m.OpenQuestions = v.cleanList(m.OpenQuestions, capShort, "open question")
	m.Limits = v.cleanList(m.Limits, capShort, "limit")
	s := &m.System
	scan(v, "V6", "components", s.Components, func(_ int, c *Component) (string, string) {
		c.Description = v.cleanText(c.Description, capDescription, "description")
		c.Tech = v.cleanList(c.Tech, 40, "tech")
		c.Zone = strings.TrimSpace(c.Zone)
		v.cleanRefs(c.Paths)
		return v.needText(&c.Name, capName, "name", "component name")
	})
	scan(v, "V6", "zones", s.Zones, func(_ int, z *Zone) (string, string) {
		z.Description = v.cleanText(z.Description, capDescription, "description")
		return v.needText(&z.Name, capName, "name", "zone name")
	})
	scan(v, "V6", "actors", s.Actors, func(_ int, a *Actor) (string, string) {
		return v.needText(&a.Name, capName, "name", "actor name")
	})
	scan(v, "V6", "assets", s.Assets, func(_ int, a *Asset) (string, string) {
		a.DataClasses = v.cleanList(a.DataClasses, 40, "data class")
		return v.needText(&a.Name, capName, "name", "asset name")
	})
	scan(v, "V6", "entry_points", s.EntryPoints, func(_ int, e *EntryPoint) (string, string) {
		if e.Ref != nil {
			v.cleanRef(e.Ref)
		}
		return "", ""
	})
	scan(v, "V6", "flows", s.Flows, func(_ int, f *Flow) (string, string) {
		f.Protocol = v.cleanText(f.Protocol, capProtocol, "protocol")
		return "", ""
	})
	scan(v, "V6", "threats", m.Threats, func(i int, t *Threat) (string, string) {
		t.Description = v.cleanText(t.Description, capDescription, "description")
		t.Actor = strings.TrimSpace(t.Actor)
		t.Existing = v.cleanExisting(fmt.Sprintf("threats[%d].existing", i), t.Existing)
		t.Missing = v.cleanMissing(fmt.Sprintf("threats[%d].missing", i), t.Missing)
		if t.AbuseCase != nil {
			t.AbuseCase.Actor = v.cleanText(t.AbuseCase.Actor, capName, "abuse case")
			t.AbuseCase.Goal = v.cleanText(t.AbuseCase.Goal, capShort, "abuse case")
			t.AbuseCase.Steps = v.cleanList(t.AbuseCase.Steps, capShort, "abuse case")
			if t.AbuseCase.Goal == "" {
				v.issue("V6", "abuse_case_dropped", SevDropped, fmt.Sprintf("threats[%d]", i), "The abuse case has no goal, so it was left out.")
				t.AbuseCase = nil
			}
		}
		return v.needText(&t.Title, capTitle, "title", "threat title")
	})
	scan(v, "V6", "no_threat", m.NoThreat, func(_ int, n *NoThreat) (string, string) {
		return v.needText(&n.Reason, capShort, "reason", "reason")
	})
	for i := range m.AttackTrees {
		tr := &m.AttackTrees[i]
		coll := fmt.Sprintf("tree_nodes#%d", i)
		scan(v, "V6", coll, tr.Nodes, func(_ int, n *TreeNode) (string, string) {
			n.Parent = strings.TrimSpace(n.Parent)
			return v.needText(&n.Label, capName*2, "label", "node label")
		})
		tr.Root = v.cleanText(tr.Root, capShort, "label")
	}
}

// scopePaths normalizes scope paths and drops the ones that are not
// project-relative.
func (v *validator) scopePaths(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, why := relPath(s); why == "" {
			out = append(out, p)
			continue
		}
		v.issue("V6", "scope_path_dropped", SevDropped, "scope", "The scope path "+clip(s, 40)+" is not a project-relative path, so it was left out.")
	}
	return out
}

func (v *validator) cleanExisting(path string, in []Mitigation) []Mitigation {
	var out []Mitigation
	for j := range in {
		m := in[j]
		if code, msg := v.needText(&m.Text, capShort, "mitigation", "mitigation text"); code != "" {
			v.refuseNested("V6", "threats.existing", fmt.Sprintf("%s[%d]", path, j), code, msg)
			continue
		}
		v.cleanRefs(m.Refs)
		out = append(out, m)
	}
	return out
}

func (v *validator) cleanMissing(path string, in []Missing) []Missing {
	var out []Missing
	for j := range in {
		m := in[j]
		if code, msg := v.needText(&m.Text, capShort, "mitigation", "mitigation text"); code != "" {
			v.refuseNested("V6", "threats.missing", fmt.Sprintf("%s[%d]", path, j), code, msg)
			continue
		}
		m.Control = v.cleanText(m.Control, capName, "control")
		v.cleanRefs(m.Refs)
		out = append(out, m)
	}
	return out
}

func v6PT(v *validator, p *PentestDoc) {
	p.Summary = v.cleanText(p.Summary, capSummary, "summary")
	p.PromptVersion = v.cleanText(p.PromptVersion, 20, "prompt_version")
	p.Generator.Tool = v.cleanText(p.Generator.Tool, capName, "generator")
	p.Generator.Model = v.cleanText(p.Generator.Model, capName, "generator")
	p.Limits = v.cleanList(p.Limits, capShort, "limit")
	p.Method.Standard = v.cleanText(p.Method.Standard, capName, "method")
	t := &p.Target
	t.URL = v.cleanText(t.URL, capPath, "url")
	t.Start.Source = v.cleanText(t.Start.Source, capShort, "start source")
	t.Start.Health.Path = v.cleanText(t.Start.Health.Path, capShort, "health path")
	t.Start.Argv = v.cleanList(t.Start.Argv, capArgvItem, "argv")
	for i := range t.Accounts {
		t.Accounts[i].Label = v.cleanText(t.Accounts[i].Label, 40, "account")
		t.Accounts[i].Role = v.cleanText(t.Accounts[i].Role, 40, "account")
	}
	scan(v, "V6", "coverage", p.Coverage, func(_ int, c *PTCoverageClaim) (string, string) {
		c.Reason = v.cleanText(c.Reason, capShort, "reason")
		c.Notes = v.cleanText(c.Notes, capShort, "notes")
		c.Probes = v.idList(c.Probes)
		return "", ""
	})
	scan(v, "V6", "findings", p.Findings, func(i int, f *PTFinding) (string, string) {
		f.Route = v.cleanText(f.Route, capRoute, "route")
		f.Impact = v.cleanText(f.Impact, capImpact, "impact")
		f.Fix = v.cleanText(f.Fix, capImpact, "fix")
		v.cleanRefs(f.Where.Refs)
		f.Evidence = v.idList(f.Evidence)
		v.cleanIndicator(fmt.Sprintf("findings[%d]", i), f)
		var steps []PTRepro
		for j, r := range f.Reproduction {
			r.Step = v.cleanText(r.Step, capShort, "reproduction")
			if r.Step == "" {
				v.refuseNested("V6", "findings.reproduction", fmt.Sprintf("findings[%d].reproduction[%d]", i, j), "empty_text", "The reproduction step is empty.")
				continue
			}
			r.Request = v.cleanRequest(fmt.Sprintf("findings[%d].reproduction[%d]", i, j), r.Request)
			steps = append(steps, r)
		}
		f.Reproduction = steps
		return v.needText(&f.Title, capTitle, "title", "finding title")
	})
}

// probeID returns id when it is a valid item id, "" otherwise.
func (v *validator) probeID(id string) string {
	id = strings.TrimSpace(id)
	if ValidItemID(id) {
		return id
	}
	return ""
}

// idList keeps the entries of a list that are valid item ids.
func (v *validator) idList(in []string) []string {
	var out []string
	for _, s := range in {
		if id := v.probeID(s); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// ---- V7: references between items ----

func ruleV7(v *validator) {
	if m := v.tm; m != nil {
		v7TM(v, m)
	}
	if p := v.pt; p != nil {
		p.Coverage = compact(v, "coverage", p.Coverage)
		p.Findings = compact(v, "findings", p.Findings)
	}
}

// resolveElement reports whether an element names a live item.
func resolveElement(e Element, comps, acts, flows, eps, assets map[string]bool) bool {
	switch e.Kind {
	case "component":
		return comps[e.ID]
	case "actor":
		return acts[e.ID]
	case "flow":
		return flows[e.ID]
	case "entry_point":
		return eps[e.ID]
	case "asset":
		return assets[e.ID]
	}
	return false
}

// keepKnown returns the entries of in that are in known, warning about the
// rest.
func (v *validator) keepKnown(path, field string, in []string, known map[string]bool) []string {
	var out []string
	for _, id := range in {
		if known[id] {
			out = append(out, id)
			continue
		}
		v.issue("V7", "dangling_reference_dropped", SevDropped, path,
			fmt.Sprintf("%s names %s, which is not an item of the model, so the entry was left out.", field, clip(id, 48)))
	}
	return out
}

func v7TM(v *validator, m *ThreatModelDoc) {
	s := &m.System
	zones := liveIDs(v, "zones", s.Zones, func(x *Zone) string { return x.ID })
	for i := range s.Components {
		c := &s.Components[i]
		if c.Zone != "" && !zones[c.Zone] && !v.isDead("components", i) {
			v.issue("V7", "dangling_reference_dropped", SevDropped, fmt.Sprintf("components[%d]", i),
				"The zone "+clip(c.Zone, 48)+" is not a zone of the model, so the component has no zone.")
			c.Zone = ""
		}
	}
	comps := liveIDs(v, "components", s.Components, func(x *Component) string { return x.ID })
	acts := liveIDs(v, "actors", s.Actors, func(x *Actor) string { return x.ID })
	for i := range s.Assets {
		if !v.isDead("assets", i) {
			s.Assets[i].StoredIn = v.keepKnown(fmt.Sprintf("assets[%d]", i), "stored_in", s.Assets[i].StoredIn, comps)
		}
	}
	scan(v, "V7", "entry_points", s.EntryPoints, func(_ int, e *EntryPoint) (string, string) {
		if !comps[e.Component] {
			return "dangling_reference", "The entry point names the component " + clip(e.Component, 48) + ", which is not a component of the model."
		}
		return "", ""
	})
	assets := liveIDs(v, "assets", s.Assets, func(x *Asset) string { return x.ID })
	scan(v, "V7", "flows", s.Flows, func(i int, f *Flow) (string, string) {
		for _, end := range []string{f.From, f.To} {
			switch {
			case comps[end] && acts[end]:
				return "ambiguous_endpoint", "The flow endpoint " + clip(end, 48) + " is both a component and an actor."
			case !comps[end] && !acts[end]:
				return "dangling_reference", "The flow endpoint " + clip(end, 48) + " is not a component or an actor of the model."
			}
		}
		p := fmt.Sprintf("flows[%d]", i)
		f.Data = v.keepKnown(p, "data", f.Data, assets)
		f.Crosses = v.keepKnown(p, "crosses", f.Crosses, zones)
		return "", ""
	})
	eps := liveIDs(v, "entry_points", s.EntryPoints, func(x *EntryPoint) string { return x.ID })
	flows := liveIDs(v, "flows", s.Flows, func(x *Flow) string { return x.ID })
	scan(v, "V7", "threats", m.Threats, func(i int, t *Threat) (string, string) {
		if !resolveElement(t.Element, comps, acts, flows, eps, assets) {
			return "dangling_reference", "The threat is about " + t.Element.Kind + " " + clip(t.Element.ID, 48) + ", which is not an item of the model."
		}
		if t.Actor != "" && !acts[t.Actor] {
			v.issue("V7", "dangling_reference_dropped", SevDropped, fmt.Sprintf("threats[%d]", i),
				"The actor "+clip(t.Actor, 48)+" is not an actor of the model, so the threat names none.")
			t.Actor = ""
		}
		return "", ""
	})
	scan(v, "V7", "no_threat", m.NoThreat, func(_ int, n *NoThreat) (string, string) {
		if !resolveElement(n.Element, comps, acts, flows, eps, assets) {
			return "dangling_reference", "The entry is about " + n.Element.Kind + " " + clip(n.Element.ID, 48) + ", which is not an item of the model."
		}
		return "", ""
	})
	for i := range m.AttackTrees {
		v7Tree(v, i, &m.AttackTrees[i])
	}
	s.Components = compact(v, "components", s.Components)
	s.Zones = compact(v, "zones", s.Zones)
	s.Actors = compact(v, "actors", s.Actors)
	s.Assets = compact(v, "assets", s.Assets)
	s.EntryPoints = compact(v, "entry_points", s.EntryPoints)
	s.Flows = compact(v, "flows", s.Flows)
	m.Threats = compact(v, "threats", m.Threats)
	m.NoThreat = compact(v, "no_threat", m.NoThreat)
	var trees []Tree
	for i := range m.AttackTrees {
		tr := m.AttackTrees[i]
		tr.Nodes = compact(v, fmt.Sprintf("tree_nodes#%d", i), tr.Nodes)
		if tr.Root == "" {
			// i is the tree's place in the file, not in the compacted list, so the
			// issue names the tree the agent wrote.
			v.refuseItem("V6", "attack_trees", i, "empty_root", "The attack tree has no root text, so it was left out.")
			continue
		}
		trees = append(trees, tr)
	}
	m.AttackTrees = trees
}

// v7Tree checks that every node's parent is empty or a live node of the same
// tree, and that following parents reaches the root without a cycle inside
// maxTreeDepth steps. A node whose parent chain fails is refused; refusing a
// node can orphan its children, so the pass repeats until nothing changes.
func v7Tree(v *validator, i int, tr *Tree) {
	coll := fmt.Sprintf("tree_nodes#%d", i)
	for changed := true; changed; {
		changed = false
		ids := liveIDs(v, coll, tr.Nodes, func(x *TreeNode) string { return x.ID })
		scan(v, "V7", coll, tr.Nodes, func(_ int, n *TreeNode) (string, string) {
			if n.Parent != "" && !ids[n.Parent] {
				changed = true
				return "dangling_reference", "The node's parent " + clip(n.Parent, 48) + " is not a node of this tree."
			}
			return "", ""
		})
	}
	parent := map[string]string{}
	for j := range tr.Nodes {
		if !v.isDead(coll, j) {
			parent[tr.Nodes[j].ID] = tr.Nodes[j].Parent
		}
	}
	scan(v, "V7", coll, tr.Nodes, func(_ int, n *TreeNode) (string, string) {
		cur := n.ID
		for depth := 0; cur != ""; depth++ {
			if depth > maxTreeDepth {
				return "tree_too_deep_or_cyclic", "Following this node's parents does not reach the root within " + fmt.Sprint(maxTreeDepth) + " steps."
			}
			cur = parent[cur]
		}
		return "", ""
	})
}
