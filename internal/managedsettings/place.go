package managedsettings

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// layerDoc accumulates one layer's document while placing.
type layerDoc struct {
	layer   Layer
	file    agentconfig.FileRow
	doc     cfgfmt.Doc
	entries []entry
}

// placer is one FromPolicy pass: the layer documents being filled and the
// per-tool results.
type placer struct {
	docs   map[string]*layerDoc // layer FileID -> doc
	byTool map[string]*ToolBundle
	out    *Bundle
}

func (p *placer) tool(name string) *ToolBundle {
	t, ok := p.byTool[name]
	if !ok {
		t = &ToolBundle{Tool: name}
		p.byTool[name] = t
	}
	return t
}

func (p *placer) skip(toolName string, s Skip) {
	p.out.Unplaced = append(p.out.Unplaced, s)
	if toolName != "" {
		p.tool(toolName).Skipped = append(p.tool(toolName).Skipped, s)
	}
}

// put sets one key in a layer's document, creating the document on first use.
func (p *placer) put(l Layer, key agentconfig.KeyPath, value any) error {
	d, ok := p.docs[l.FileID]
	if !ok {
		f, found := fileRow(l.FileID)
		if !found {
			return fmt.Errorf("managedsettings: layer %s names no catalogue file", l.FileID)
		}
		eng, ok := f.Format.Engine()
		if !ok {
			return fmt.Errorf("managedsettings: layer %s has no format engine", l.FileID)
		}
		doc, err := cfgfmt.Parse(eng, nil)
		if err != nil {
			return fmt.Errorf("managedsettings: layer %s: %w", l.FileID, err)
		}
		d = &layerDoc{layer: l, file: f, doc: doc}
		p.docs[l.FileID] = d
	}
	if err := d.doc.Set(cfgfmt.Path(key), value); err != nil {
		return err
	}
	d.entries = append(d.entries, entry{Key: key, Value: value})
	return nil
}

// record notes a placed value under the layer's tool.
func (p *placer) record(l Layer, row agentconfig.SettingRow, d orgcontract.AgentConfigDirective, key, derived string) {
	f, _ := fileRow(l.FileID)
	t := p.tool(f.Tool)
	t.Placed = append(t.Placed, Placed{
		Setting: d.Setting, Mode: d.Mode, FileID: l.FileID, Key: key, Strength: l.bestFor(row.ID, f), Derived: derived,
	})
}

// directive places one directive: its own key in every layer that takes it,
// then the constraints it derives. It returns the skip reason when nothing
// landed ("" when something did).
func (p *placer) directive(d orgcontract.AgentConfigDirective, row agentconfig.SettingRow, value any) (string, error) {
	targets, failure := layersFor(row, d.Mode)
	landed := false
	for _, l := range targets {
		key, _ := l.keyFor(row)
		if l.Check != nil && l.Check(row.ID, value) != nil {
			failure = ReasonValueRefused
			continue
		}
		if err := p.put(l, key, value); err != nil {
			failure = ReasonValueNotWritten
			continue
		}
		landed = true
		p.record(l, row, d, key.String(), "")
	}
	for _, dv := range derivedFor(d.Setting, d.Mode) {
		v, ok := dv.Transform(value)
		if !ok {
			continue
		}
		l, found := layerByFile(dv.To)
		if !found {
			return "", fmt.Errorf("managedsettings: derived rule %s targets unknown layer %s", dv.Name, dv.To)
		}
		if err := p.put(l, dv.Path, v); err != nil {
			failure = ReasonValueNotWritten
			continue
		}
		landed = true
		p.record(l, row, d, dv.Path.String(), dv.Name)
	}
	if landed {
		return "", nil
	}
	if failure == "" {
		failure = ReasonNotInLayer
	}
	return failure, nil
}

// sortedDirectives orders the body's directives by setting, project, mode.
func sortedDirectives(in []orgcontract.AgentConfigDirective) []orgcontract.AgentConfigDirective {
	dirs := append([]orgcontract.AgentConfigDirective(nil), in...)
	sort.SliceStable(dirs, func(i, j int) bool {
		if dirs[i].Setting != dirs[j].Setting {
			return dirs[i].Setting < dirs[j].Setting
		}
		if dirs[i].Project != dirs[j].Project {
			return dirs[i].Project < dirs[j].Project
		}
		return dirs[i].Mode < dirs[j].Mode
	})
	return dirs
}

// FromPolicy renders the managed-layer artifacts of one composed policy.
func FromPolicy(in PolicyInput) (Bundle, error) {
	ident := strings.TrimSpace(in.Identifier)
	if ident == "" {
		ident = DefaultIdentifier
	}
	out := Bundle{Audience: in.Audience, PolicyVersion: in.Version, Policies: append([]string{}, in.Body.Policies...)}
	p := &placer{docs: map[string]*layerDoc{}, byTool: map[string]*ToolBundle{}, out: &out}
	for _, d := range sortedDirectives(in.Body.Directives) {
		row, ok := agentconfig.Setting(d.Setting)
		if !ok {
			p.skip("", Skip{Setting: d.Setting, Mode: d.Mode, Project: d.Project, Reason: ReasonUnknownSetting})
			continue
		}
		if strings.TrimSpace(d.Project) != "" {
			p.skip(row.Tool, Skip{Setting: d.Setting, Mode: d.Mode, Project: d.Project, Reason: ReasonProjectScope})
			continue
		}
		value, err := decodeValue(d.Value)
		if err != nil {
			p.skip(row.Tool, Skip{Setting: d.Setting, Mode: d.Mode, Reason: ReasonUndecodable})
			continue
		}
		reason, err := p.directive(d, row, value)
		if err != nil {
			return Bundle{}, err
		}
		if reason != "" {
			p.skip(row.Tool, Skip{Setting: d.Setting, Mode: d.Mode, Reason: reason})
		}
	}
	if err := p.render(in, ident); err != nil {
		return Bundle{}, err
	}
	if out.Unplaced == nil {
		out.Unplaced = []Skip{}
	}
	if out.Tools == nil {
		out.Tools = []ToolBundle{}
	}
	out.Locks = Locks()
	out.Readme = bundleReadme(out)
	return out, nil
}

// render turns every filled layer into its channels and finishes each tool.
func (p *placer) render(in PolicyInput, ident string) error {
	fileIDs := make([]string, 0, len(p.docs))
	for id := range p.docs {
		fileIDs = append(fileIDs, id)
	}
	sort.Strings(fileIDs)
	for _, id := range fileIDs {
		d := p.docs[id]
		arts, err := renderLayer(d, in, ident)
		if err != nil {
			return err
		}
		t := p.tool(d.file.Tool)
		t.Artifacts = append(t.Artifacts, arts...)
	}
	names := make([]string, 0, len(p.byTool))
	for n := range p.byTool {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t := p.byTool[n]
		finishTool(t)
		p.out.Tools = append(p.out.Tools, *t)
	}
	return nil
}

// layersFor returns the managed layers a setting's value lands in for a
// mode: the layers taking the setting's file shape whose Modes include the
// mode, whose catalogue scope the setting may be set at and that have a key
// for it. The reason explains an empty result.
func layersFor(row agentconfig.SettingRow, mode string) ([]Layer, string) {
	var out []Layer
	toolHasLayer, shapeHasMode := false, false
	for _, l := range Layers() {
		f, ok := fileRow(l.FileID)
		if !ok || !contains(toolsOfLayer(l), row.Tool) {
			continue
		}
		toolHasLayer = true
		if !l.takesShape(f.Shape, row.FileID) || !l.carries(mode) {
			continue
		}
		shapeHasMode = true
		if !l.admits(f, row) {
			continue
		}
		if _, ok := l.keyFor(row); !ok {
			continue
		}
		out = append(out, l)
	}
	switch {
	case len(out) > 0:
		return out, ""
	case !toolHasLayer:
		return nil, ReasonNoManagedLayer
	case !shapeHasMode && mode == orgcontract.AgentConfigModeDefault:
		return nil, ReasonNoDefaultLayer
	default:
		return nil, ReasonNotInLayer
	}
}

func scopeAllowed(scopes []agentconfig.Scope, s agentconfig.Scope) bool {
	for _, x := range scopes {
		if x == s {
			return true
		}
	}
	return false
}

// decodeValue turns a directive's JSON into the engines' native value
// (whole numbers as int64), the way a managed node decodes it.
func decodeValue(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	if v == nil {
		return nil, fmt.Errorf("null value")
	}
	return cfgfmt.NativeNumbers(v), nil
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// renderLayer renders one filled layer into its file, profile and registry
// artifacts.
func renderLayer(d *layerDoc, in PolicyInput, ident string) ([]Artifact, error) {
	l, f := d.layer, d.file
	tree, err := d.doc.Value()
	if err != nil {
		return nil, fmt.Errorf("managedsettings: %s: %w", l.FileID, err)
	}
	body := d.doc.Bytes()
	if hdr := l.header(in); hdr != "" {
		body = append([]byte(hdr), body...)
	}
	fileName := l.fileName(f)
	base := strings.TrimSuffix(fileName, path.Ext(fileName))
	strengths := func(ch Channel, oses []string) map[string]Strength {
		m := map[string]Strength{}
		for _, o := range oses {
			m[o] = l.channelStrength(ch, o)
		}
		return m
	}
	var out []Artifact
	if fileOS := l.fileOS(f); len(fileOS) > 0 {
		out = append(out, Artifact{
			Name: f.Tool + "/" + fileName, FileID: l.FileID, Channel: ChannelFile, OS: fileOS,
			Format: string(f.Format), Encoding: EncodingUTF8, Content: string(body),
			Strength: strengths(ChannelFile, fileOS), Install: l.fileInstall(f, fileName), Note: l.Note,
		})
	}
	desc := fmt.Sprintf("Observer AI tool policy for %s, version %d (%s).", in.Audience, in.Version, f.Tool)
	if l.Profile != nil {
		content, err := renderProfile(*l.Profile, ident+"."+profileSlug(l.FileID), "Observer: "+f.Tool+" managed settings", desc, tree, d.entries, body)
		if err != nil {
			return nil, err
		}
		out = append(out, Artifact{
			Name: f.Tool + "/" + base + ".mobileconfig", FileID: l.FileID, Channel: ChannelProfile, OS: []string{"darwin"},
			Format: "mobileconfig", Encoding: EncodingUTF8, Content: content,
			Strength: strengths(ChannelProfile, []string{"darwin"}),
			Install: []InstallStep{{OS: "darwin", Steps: []string{
				"Upload the .mobileconfig to your MDM (Jamf, Kandji, Mosyle, Intune) as a custom configuration profile scoped to the devices, or",
				"for one test Mac: open the file, then System Settings > Privacy and Security > Profiles > Install.",
				"The profile is unsigned: sign it with your MDM's certificate if your MDM requires signed profiles.",
				"Check with: sudo profiles show -type configuration | grep " + l.Profile.Domain,
			}}},
			Note: "Managed preferences domain " + l.Profile.Domain + ".",
		})
	}
	if l.Registry != nil {
		comment := []string{
			fmt.Sprintf("Observer AI tool policy for %s, version %d (%s).", in.Audience, in.Version, f.Tool),
			"Import from an elevated prompt: reg import <file>, or deploy the same values with Group Policy Preferences or Intune.",
		}
		content, err := renderRegistry(*l.Registry, comment, tree, d.entries)
		if err != nil {
			return nil, err
		}
		out = append(out, Artifact{
			Name: f.Tool + "/" + base + ".reg", FileID: l.FileID, Channel: ChannelRegistry, OS: []string{"windows"},
			Format: "reg", Encoding: EncodingUTF16LE, Content: content,
			Strength: strengths(ChannelRegistry, []string{"windows"}),
			Install: []InstallStep{{OS: "windows", Steps: []string{
				"From an elevated prompt: reg import " + base + ".reg",
				`Fleet: deploy the same values under HKEY_LOCAL_MACHINE\` + l.Registry.Key + " with Group Policy Preferences (Registry) or an Intune configuration profile.",
				"HKLM policy keys are writable by administrators only.",
			}}},
			Note: `Registry key HKEY_LOCAL_MACHINE\` + l.Registry.Key + ".",
		})
	}
	return out, nil
}

func profileSlug(fileID string) string {
	return strings.NewReplacer("/", ".", "_", "-").Replace(fileID)
}

// finishTool sorts a tool's rows and computes its summary fields.
func finishTool(t *ToolBundle) {
	sort.SliceStable(t.Artifacts, func(i, j int) bool { return t.Artifacts[i].Name < t.Artifacts[j].Name })
	best := StrengthTamperEvident
	srcs := map[string]bool{}
	verified := "doc"
	seenLayer := map[string]bool{}
	for _, p := range t.Placed {
		if Stronger(p.Strength, best) {
			best = p.Strength
		}
		if seenLayer[p.FileID] {
			continue
		}
		seenLayer[p.FileID] = true
		if l, ok := layerByFile(p.FileID); ok {
			for _, s := range l.Sources {
				srcs[s] = true
			}
			if !l.Verified {
				verified = "unverified"
			}
		}
	}
	if len(t.Placed) == 0 {
		verified = ""
	}
	t.Strength = best
	t.Verified = verified
	t.Sources = []string{}
	for s := range srcs {
		t.Sources = append(t.Sources, s)
	}
	sort.Strings(t.Sources)
	if t.Placed == nil {
		t.Placed = []Placed{}
	}
	if t.Skipped == nil {
		t.Skipped = []Skip{}
	}
	if t.Artifacts == nil {
		t.Artifacts = []Artifact{}
	}
	t.Readme = toolReadme(*t)
}
