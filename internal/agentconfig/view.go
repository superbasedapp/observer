package agentconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

// The read-only view (phase P4, plan sections 5.1 and 7): per tool and
// scope, the files, every catalogue setting's value in each file, the
// effective value with the layer that decided it, Observer-owned spans and
// secrets as present / absent. Pure: the boundary reads the bytes (never a
// PrivNever file) and hands them in.

// FileState is what the boundary found at a resolved path.
type FileState string

// The closed FileState vocabulary.
const (
	FilePresent FileState = "present"
	FileMissing FileState = "missing"
	// FileNeverRead: the catalogue marks the file off-limits (WriteNeeds
	// never: credential stores, editor databases, signed caches). Observer
	// does not open it, not even to say whether it exists.
	FileNeverRead FileState = "never_read"
	// FileUnresolved: no concrete path on this machine (needs a project,
	// no such file on this OS, a directory or a glob).
	FileUnresolved FileState = "unresolved"
	// FileUnreadable: the read failed (permissions, too large, a directory).
	FileUnreadable FileState = "unreadable"
)

// FileSnapshot is one file row as the boundary found it.
type FileSnapshot struct {
	Row      FileRow
	Resolved ResolvedPath
	State    FileState
	Reason   string
	Bytes    []byte
}

// ValueLayer is the badge on a value: which layer put it there.
type ValueLayer string

// The closed ValueLayer vocabulary (plan section 3 layers as the view
// shows them; the org layers join in phase P6).
const (
	ValueVendorDefault ValueLayer = "vendor_default"
	ValueL1            ValueLayer = "l1_all_adapters"
	ValueL2            ValueLayer = "l2_adapter"
	ValueL3            ValueLayer = "l3_project"
	ValueSystem        ValueLayer = "system"
	ValueVendorManaged ValueLayer = "vendor_managed"
	// The org layers (phase P6): a value the organization's policy wrote.
	ValueO1 ValueLayer = "o1_org"
	ValueO2 ValueLayer = "o2_team"
	ValueO3 ValueLayer = "o3_member"
)

// scopeLayer is the layer a value set outside Observer is adopted into
// (plan section 2.5 rule 7): the layer that owns its file.
var scopeLayer = map[Scope]ValueLayer{
	ScopeUser:          ValueL2,
	ScopeProjectShared: ValueL3,
	ScopeProjectLocal:  ValueL3,
	ScopeSystem:        ValueSystem,
	ScopeManaged:       ValueVendorManaged,
}

// LayerRecord is one value Observer wrote, from the node-local layer store:
// the badge says L1 when the file still holds exactly the value an L1 save
// wrote.
type LayerRecord struct {
	FilePath  string
	Key       string // dotted key path
	Layer     ValueLayer
	CommonKey CommonKey
	ValueHash string
}

// ValueHash is the layer store's fingerprint of a value (canonical JSON).
func ValueHash(v any) string {
	n, err := cfgfmt.Normalize(v)
	if err != nil {
		n = v
	}
	b, _ := json.Marshal(n)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// Access is the write posture of this node for the editor (plan section 6.8).
// The org half (locks, grants, posture) is filled by phase P6; until then a
// managed node is read-only (operator ruling D-102) and an individual node
// may edit everything a catalogue row allows.
type Access struct {
	// ReadOnly refuses every write; Reason says why.
	ReadOnly bool   `json:"read_only"`
	Reason   string `json:"reason,omitempty"`
	// Locked maps a setting id to the org policy that enforces it (P6).
	Locked map[string]string `json:"locked,omitempty"`
	// SecretsPosture is warn on an individual node (D-104); the org sets it
	// on a managed node (P6).
	SecretsPosture SecretsPosture `json:"secrets_posture"`
	// GrantsOnly: a managed node whose organization granted editing of
	// specific settings only (D-102). Every setting Grants does not name is
	// read-only; a file is editable only when some grant names its tool.
	GrantsOnly bool `json:"grants_only,omitempty"`
	// Grants are the setting ids (or "<tool>/*") the developer may edit.
	Grants []string `json:"grants,omitempty"`
	// OrgBlockLocked names the org policy whose instruction blocks (D-107)
	// this node holds: a save that adds, changes or removes an org block is
	// refused (org_locked); the text around it stays editable.
	OrgBlockLocked string `json:"org_block_locked,omitempty"`
	// OrgWrite marks the organization's own apply (never set from a
	// request): only it may write or remove an org block.
	OrgWrite bool `json:"-"`
}

// Granted reports whether the developer may edit a setting: always on a node
// that is not GrantsOnly; otherwise when a grant names it or its tool.
func (a Access) Granted(settingID string) bool {
	if !a.GrantsOnly {
		return true
	}
	tool, _, _ := strings.Cut(settingID, "/")
	for _, g := range a.Grants {
		if g == settingID || g == tool+"/*" {
			return true
		}
	}
	return false
}

// ToolGranted reports a "<tool>/*" grant (or a node that is not GrantsOnly):
// the whole tool is editable, including keys the catalogue does not know and
// its instruction files.
func (a Access) ToolGranted(tool string) bool {
	if !a.GrantsOnly {
		return true
	}
	for _, g := range a.Grants {
		if g == tool+"/*" {
			return true
		}
	}
	return false
}

// AnyGrantFor reports whether some grant names the tool or one of its
// settings (a file of the tool is then editable, setting by setting).
func (a Access) AnyGrantFor(tool string) bool {
	if !a.GrantsOnly {
		return true
	}
	for _, g := range a.Grants {
		if strings.HasPrefix(g, tool+"/") {
			return true
		}
	}
	return false
}

// SecretsPosture is the plaintext-secret rule (plan section 5.3).
type SecretsPosture string

// The closed SecretsPosture vocabulary.
const (
	SecretsWarn   SecretsPosture = "warn"
	SecretsRefuse SecretsPosture = "refuse"
	SecretsAllow  SecretsPosture = "allow"
)

// InspectInput is everything InspectTool needs.
type InspectInput struct {
	Tool    string
	Files   []FileSnapshot
	Layers  []LayerRecord
	Detect  SecretDetector
	Spans   SpanEnv
	Access  Access
	Project string
}

// FileView is one file in the view.
type FileView struct {
	ID         string     `json:"id"`
	Shape      string     `json:"shape"`
	Kind       FileKind   `json:"kind"`
	Scope      Scope      `json:"scope"`
	Format     Format     `json:"format"`
	Path       string     `json:"path,omitempty"`
	PathStatus PathStatus `json:"path_status"`
	State      FileState  `json:"state"`
	Reason     string     `json:"reason,omitempty"`
	Precedence int        `json:"precedence"`
	WriteNeeds Privilege  `json:"write_needs"`
	Gitignored bool       `json:"gitignored,omitempty"`
	Note       string     `json:"note,omitempty"`
	// Editable: Observer may write this file (user privilege, an engine for
	// its format, not read-only on this node).
	Editable    bool   `json:"editable"`
	NotEditable string `json:"not_editable,omitempty"`
	ParseError  string `json:"parse_error,omitempty"`
	// Etag is the sha256 of the bytes ("" when absent); a save sends it back.
	Etag string `json:"etag"`
	// Tracked: a project_shared file a commit would carry into the repo.
	Tracked      bool        `json:"tracked,omitempty"`
	Spans        []SpanState `json:"spans,omitempty"`
	Uncatalogued []string    `json:"uncatalogued,omitempty"`
	// Secrets lists the dotted paths holding a credential (presence only).
	Secrets []string `json:"secrets,omitempty"`
	Size    int      `json:"size"`
}

// SettingValue is one file's value for one setting.
type SettingValue struct {
	FileID string     `json:"file_id"`
	Scope  Scope      `json:"scope"`
	Layer  ValueLayer `json:"layer"`
	// Value is omitted for a secret; SecretPresent says it is there.
	Value         any  `json:"value,omitempty"`
	SecretPresent bool `json:"secret_present,omitempty"`
	// Masked: the value holds a hidden secret inside it.
	Masked bool `json:"masked,omitempty"`
}

// Effective is the value the tool will actually use.
type Effective struct {
	Set           bool       `json:"set"`
	Value         any        `json:"value,omitempty"`
	SecretPresent bool       `json:"secret_present,omitempty"`
	Masked        bool       `json:"masked,omitempty"`
	Layer         ValueLayer `json:"layer,omitempty"`
	FileID        string     `json:"file_id,omitempty"`
	// Shadowed names the files whose value loses to the winner.
	Shadowed []string `json:"shadowed,omitempty"`
}

// SettingView is one catalogue row with its values.
type SettingView struct {
	ID         string         `json:"id"`
	Path       string         `json:"path"`
	Shape      string         `json:"shape"`
	Type       ValueType      `json:"type"`
	Enum       []string       `json:"enum,omitempty"`
	Min        *float64       `json:"min,omitempty"`
	Max        *float64       `json:"max,omitempty"`
	Default    string         `json:"default,omitempty"`
	Desc       string         `json:"desc,omitempty"`
	Source     string         `json:"source,omitempty"`
	Verified   Verified       `json:"verified"`
	Owner      Owner          `json:"owner"`
	Writable   bool           `json:"writable"`
	Danger     DangerClass    `json:"danger,omitempty"`
	Secret     bool           `json:"secret,omitempty"`
	Deprecated bool           `json:"deprecated,omitempty"`
	Scopes     []Scope        `json:"scopes,omitempty"`
	Note       string         `json:"note,omitempty"`
	Common     []CommonKey    `json:"common,omitempty"`
	Values     []SettingValue `json:"values,omitempty"`
	Effective  Effective      `json:"effective"`
	// Locked names the org policy enforcing the value (P6).
	Locked string `json:"locked,omitempty"`
	// ReadOnlyReason is the user-facing note for a non-writable row
	// (plan section 7, ruling 11), one phrasing per reason.
	ReadOnlyReason string `json:"read_only_reason,omitempty"`
}

// ToolView is the whole read-only view of one tool.
type ToolView struct {
	Tool     string        `json:"tool"`
	Project  string        `json:"project,omitempty"`
	Coverage ToolCoverage  `json:"coverage"`
	Files    []FileView    `json:"files"`
	Settings []SettingView `json:"settings"`
	Access   Access        `json:"access"`
}

// parsedFile is one present file, decoded.
type parsedFile struct {
	snap FileSnapshot
	doc  cfgfmt.Doc
	tree map[string]any
}

// Etag fingerprints file bytes ("" for an absent file).
func Etag(b []byte, present bool) string {
	if !present {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// InspectTool builds the read-only view of one tool.
func InspectTool(in InspectInput) ToolView {
	view := ToolView{Tool: in.Tool, Project: in.Project, Access: in.Access}
	for _, c := range Coverage() {
		if c.Tool == in.Tool {
			view.Coverage = c
		}
	}
	parsed := map[string]*parsedFile{}
	for _, snap := range in.Files {
		fv, pf := inspectFile(in, snap)
		view.Files = append(view.Files, fv)
		if pf != nil {
			parsed[snap.Row.ID] = pf
		}
	}
	sort.SliceStable(view.Files, func(i, j int) bool {
		a, b := view.Files[i], view.Files[j]
		if a.Shape != b.Shape {
			return a.Shape < b.Shape
		}
		return a.Precedence < b.Precedence
	})
	commonBySetting := map[string][]CommonKey{}
	for _, m := range MapRows() {
		if m.Tool != in.Tool {
			continue
		}
		for _, id := range m.Settings {
			commonBySetting[id] = append(commonBySetting[id], m.Key)
		}
	}
	layers := map[string]LayerRecord{}
	for _, l := range in.Layers {
		layers[l.FilePath+"\x00"+l.Key] = l
	}
	judges := map[string]secretJudge{}
	for _, r := range SettingsFor(in.Tool) {
		j, ok := judges[r.FileID]
		if !ok {
			j = newSecretJudge(r.FileID, in.Detect)
			judges[r.FileID] = j
		}
		view.Settings = append(view.Settings, inspectSetting(in, r, in.Files, parsed, layers, j, commonBySetting[r.ID]))
	}
	return view
}

// IsTracked reports whether a save to the file would be carried into the
// repository by the next commit: a project_shared file, and never one the
// vendor documents as a gitignored personal overlay. It is the ONE answer
// every surface (the file view, the instruction list, the UI's "commits
// with the repo" warning) reads.
func IsTracked(r FileRow) bool {
	return r.Scope == ScopeProjectShared && !r.Gitignored
}

func inspectFile(in InspectInput, snap FileSnapshot) (FileView, *parsedFile) {
	r := snap.Row
	fv := FileView{
		ID: r.ID, Shape: r.Shape, Kind: r.Kind, Scope: r.Scope, Format: r.Format,
		Path: snap.Resolved.Path, PathStatus: snap.Resolved.Status, State: snap.State, Reason: snap.Reason,
		Precedence: r.Precedence, WriteNeeds: r.WriteNeeds, Gitignored: r.Gitignored, Note: r.Note,
		Etag: Etag(snap.Bytes, snap.State == FilePresent), Size: len(snap.Bytes),
		Tracked: IsTracked(r),
	}
	fv.Editable, fv.NotEditable = fileEditable(r, snap, in.Access)
	if snap.State != FilePresent {
		fv.Spans = SpanStates(in.Spans, r.ID, nil, nil, false)
		return fv, nil
	}
	eng, ok := r.Format.Engine()
	if !ok {
		return fv, nil
	}
	doc, err := cfgfmt.Parse(eng, snap.Bytes)
	if err != nil {
		fv.ParseError = err.Error()
		return fv, nil
	}
	tree, err := doc.Value()
	if err != nil {
		fv.ParseError = err.Error()
		return fv, nil
	}
	fv.Spans = SpanStates(in.Spans, r.ID, tree, snap.Bytes, true)
	if r.Kind != KindInstructions && r.Kind != KindSkill && r.Kind != KindAgent && r.Kind != KindCommand && r.Kind != KindRule {
		fv.Uncatalogued = UncataloguedKeys(r.Shape, tree)
		j := newSecretJudge(r.Shape, in.Detect)
		for _, m := range j.findSecrets(tree) {
			fv.Secrets = append(fv.Secrets, m.Path.String())
		}
	}
	return fv, &parsedFile{snap: snap, doc: doc, tree: tree}
}

// fileEditableRule is one row of the "may Observer write this file" table,
// walked top-down; the first failing rule names the reason.
type fileEditableRule struct {
	fails  func(r FileRow, snap FileSnapshot, a Access) bool
	reason string
}

var fileEditableRules = []fileEditableRule{
	{
		func(r FileRow, _ FileSnapshot, _ Access) bool { return r.WriteNeeds == PrivNever },
		"This file is never read or written by Observer (credentials, editor state or a signed cache).",
	},
	{
		func(r FileRow, _ FileSnapshot, _ Access) bool { return r.WriteNeeds == PrivAdminRoot },
		"Writing this file needs administrator rights; your organization deploys it through device management.",
	},
	{
		func(r FileRow, _ FileSnapshot, _ Access) bool { return r.Kind == KindToolState },
		"The tool maintains this file itself; editing it here would be overwritten.",
	},
	{
		func(r FileRow, _ FileSnapshot, _ Access) bool { _, ok := r.Format.Engine(); return !ok },
		"Observer shows this file but has no safe editor for its format.",
	},
	{
		func(_ FileRow, s FileSnapshot, _ Access) bool { return s.Resolved.Status == PathEnvUnset },
		"The tool reads this file only while its environment variable names a directory, and that variable is not set here.",
	},
	{
		func(_ FileRow, s FileSnapshot, _ Access) bool { return s.Resolved.Status == PathRelocationUnresolved },
		"The tool's relocation variable holds a relative path, read against a working directory Observer cannot know, so Observer writes nothing (not the default location either).",
	},
	{
		func(_ FileRow, s FileSnapshot, _ Access) bool { return s.Resolved.Status != PathResolved },
		"No concrete file on this machine (select a project, or the tool has no such file on this OS).",
	},
	{
		func(_ FileRow, s FileSnapshot, _ Access) bool { return s.State == FileUnreadable },
		"Observer could not read this file.",
	},
	{func(_ FileRow, _ FileSnapshot, a Access) bool { return a.ReadOnly }, ""},
	{
		func(r FileRow, _ FileSnapshot, a Access) bool {
			if isInstructionKind(r.Kind) {
				return !a.ToolGranted(r.Tool)
			}
			return !a.AnyGrantFor(r.Tool)
		},
		"Your organization manages this machine and has not granted editing of this tool's files.",
	},
}

func fileEditable(r FileRow, snap FileSnapshot, a Access) (bool, string) {
	for _, rule := range fileEditableRules {
		if rule.fails(r, snap, a) {
			reason := rule.reason
			if reason == "" {
				reason = a.Reason
			}
			return false, reason
		}
	}
	return true, ""
}

// readOnlyReason is the user-facing note for a non-writable setting row
// (plan section 7 / ruling 11), one phrasing per owner.
func readOnlyReason(r SettingRow, a Access) string {
	switch {
	case a.Locked[r.ID] != "":
		return "Set by your organization's policy " + a.Locked[r.ID] + "."
	case !a.Granted(r.ID):
		return "Your organization manages this machine and has not granted editing of this setting."
	case r.Owner.IsObserver():
		return "Observer manages this (" + strings.TrimPrefix(string(r.Owner), "observer:") + "); use its own verb instead of editing it here."
	case r.Owner == OwnerToolState || r.Owner == OwnerServerCache:
		return "The tool maintains this itself; editing it here would be overwritten."
	case r.Owner == OwnerVendorManaged:
		return "Your organization manages this in the vendor's admin console or managed-settings file."
	case r.Verified == VerifiedUnverified && !r.Writable:
		return "Not verified for your version of the tool."
	case !r.Writable:
		return "No file at a scope this setting allows is writable with your own rights."
	case a.ReadOnly:
		return a.Reason
	}
	return ""
}

func inspectSetting(in InspectInput, r SettingRow, files []FileSnapshot, parsed map[string]*parsedFile,
	layers map[string]LayerRecord, j secretJudge, common []CommonKey,
) SettingView {
	sv := SettingView{
		ID: r.ID, Path: r.Path.String(), Shape: r.FileID, Type: r.Type, Enum: r.Enum, Min: r.Min, Max: r.Max,
		Default: r.Default, Desc: firstSentence(r.Desc), Source: r.Source, Verified: r.Verified, Owner: r.Owner,
		Writable: r.Writable && !in.Access.ReadOnly && in.Access.Locked[r.ID] == "" && in.Access.Granted(r.ID), Danger: r.Danger, Secret: r.Secret,
		Deprecated: r.Deprecated, Scopes: r.Scopes, Note: r.Note, Common: common, Locked: in.Access.Locked[r.ID],
	}
	if !sv.Writable {
		sv.ReadOnlyReason = readOnlyReason(r, in.Access)
	}
	type cand struct {
		fileID string
		prec   int
		val    SettingValue
	}
	var cands []cand
	for _, snap := range files {
		if snap.Row.Shape != r.FileID {
			continue
		}
		pf := parsed[snap.Row.ID]
		if pf == nil {
			continue
		}
		v, found := lookupTree(pf.tree, r.Path)
		if !found {
			continue
		}
		val := SettingValue{FileID: snap.Row.ID, Scope: snap.Row.Scope, Layer: scopeLayer[snap.Row.Scope]}
		if rec, ok := layers[snap.Resolved.Path+"\x00"+r.Path.String()]; ok && rec.ValueHash == ValueHash(v) {
			val.Layer = rec.Layer
		}
		switch {
		case j.wholeSecret(r.Path, v):
			val.SecretPresent = true
		case j.containsSecret(v):
			val.Value, val.Masked = j.maskValue(v), true
		default:
			val.Value = v
		}
		cands = append(cands, cand{fileID: snap.Row.ID, prec: snap.Row.Precedence, val: val})
	}
	sort.SliceStable(cands, func(i, k int) bool { return cands[i].prec > cands[k].prec })
	for _, c := range cands {
		sv.Values = append(sv.Values, c.val)
	}
	if len(cands) > 0 {
		w := cands[0].val
		sv.Effective = Effective{Set: true, Value: w.Value, SecretPresent: w.SecretPresent, Masked: w.Masked, Layer: w.Layer, FileID: w.FileID}
		for _, c := range cands[1:] {
			sv.Effective.Shadowed = append(sv.Effective.Shadowed, c.fileID)
		}
	} else if r.Default != "" && !r.Secret {
		var d any
		if err := json.Unmarshal([]byte(r.Default), &d); err == nil {
			sv.Effective = Effective{Set: true, Value: d, Layer: ValueVendorDefault}
		}
	}
	return sv
}

// firstSentence trims a vendor description for the list view.
func firstSentence(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, ". "); i > 0 && i < 240 {
		return s[:i+1]
	}
	if len(s) > 240 {
		return s[:237] + "..."
	}
	return s
}

// UncataloguedKeys lists the top-most key paths of a document that no
// catalogue row of the shape covers (plan section 2.2 tier 3): still
// editable in the raw editor, a WARNING on save, never an error.
func UncataloguedKeys(shape string, tree map[string]any) []string {
	rows := shapeRows(shape)
	if len(rows) == 0 {
		return nil
	}
	exact := map[string]bool{}
	prefix := map[string]bool{}
	for _, r := range rows {
		exact[r.Path.String()] = true
		for i := 1; i < len(r.Path); i++ {
			prefix[r.Path[:i].String()] = true
		}
	}
	var out []string
	var walk func(p KeyPath, m map[string]any)
	walk = func(p KeyPath, m map[string]any) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			kp := append(append(KeyPath(nil), p...), k)
			s := kp.String()
			switch {
			case exact[s]:
				continue
			case prefix[s]:
				if sub, ok := m[k].(map[string]any); ok {
					walk(kp, sub)
				}
			default:
				out = append(out, s)
			}
		}
	}
	walk(nil, tree)
	return out
}

// MaskedFile renders one file's bytes with every secret hidden, for the raw
// view. Markdown is masked through maskText (the boundary's scrubber).
func MaskedFile(row FileRow, b []byte, detect SecretDetector, maskText func(string) (string, bool)) (MaskedDoc, error) {
	eng, ok := row.Format.Engine()
	if !ok {
		return maskMarkdown(b, maskText), nil
	}
	// A file that does not parse comes back with its free text masked: the
	// raw view of a broken file must still never show a credential.
	md, err := maskDocument(eng, row.Shape, b, detect, maskText)
	return md, err
}

// DecodeTree decodes a file's bytes with its format engine (nil when the
// format has no engine or the bytes do not parse).
func DecodeTree(row FileRow, b []byte) map[string]any {
	eng, ok := row.Format.Engine()
	if !ok {
		return nil
	}
	doc, err := cfgfmt.Parse(eng, b)
	if err != nil {
		return nil
	}
	tree, err := doc.Value()
	if err != nil {
		return nil
	}
	return tree
}

// LookupDotted reads a value at a dotted path as Change.Path spells it (a
// key holding a dot is quoted by KeyPath.String; the tree disambiguates).
func LookupDotted(tree map[string]any, dotted string) (any, bool) {
	return lookupTree(tree, splitDotted(dotted, tree))
}
