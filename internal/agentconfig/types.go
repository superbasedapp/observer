package agentconfig

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
)

// FileKind says what a file IS to the tool that reads it.
type FileKind string

// The closed FileKind vocabulary.
const (
	KindSettings     FileKind = "settings"
	KindMCP          FileKind = "mcp"
	KindHooks        FileKind = "hooks"
	KindPermissions  FileKind = "permissions"
	KindInstructions FileKind = "instructions"
	KindRule         FileKind = "rule"
	KindSkill        FileKind = "skill"
	KindAgent        FileKind = "agent"
	KindCommand      FileKind = "command"
	// KindToolState is a file the tool maintains itself (caches, auth,
	// session state). Shown, never form-edited.
	KindToolState FileKind = "tool_state"
)

// Scope is where a file sits in the tool's own layering.
type Scope string

// The closed Scope vocabulary.
const (
	ScopeManaged       Scope = "managed"
	ScopeSystem        Scope = "system"
	ScopeUser          Scope = "user"
	ScopeProjectShared Scope = "project_shared"
	ScopeProjectLocal  Scope = "project_local"
)

// Scopes returns the closed Scope vocabulary in layering order.
func Scopes() []Scope {
	return []Scope{ScopeSystem, ScopeUser, ScopeProjectShared, ScopeProjectLocal, ScopeManaged}
}

// Format is the on-disk syntax of a file. It is a superset of the
// cfgfmt engines: crushrc and script have no engine (raw text only) and
// vscode_settings is JSONC with VS Code's dotted-key convention.
type Format string

// The closed Format vocabulary.
const (
	FormatJSON           Format = "json"
	FormatJSONC          Format = "jsonc"
	FormatTOML           Format = "toml"
	FormatYAML           Format = "yaml"
	FormatMarkdown       Format = "markdown"
	FormatMDC            Format = "mdc"
	FormatCrushrc        Format = "crushrc"
	FormatVSCodeSettings Format = "vscode_settings"
	// FormatScript is a code file (a TypeScript mod, a Python plugin): raw
	// text only, never form-edited; listed so an Observer-owned plugin file
	// has a Files row.
	FormatScript Format = "script"
)

// Engine returns the cfgfmt engine that edits this format; ok is false for
// a raw-text-only format.
func (f Format) Engine() (cfgfmt.Format, bool) {
	switch f {
	case FormatJSON:
		return cfgfmt.FormatJSON, true
	case FormatJSONC, FormatVSCodeSettings:
		return cfgfmt.FormatJSONC, true
	case FormatTOML:
		return cfgfmt.FormatTOML, true
	case FormatYAML:
		return cfgfmt.FormatYAML, true
	case FormatMarkdown:
		return cfgfmt.FormatMarkdown, true
	case FormatMDC:
		return cfgfmt.FormatMDC, true
	}
	return "", false
}

// Privilege is what writing a file requires.
type Privilege string

// The closed Privilege vocabulary.
const (
	PrivUser Privilege = "user"
	// PrivAdminRoot: system paths and OS policy stores; Observer emits
	// artifacts for MDM instead of writing them (plan section 6.2).
	PrivAdminRoot Privilege = "admin_root"
	// PrivNever: editor state databases, keychains, signed caches, files
	// that hold plaintext credentials. Never written.
	PrivNever Privilege = "never"
)

// InstructionStrategy is how an org instruction block reaches a tool
// (plan section 6.4). Empty until the P6 lane fills the column.
type InstructionStrategy string

// The closed InstructionStrategy vocabulary.
const (
	StrategyBlockInOwnFile    InstructionStrategy = "block_in_own_file"
	StrategyDedicatedRuleFile InstructionStrategy = "dedicated_rule_file"
	StrategyAgentsMDImport    InstructionStrategy = "agents_md_import"
	StrategyAgentsMDNative    InstructionStrategy = "agents_md_native"
)

// GroundingKind names the evidence class behind a row.
type GroundingKind string

// The closed GroundingKind vocabulary.
const (
	GroundDoc        GroundingKind = "doc"
	GroundSchema     GroundingKind = "schema"
	GroundAdapterDoc GroundingKind = "adapter_doc"
	GroundLive       GroundingKind = "live"
	GroundSource     GroundingKind = "source"
)

// Grounding is the evidence for a file row.
type Grounding struct {
	Kind GroundingKind
	// Source is a vendor URL, a repo path, or "node 1" for a live probe.
	Source string
	// Date is when the evidence was taken (YYYY-MM-DD).
	Date string
}

// OSPaths is a file location per OS. Tokens: "~" (the user's home),
// "<project>" (the project root), "%APPDATA%", "%LOCALAPPDATA%",
// "%ProgramData%" and "$XDG_CONFIG_HOME" are expanded by the caller, and a
// variable-only token such as "$OPENCODE_CONFIG_DIR" names a directory
// the tool reads only while the variable is set (paths.go pathTokens). An
// empty entry means the file does not exist on that OS. A trailing "/"
// names a directory whose file name the vendor does not document.
type OSPaths struct {
	Linux   string
	Darwin  string
	Windows string
}

// All returns the paths that are set, Linux / Darwin / Windows order.
func (p OSPaths) All() []string {
	var out []string
	for _, s := range []string{p.Linux, p.Darwin, p.Windows} {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// samePath is an OSPaths with one path on every OS.
func samePath(p string) OSPaths { return OSPaths{Linux: p, Darwin: p, Windows: p} }

// FileRow is one physical config or instruction file of one tool.
type FileRow struct {
	// ID is "<tool>/<name>", unique across the table.
	ID   string
	Tool string
	// Shape groups the files that hold the same key set at different
	// scopes ("claude-code/settings" covers the user, project, local and
	// managed settings.json files). SettingRow.FileID names a shape.
	Shape      string
	Kind       FileKind
	Scope      Scope
	Paths      OSPaths
	Format     Format
	SchemaURL  string
	Precedence int // the tool's own order: higher wins
	WriteNeeds Privilege
	// Gitignored marks a project_local file the vendor documents as
	// personal (never committed).
	Gitignored bool
	// Borrowed marks an instruction-family file in a directory the tool
	// reads but does not own (another tool's tree or a tool-agnostic one,
	// guidance.Rule.Borrowed): it is never evidence the tool is installed.
	Borrowed            bool
	InstructionStrategy InstructionStrategy
	// DropInDir names a directory beside the file whose *.json drop-ins the
	// tool merges into it in name order (Claude Code's managed-settings.d);
	// "" for none. The directory lives next to each OS path, so readers and
	// the guard's hook-switch rows derive it from Paths (surface-gap FU-35).
	DropInDir string
	Grounding Grounding
	Note      string
}

// KeyPath is a format-agnostic key path inside a file.
type KeyPath []string

// String renders the path dotted (quoting a segment that holds a dot).
func (p KeyPath) String() string { return cfgfmt.Path(p).String() }

// ValueType is a setting's value shape.
type ValueType string

// The closed ValueType vocabulary.
const (
	TypeString     ValueType = "string"
	TypeEnum       ValueType = "enum"
	TypeInt        ValueType = "int"
	TypeFloat      ValueType = "float"
	TypeBool       ValueType = "bool"
	TypeStringList ValueType = "string_list"
	TypeStringMap  ValueType = "string_map"
	TypeObject     ValueType = "object"
	TypeRuleList   ValueType = "rule_list"
	TypeMCPMap     ValueType = "mcp_map"
)

// Verified is how a setting row was established.
type Verified string

// The closed Verified vocabulary.
const (
	VerifiedDoc        Verified = "doc"
	VerifiedSchema     Verified = "schema"
	VerifiedLive       Verified = "live"
	VerifiedUnverified Verified = "unverified"
)

// Owner says who may write a setting. Only OwnerUser rows are editable;
// "observer:<writer>" rows are spans an Observer writer owns (plan section
// 2.3, stamped from the registry in phase P3).
type Owner string

// The fixed Owner values ("observer:<writer>" is built by ObserverOwner).
const (
	OwnerUser          Owner = "user"
	OwnerToolState     Owner = "tool_state"
	OwnerServerCache   Owner = "server_cache"
	OwnerVendorManaged Owner = "vendor_managed"
)

// ObserverOwner is the Owner for a span an Observer writer owns.
func ObserverOwner(writer string) Owner { return Owner("observer:" + writer) }

// IsObserver reports an Observer-owned span.
func (o Owner) IsObserver() bool { return strings.HasPrefix(string(o), "observer:") }

// Known reports a value in the Owner vocabulary.
func (o Owner) Known() bool {
	switch o {
	case OwnerUser, OwnerToolState, OwnerServerCache, OwnerVendorManaged:
		return true
	}
	return o.IsObserver() && len(o) > len("observer:")
}

// DangerClass is the hygiene posture of a setting (plan section 5.4).
type DangerClass string

// The closed DangerClass vocabulary.
const (
	DangerNone DangerClass = ""
	// DangerConfirm: some values loosen safety (bypass approvals, open a
	// sandbox, run an arbitrary command); the save needs a confirmation.
	DangerConfirm DangerClass = "confirm"
	// DangerRefuseWhileIntegrated: the setting can switch off Observer's
	// own capture or hooks; refused while Observer integrates the tool.
	DangerRefuseWhileIntegrated DangerClass = "refuse_while_integrated"
)

// SettingRow is one setting of one tool.
type SettingRow struct {
	// ID is "<tool>/<dotted key path>" ("codex/model").
	ID   string
	Tool string
	// FileID names the file SHAPE the setting lives in (FileRow.Shape).
	FileID string
	Path   KeyPath
	// Scopes are where the setting may be set; nil inherits every scope
	// of the shape's files.
	Scopes []Scope
	Type   ValueType
	// Enum holds the vendor values verbatim.
	Enum []string
	// Min / Max are documented bounds (inclusive unless the Exclusive
	// flag is set).
	Min, Max                   *float64
	ExclusiveMin, ExclusiveMax bool
	// Default is the vendor default as canonical JSON ("" when none or
	// too large to carry).
	Default string
	Desc    string
	// Source is the vendor URL or schema pointer the row was taken from.
	Source   string
	Verified Verified
	Owner    Owner
	// Writable is derived: Owner == user and the shape has a file the
	// user may write.
	Writable   bool
	Danger     DangerClass
	Secret     bool
	Deprecated bool
	// Since is the tool version the row was verified against ("" when the
	// source carries no version).
	Since string
	Note  string
}

func f64(v float64) *float64 { return &v }
