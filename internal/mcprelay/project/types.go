package project

import (
	"context"
	"time"
)

// RemoteEntry is one REMOTE MCP server entry to project: the shape the
// per-format remote writer emits (internal/mcp), as plain values.
type RemoteEntry struct {
	// Name is the mcpServers key (the relay-owned entry key for the
	// approved vserver, e.g. "superbased-github").
	Name string `json:"name"`
	// URL is the endpoint: the node relay's own loopback URL
	// (http://127.0.0.1:<port>/mcp/<slug>) or the org gateway's
	// https://<gw>/mcp/<slug>.
	URL string `json:"url"`
	// Transport is "http" (default) or "sse".
	Transport string `json:"transport,omitempty"`
	// Headers are static headers the client sends. Credentials are NEVER
	// projected (the access token is memory-only, §11.7 W4b): a header
	// named authorization (any case) is refused by Plan.
	Headers map[string]string `json:"headers,omitempty"`
}

// WrapSpec is how an existing stdio entry is rewritten to the relay's TRUE
// stdio wrapper (doc3 §12.1 "concrete stdio-wrapper config transformation",
// §12.2): `{command: <observer binary>, args: ["mcp-relay","wrap",
// "--client",<tool>,"--server",<entry key>(,"--config",<path>)]}`. The
// original command/args/cwd/env-KEYS are journaled first so disable puts
// them back. Every other field of the entry (env VALUES, disabled, type,
// timeouts) is preserved verbatim by the writer: the client keeps handing
// the same environment to the wrapper, which hands it to the original.
type WrapSpec struct {
	// Command is the absolute path of the observer binary the client spawns.
	Command string `json:"command"`
	// ConfigPath, when set, is appended as `--config <path>` so the wrapper
	// reads the same config the daemon that projected it did.
	ConfigPath string `json:"config_path,omitempty"`
	// Bind resolves one stdio entry key to its approved registry binding
	// (Sol P3+P4 fold finding 2). The Projector ALWAYS installs it from
	// Desired.Approved before it stages (a caller's value is overwritten);
	// a writer consults it through BindingFor and wraps ONLY an entry that
	// binds, carrying the binding on the StdioEntry it stages. refusal is
	// one of the Refuse* reasons ("" = bound). nil (a bare writer-primitive
	// call outside the projector, e.g. a writer unit test) admits every
	// entry with no binding - such a stage is refused by the projector.
	Bind func(key string) (b Binding, refusal string) `json:"-"`
}

// BindingFor is the writer-side consultation of Bind: ok=false means the
// entry must NOT be wrapped (no approved binding - it stays direct and the
// projector reports the refusal). A nil Bind admits with a zero binding.
func (w WrapSpec) BindingFor(key string) (Binding, bool) {
	if w.Bind == nil {
		return Binding{}, true
	}
	b, refusal := w.Bind(key)
	return b, refusal == ""
}

// Wrap-args vocabulary (the wrapper subcommand the args name).
const (
	// WrapCommandWord is the observer subcommand ("mcp-relay").
	WrapCommandWord = "mcp-relay"
	// WrapVerb is its verb ("wrap").
	WrapVerb = "wrap"
)

// WrapArgs renders the wrapper argument vector for one (tool, entry key).
func WrapArgs(tool, key string, w WrapSpec) []string {
	args := []string{WrapCommandWord, WrapVerb, "--client", tool, "--server", key}
	if w.ConfigPath != "" {
		args = append(args, "--config", w.ConfigPath)
	}
	return args
}

// IsWrapper reports whether an entry already spawns the relay's wrapper
// (idempotence: such an entry is never wrapped twice).
func IsWrapper(command string, args []string, w WrapSpec) bool {
	return command == w.Command && len(args) >= 2 && args[0] == WrapCommandWord && args[1] == WrapVerb
}

// IsObserver reports whether an entry's command IS the observer binary
// (observer's own MCP server, `observer serve`, or any other observer
// subcommand): never wrapped - the relay would be mediating itself.
func IsObserver(command string, w WrapSpec) bool {
	if command == "" {
		return false
	}
	if command == w.Command {
		return true
	}
	base := command
	for i := len(command) - 1; i >= 0; i-- {
		if command[i] == '/' || command[i] == '\\' {
			base = command[i+1:]
			break
		}
	}
	return base == "observer" || base == "observer.exe"
}

// ApprovedServer is one member of the accepted tools.mcp_access registry as
// a stdio entry can bind to it: the compiled node table's vserver ID (what
// localpdp.Table.NodePrincipal and the local PDP key on), that vserver's
// slug, and one registry member (ServerID + Target; both "" for a vserver
// that lists no member). Plain values: the composition root flattens the
// table's registry into these rows so this package never imports it.
type ApprovedServer struct {
	VServer     string `json:"vserver"`
	VServerSlug string `json:"vserver_slug,omitempty"`
	ServerID    string `json:"server_id,omitempty"`
	Target      string `json:"target,omitempty"`
}

// Binding is the approved (vserver, registry server) pair a wrapped stdio
// entry is bound to at PROJECTION time and journaled with its row: the
// wrapper hands it to the local PDP as the call's target (VServer =
// Target.VServer, ServerID = Target.ServerID / Request.Server).
type Binding struct {
	VServer  string `json:"vserver"`
	ServerID string `json:"server_id,omitempty"`
}

// Binding refusals: the typed reasons an entry is NOT wrapped. Never a
// guess - an entry that does not bind to exactly one approved vserver (and
// one member of it) stays direct and is reported.
const (
	// RefuseNoApprovedServers: no accepted tools.mcp_access table on this
	// node, or the table names no vserver - nothing an entry could bind to.
	RefuseNoApprovedServers = "no_approved_servers"
	// RefuseNoBinding: the entry key names no approved vserver (by id or
	// slug) and no approved member (by server id or target).
	RefuseNoBinding = "no_approved_binding"
	// RefuseAmbiguousVServer: the key matches members / vservers of MORE
	// than one approved vserver.
	RefuseAmbiguousVServer = "ambiguous_vserver"
	// RefuseAmbiguousServer: the key matches one vserver but cannot name
	// exactly one of its members (a vserver-level match on a vserver that
	// aggregates several servers, or two members' id/target).
	RefuseAmbiguousServer = "ambiguous_server"
)

// bindMatcher is one ordered row of the binding vocabulary: the SAME names
// the hook / proxy seam resolves an `mcp__<key>__` tool name with (vserver
// id, vserver slug, member server id, member target), so a key the wrapper
// binds is the key the pre-execution points resolve to the same vserver.
// member reports the row names a specific registry member.
type bindMatcher struct {
	name   string
	member bool
	match  func(a ApprovedServer, key string) bool
}

var bindMatchers = []bindMatcher{
	{name: "vserver_id", match: func(a ApprovedServer, key string) bool { return a.VServer == key }},
	{name: "vserver_slug", match: func(a ApprovedServer, key string) bool { return a.VServerSlug != "" && a.VServerSlug == key }},
	{name: "server_id", member: true, match: func(a ApprovedServer, key string) bool { return a.ServerID != "" && a.ServerID == key }},
	{name: "server_target", member: true, match: func(a ApprovedServer, key string) bool { return a.Target != "" && a.Target == key }},
}

// Bind resolves one client config entry key against the approved registry.
// Every matcher row contributes candidates; the UNION must name exactly one
// vserver, and exactly one member of it (a member named by the key, else
// the vserver's only member, else - for a vserver with no member - none),
// or the entry is refused with the typed reason. Pure.
func Bind(approved []ApprovedServer, key string) (Binding, string) {
	if len(approved) == 0 {
		return Binding{}, RefuseNoApprovedServers
	}
	if key == "" {
		return Binding{}, RefuseNoBinding
	}
	vservers := map[string]bool{}
	named := map[string]bool{}
	for _, a := range approved {
		for _, m := range bindMatchers {
			if !m.match(a, key) {
				continue
			}
			vservers[a.VServer] = true
			if m.member {
				named[a.ServerID] = true
			}
		}
	}
	switch len(vservers) {
	case 0:
		return Binding{}, RefuseNoBinding
	case 1:
	default:
		return Binding{}, RefuseAmbiguousVServer
	}
	var vs string
	for v := range vservers {
		vs = v
	}
	if len(named) > 1 {
		return Binding{}, RefuseAmbiguousServer
	}
	for id := range named {
		return Binding{VServer: vs, ServerID: id}, ""
	}
	// A vserver-level match (id / slug): bind to its only member.
	members := map[string]bool{}
	for _, a := range approved {
		if a.VServer == vs && a.ServerID != "" {
			members[a.ServerID] = true
		}
	}
	switch len(members) {
	case 0:
		return Binding{VServer: vs}, ""
	case 1:
		for id := range members {
			return Binding{VServer: vs, ServerID: id}, ""
		}
	}
	return Binding{}, RefuseAmbiguousServer
}

// Desired is what one client's config should hold after projection.
type Desired struct {
	// Wrap, when non-nil, rewrites every existing stdio entry that BINDS to
	// an Approved server to the wrapper; an entry that does not bind is
	// left direct and reported (Receipt.Refused).
	Wrap *WrapSpec
	// Approved is the accepted tools.mcp_access registry flattened (nil =
	// no table: every stdio entry is refused RefuseNoApprovedServers).
	Approved []ApprovedServer
	// Remote are the relay-owned remote entries to upsert (approved
	// vservers through the relay's loopback listener).
	Remote []RemoteEntry
}

// Client is one AI client whose config may receive the projection.
type Client struct {
	// Tool is the integration registry tool id; ConfigPath the config file
	// the writer edits; Format the integration.MCPFormat name (a plain
	// string here so the package need not import internal/integration; the
	// writer resolves it from Tool when empty, as on a restore).
	Tool       string `json:"tool"`
	ConfigPath string `json:"config_path"`
	Format     string `json:"format"`
	// Verified reports the client is installed on this node AND the
	// per-format writer exists (internal/mcp can wrap its stdio entries).
	// An unverified client is never written.
	Verified bool `json:"verified"`
}

// StdioEntry is one ORIGINAL stdio entry a stage replaces with the wrapper.
// EnvKeys carries env KEY NAMES only - never a value (R8.18 "env as SECRET
// REFERENCES only").
type StdioEntry struct {
	Key     string
	Command string
	Args    []string
	Cwd     string
	EnvKeys []string
	// VServer / ServerID are the approved binding the writer staged the
	// wrap under (WrapSpec.BindingFor); the projector journals them.
	VServer  string
	ServerID string
}

// Staged is a writer's prepared edit: what the file holds now and what it
// would hold after. Changed=false means the desired state is already
// present (idempotent re-apply: nothing is journaled or written).
type Staged struct {
	Changed bool
	// Before is the file's current bytes verbatim (nil = absent).
	Before []byte
	After  []byte
	// Wrapped are the original stdio entries this stage replaces.
	Wrapped []StdioEntry
	// RemoteKeys are the relay-owned remote entry keys this stage adds or
	// changes.
	RemoteKeys []string
}

// Writer is the per-format writer seam (internal/mcp's Registrar). Stage
// never touches the file; Commit writes the staged bytes atomically and
// MUST refuse with ErrConfigChanged when the file no longer holds exactly
// Staged.Before; Revert is the format-aware reversal of ONLY the
// relay-owned entries named by rows (a wrapped stdio entry gets its
// journaled original back, a relay remote entry is deleted, everything
// else is preserved) under the writer's own read-compare-write CAS.
type Writer interface {
	Stage(ctx context.Context, client Client, desired Desired) (Staged, error)
	Commit(ctx context.Context, client Client, staged Staged) error
	Revert(ctx context.Context, client Client, rows []JournalRow) error
}

// RowKind classifies a journal row.
type RowKind string

// Row kinds.
const (
	// RowStdioWrap: an existing stdio entry was replaced by the wrapper; the
	// row carries the original launch.
	RowStdioWrap RowKind = "stdio_wrap"
	// RowRemote: the relay ADDED a remote entry; there is no original launch
	// (OrigCommand is RemoteOrigCommand) and restore deletes the entry.
	RowRemote RowKind = "remote"
)

// RemoteOrigCommand is the orig_command sentinel of a RowRemote row: the
// journal table requires a command, and a relay-added remote entry has none.
const RemoteOrigCommand = "<remote>"

// JournalRow is one mcp_relay_launch_spec row as the projector sees it.
type JournalRow struct {
	Tool        string
	ConfigPath  string
	EntryKey    string
	OrigCommand string
	OrigArgs    []string
	OrigCwd     string
	OrigEnvRefs []string
	// ConfigGeneration is the CAS target (1 on the first write of this
	// entry; bumped by every re-write).
	ConfigGeneration int64
	// BackupPath / BackupSHA256 name the verbatim pre-relay backup the row's
	// FIRST write took (a re-write keeps it: the backup is the pre-relay
	// original).
	BackupPath   string
	BackupSHA256 string
	// AppliedSHA256 is the digest of the bytes the write that produced this
	// row put on disk ("" = a pre-migration-132 row). A later write event on
	// the same config that built on exactly those bytes refreshes it (the
	// entry is still in the file it wrote).
	AppliedSHA256 string
	AppliedAt     time.Time
	// VServer / RegistryServerID are the approved binding a RowStdioWrap
	// row was projected under (node migration 133; "" = a remote row or a
	// pre-133 row, which the wrapper refuses to launch - never a guess).
	VServer          string
	RegistryServerID string
}

// Kind resolves the row's kind from the sentinel.
func (r JournalRow) Kind() RowKind {
	if r.OrigCommand == RemoteOrigCommand {
		return RowRemote
	}
	return RowStdioWrap
}

// Journal is the durable launch-journal seam (Lane N-M's
// mcp_relay_launch_spec store + the backup FILE half in internal/mcprelay/
// journal.go). Put must be durable before it returns; a failure aborts the
// write (restore-on-disable is only possible for a write whose original was
// journaled). Backup writes the verbatim original to an owner-only file and
// fsyncs it (doc3 §12.1 step 1); RestoreWhole rewrites the config byte-
// identically from that file and MUST refuse with ErrConfigChanged when the
// config's current bytes differ from row.AppliedSHA256 (Sol P3+P4 finding
// 7) and with ErrNoAppliedDigest when the row carries none.
type Journal interface {
	List(ctx context.Context) ([]JournalRow, error)
	Put(ctx context.Context, row JournalRow, expectedGeneration int64) error
	Delete(ctx context.Context, tool, configPath, entryKey string) error
	Backup(ctx context.Context, client Client, original []byte) (backupPath, sha256Hex string, err error)
	RestoreWhole(ctx context.Context, client Client, row JournalRow) error
}

// Op is one planned action for one client.
type Op struct {
	Client Client
	// Skip is the table-driven reason the client is not written ("" =
	// project).
	Skip string
}

// EntryRefusal is one stdio entry the projection did NOT wrap, with the
// typed Refuse* reason.
type EntryRefusal struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// Receipt reports what Apply did for one client.
type Receipt struct {
	Client  Client
	Skipped string
	Changed bool
	// Wrapped lists the stdio entry keys replaced by the wrapper.
	Wrapped []string
	// Refused lists the stdio entries left direct because they bind to no
	// approved server (sorted by key).
	Refused []EntryRefusal
	// Remote lists the relay-owned remote entry keys added or changed.
	Remote []string
	// BackupPath is the verbatim pre-write backup this apply took ("" when
	// every row already had one).
	BackupPath string
	// AppliedSHA256 is the digest of the bytes written.
	AppliedSHA256 string
	// Note is a non-fatal remark (a post-commit applied-digest refresh that
	// failed: those rows under-claim until the next write event).
	Note string
	Err  string
}

// Report is Apply's outcome.
type Report struct {
	Fingerprint string
	Receipts    []Receipt
}

// Restore modes.
const (
	// RestoreWholeFile: the config was rewritten byte-identically from the
	// pre-relay backup (single write event, config untouched since).
	RestoreWholeFile = "whole_file"
	// RestoreReversal: only the relay-owned entries were reversed in place
	// (config edited since the write, several write events, or a pre-132
	// row); everything else in the file was preserved.
	RestoreReversal = "reversal"
)

// RestoreReceipt reports what Restore did for one (client, config).
type RestoreReceipt struct {
	Client Client
	// Rows is the number of journal rows the group held.
	Rows int
	// Mode is RestoreWholeFile or RestoreReversal ("" when nothing ran).
	Mode string
	// Rule names the restore-rule row that decided the mode.
	Rule string
	// Note explains a fallback (a refused whole-file restore).
	Note     string
	Restored bool
	Err      string
}
