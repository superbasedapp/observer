//go:build !sbo_omit_agentaccess_relay

package mcpregister

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/project"
)

// The Agent Access relay writer's per-format edits (T-397). Every client MCP
// config the relay projects into can hold credentials (another server's env
// block or headers carry literal tokens), so the D-268 / D-270 rules apply:
//
//   - the edit goes through the comment- and order-preserving cfgfmt engine
//     with re-serialization forbidden: a wrap sets only the entry's launch
//     members (command / args), a remote upsert sets only the relay-owned
//     entry, a reversal puts back only those; every other byte of the file
//     (sibling servers, env values, comments, key order) stays, and an edit
//     cfgfmt could only make by re-serializing (an inline table) is refused;
//   - no copy of the file is taken and nothing derived from the whole file
//     leaves the process: the journal gets only the OWNED digest of each
//     relay-owned entry (project.OwnedStdioDigest / OwnedRemoteDigest);
//   - the file's mode is kept and the write is atomic (writeFileSync);
//   - no error carries a value read from the file (relayWriterError).

// formatWriter is one row of wrapWriters: how one config format spells the
// server object and a stdio launch.
type formatWriter struct {
	format cfgfmt.Format
	// topKey is the server object's key ("mcpServers", "mcp", "mcp_servers").
	topKey string
	// read extracts a stdio launch from a (cfgfmt-normalized) entry; ok=false
	// for a remote or unrepresentable entry.
	read func(e map[string]any) (cmd string, args []string, cwd string, envKeys []string, ok bool)
	// launch returns the entry members that carry a launch; a nil value
	// means "delete the member".
	launch func(cmd string, args []string) map[string]any
	// remote renders the relay remote entry for this format.
	remote func(entry project.RemoteEntry, remote *integration.MCPRemoteTarget) map[string]any
}

// wrapWriters is the per-format writer table: the ONE place that says which
// config formats the relay can wrap TODAY (the coverage matrix's "writer
// exists" input, doc3 §12.7). A format absent here is honestly unwrappable
// (hermes' YAML: its stdio writer lives in internal/hook and there is no
// locate row).
var wrapWriters = map[locate.Format]formatWriter{
	locate.FormatMCPServersJSON: {format: cfgfmt.FormatJSON, topKey: "mcpServers", read: stdioLaunchOf, launch: sharedLaunch, remote: jsonRemoteEntry},
	locate.FormatOpenCodeJSON:   {format: cfgfmt.FormatJSON, topKey: "mcp", read: opencodeLaunchOf, launch: opencodeLaunch, remote: opencodeRemoteEntry},
	locate.FormatCodexTOML: {format: cfgfmt.FormatTOML, topKey: "mcp_servers", read: stdioLaunchOf, launch: codexLaunch, remote: func(e project.RemoteEntry, _ *integration.MCPRemoteTarget) map[string]any {
		return codexRemoteEntry(e)
	}},
}

// wrapFormats maps the integration registry's format vocabulary onto the
// locate table's (the two grew separately; this is the bridge the
// capability-shape question is answered through).
var wrapFormats = map[integration.MCPFormat]locate.Format{
	integration.MCPServersJSON:  locate.FormatMCPServersJSON,
	integration.MCPCodexTOML:    locate.FormatCodexTOML,
	integration.MCPOpenCodeJSON: locate.FormatOpenCodeJSON,
}

// WrapWriterImplemented reports whether a stdio-wrap writer exists for a
// registry MCP format - what the coverage matrix's
// ClientShape.RegistryWriterImplemented means.
func WrapWriterImplemented(f integration.MCPFormat) bool {
	lf, ok := wrapFormats[f]
	if !ok {
		return false
	}
	_, ok = wrapWriters[lf]
	return ok
}

// stageResult is a format writer's staged transformation.
type stageResult struct {
	after      []byte
	wrapped    []project.StdioEntry
	remoteKeys []string
	owned      map[string]string
}

// stdioLaunchOf reads the {"command":..,"args":[..],"cwd":..,"env":{..}}
// launch shared by the mcpServers JSON clients and Codex's TOML tables.
func stdioLaunchOf(e map[string]any) (cmd string, args []string, cwd string, envKeys []string, ok bool) {
	if _, remote := e["url"]; remote {
		return "", nil, "", nil, false
	}
	cmd, _ = e["command"].(string)
	if cmd == "" {
		return "", nil, "", nil, false
	}
	switch v := e["args"].(type) {
	case nil:
	case []any:
		for _, a := range v {
			s, isStr := a.(string)
			if !isStr {
				return "", nil, "", nil, false
			}
			args = append(args, s)
		}
	default:
		return "", nil, "", nil, false
	}
	cwd, _ = e["cwd"].(string)
	if env, isMap := e["env"].(map[string]any); isMap {
		envKeys = sortedMapKeys(env)
	}
	return cmd, args, cwd, envKeys, true
}

// opencodeLaunchOf reads OpenCode's {"type":"local","command":[bin,
// args...],"environment":{..}} launch.
func opencodeLaunchOf(e map[string]any) (cmd string, args []string, cwd string, envKeys []string, ok bool) {
	if typ, _ := e["type"].(string); typ != "" && typ != "local" {
		return "", nil, "", nil, false
	}
	command, isList := e["command"].([]any)
	if !isList || len(command) == 0 {
		return "", nil, "", nil, false
	}
	parts := make([]string, 0, len(command))
	for _, a := range command {
		s, isStr := a.(string)
		if !isStr {
			return "", nil, "", nil, false
		}
		parts = append(parts, s)
	}
	if parts[0] == "" {
		return "", nil, "", nil, false
	}
	if env, isMap := e["environment"].(map[string]any); isMap {
		envKeys = sortedMapKeys(env)
	}
	return parts[0], parts[1:], "", envKeys, true
}

func stringsToAny(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// sharedLaunch spells a launch as command + args (args always present).
func sharedLaunch(cmd string, args []string) map[string]any {
	return map[string]any{"command": cmd, "args": stringsToAny(args)}
}

// codexLaunch spells a launch as command + args; a launch with no args
// drops the args key (how the original table read).
func codexLaunch(cmd string, args []string) map[string]any {
	if args == nil {
		return map[string]any{"command": cmd, "args": nil}
	}
	return map[string]any{"command": cmd, "args": stringsToAny(args)}
}

// opencodeLaunch spells a launch as one command array.
func opencodeLaunch(cmd string, args []string) map[string]any {
	return map[string]any{"command": stringsToAny(append([]string{cmd}, args...))}
}

func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// parse parses raw for an edit (re-serialization forbidden). An absent or
// empty JSON config starts as an empty object.
func (f formatWriter) parse(raw []byte) (cfgfmt.Doc, error) {
	body := raw
	if f.format == cfgfmt.FormatJSON && len(bytes.TrimSpace(raw)) == 0 {
		body = []byte("{}\n")
	}
	return cfgfmt.ParseWith(f.format, body, cfgfmt.Options{ForbidReserialize: true})
}

// servers returns the server object (empty when absent or null).
func (f formatWriter) servers(doc cfgfmt.Doc) (map[string]any, error) {
	v, found, err := doc.Get(cfgfmt.Path{f.topKey})
	if err != nil {
		return nil, err
	}
	if !found || v == nil {
		return map[string]any{}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: %w", f.topKey, cfgfmt.ErrTypeMismatch)
	}
	return m, nil
}

// setMembers sets (or, for a nil value, deletes) each member of the entry at
// base, in sorted order.
func setMembers(doc cfgfmt.Doc, base cfgfmt.Path, members map[string]any) error {
	for _, k := range sortedMapKeys(members) {
		path := append(append(cfgfmt.Path(nil), base...), k)
		v := members[k]
		if v == nil {
			if _, err := doc.Delete(path); err != nil {
				return err
			}
			continue
		}
		if err := doc.Set(path, v); err != nil {
			return err
		}
	}
	return nil
}

// ownedKind decides which entries of a config are relay-owned and how their
// digest is taken (ok=false: not relay-owned).
type ownedKind func(key string, e map[string]any) (project.RowKind, bool)

// owned computes the owned digest of every relay-owned entry in raw.
func (f formatWriter) owned(raw []byte, kindOf ownedKind) (map[string]string, error) {
	doc, err := f.parse(raw)
	if err != nil {
		return nil, err
	}
	servers, err := f.servers(doc)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for key, v := range servers {
		e, ok := v.(map[string]any)
		if !ok {
			continue
		}
		kind, ok := kindOf(key, e)
		if !ok {
			continue
		}
		if kind == project.RowRemote {
			if d := project.OwnedRemoteDigest(key, e); d != "" {
				out[key] = d
			}
			continue
		}
		if cmd, args, _, _, ok := f.read(e); ok {
			out[key] = project.OwnedStdioDigest(key, cmd, args)
		}
	}
	return out, nil
}

// stage builds the surgical edit: every bound stdio entry gets the wrapper
// launch, every relay remote entry is upserted; nothing else changes.
func (f formatWriter) stage(raw []byte, c project.Client, d project.Desired, remote *integration.MCPRemoteTarget) (stageResult, error) {
	doc, err := f.parse(raw)
	if err != nil {
		return stageResult{}, err
	}
	servers, err := f.servers(doc)
	if err != nil {
		return stageResult{}, err
	}
	var res stageResult
	if d.Wrap != nil {
		for _, key := range sortedMapKeys(servers) {
			e, ok := servers[key].(map[string]any)
			if !ok {
				continue
			}
			cmd, args, cwd, envKeys, ok := f.read(e)
			if !ok || project.IsObserver(cmd, *d.Wrap) || project.IsWrapper(cmd, args, *d.Wrap) {
				continue
			}
			// Only an entry bound to an approved (vserver, server) is
			// wrapped; the binding rides the staged entry (Sol P3+P4 fold
			// finding 2).
			b, bound := d.Wrap.BindingFor(key)
			if !bound {
				continue
			}
			res.wrapped = append(res.wrapped, project.StdioEntry{Key: key, Command: cmd, Args: args, Cwd: cwd, EnvKeys: envKeys, VServer: b.VServer, ServerID: b.ServerID})
			if err := setMembers(doc, cfgfmt.Path{f.topKey, key}, f.launch(d.Wrap.Command, project.WrapArgs(c.Tool, key, *d.Wrap))); err != nil {
				return stageResult{}, err
			}
		}
	}
	remoteNames := map[string]bool{}
	if remote != nil {
		for _, entry := range d.Remote {
			remoteNames[entry.Name] = true
			desired, err := cfgfmt.Normalize(f.remote(entry, remote))
			if err != nil {
				return stageResult{}, err
			}
			if cur, ok := servers[entry.Name]; ok && cfgfmt.Equal(cur, desired) {
				continue
			}
			if err := doc.Set(cfgfmt.Path{f.topKey, entry.Name}, desired); err != nil {
				return stageResult{}, err
			}
			res.remoteKeys = append(res.remoteKeys, entry.Name)
		}
	}
	res.after = raw
	if len(res.wrapped) > 0 || len(res.remoteKeys) > 0 {
		res.after = doc.Bytes()
	}
	res.owned, err = f.owned(res.after, func(key string, e map[string]any) (project.RowKind, bool) {
		if remoteNames[key] {
			return project.RowRemote, true
		}
		if cmd, args, _, _, ok := f.read(e); ok && project.IsWrapper(cmd, args, project.WrapSpec{Command: cmd}) {
			return project.RowStdioWrap, true
		}
		return "", false
	})
	return res, err
}

// revert puts back only the relay-owned entries named by rows. empty reports
// the result holds nothing at all (the caller then removes the file).
func (f formatWriter) revert(raw []byte, rows []project.JournalRow) (after []byte, changed, empty bool, err error) {
	doc, err := f.parse(raw)
	if err != nil {
		return nil, false, false, err
	}
	servers, err := f.servers(doc)
	if err != nil {
		return nil, false, false, err
	}
	for _, row := range rows {
		cur, ok := servers[row.EntryKey]
		if !ok {
			continue
		}
		switch row.Kind() {
		case project.RowRemote:
			if _, err := doc.Delete(cfgfmt.Path{f.topKey, row.EntryKey}); err != nil {
				return nil, false, false, err
			}
			changed = true
		case project.RowStdioWrap:
			e, ok := cur.(map[string]any)
			if !ok {
				continue
			}
			cmd, args, _, _, ok := f.read(e)
			if !ok || !project.IsWrapper(cmd, args, project.WrapSpec{Command: cmd}) {
				continue // already put back by hand: leave it
			}
			if err := setMembers(doc, cfgfmt.Path{f.topKey, row.EntryKey}, f.launch(row.OrigCommand, row.OrigArgs)); err != nil {
				return nil, false, false, err
			}
			changed = true
		}
	}
	if !changed {
		return raw, false, false, nil
	}
	if rest, err := f.servers(doc); err == nil && len(rest) == 0 {
		if _, err := doc.Delete(cfgfmt.Path{f.topKey}); err != nil {
			return nil, false, false, err
		}
	}
	val, err := doc.Value()
	if err != nil {
		return nil, false, false, err
	}
	return doc.Bytes(), true, len(val) == 0, nil
}

// relayWriterError makes a writer error safe to surface: a message composed
// from paths and key names passes, an edit cfgfmt could only make by
// re-serializing names the shape, and anything else (a decoder message
// quotes the file) is withheld.
func relayWriterError(c project.Client, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, cfgfmt.ErrNeedsReserialize) || errors.Is(err, cfgfmt.ErrUnsupported) || errors.Is(err, cfgfmt.ErrTypeMismatch) {
		return credfile.SafeErrorf("mcp.relay-writer %s: %s holds an MCP server entry in a form Observer cannot edit in place (an inline table, or a value of another type); nothing was written", c.Tool, c.ConfigPath)
	}
	return credfile.Withhold("mcp.relay-writer "+c.Tool, c.ConfigPath, err)
}

// readConfig returns the file's verbatim bytes (nil, false when absent).
func readConfig(path string) ([]byte, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return raw, true, nil
}

// keepMode returns path's permission bits (0600 for a new file).
func keepMode(path string) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return 0o600
}

// Stage implements project.Writer: the staged transformation of c's config
// for the desired state, never touching the file. Changed is true only
// when an entry was wrapped or a relay remote entry added / changed - a
// hand-formatted file with nothing to do stays untouched on every re-apply
// (idempotence), and observer's own server / an entry already spawning the
// wrapper are never wrapped (project.IsObserver / project.IsWrapper).
// Staged.Owned carries the owned digest of every relay-owned entry.
func (r *Registrar) Stage(_ context.Context, c project.Client, d project.Desired) (project.Staged, error) {
	c, w, err := r.resolveClient(c)
	if err != nil {
		return project.Staged{}, err
	}
	raw, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return project.Staged{}, relayWriterError(c, fmt.Errorf("read: %w", err))
	}
	var remote *integration.MCPRemoteTarget
	if len(d.Remote) > 0 {
		// A client whose registry row grounds no implemented remote target
		// gets no remote entry (the matrix already labels it): the stdio
		// wrap still applies.
		if rt, rerr := remoteTargetFor(c.Tool); rerr == nil {
			remote = rt
			for _, e := range d.Remote {
				if verr := validateRemoteEntry(c.Tool, e, remote); verr != nil {
					return project.Staged{}, verr
				}
			}
		}
	}
	res, err := w.stage(raw, c, d, remote)
	if err != nil {
		return project.Staged{}, relayWriterError(c, err)
	}
	st := project.Staged{After: res.after, Wrapped: res.wrapped, RemoteKeys: res.remoteKeys, Owned: res.owned}
	if exists {
		st.Before = raw
	}
	st.Changed = len(res.wrapped) > 0 || len(res.remoteKeys) > 0
	return st, nil
}

// Commit implements project.Writer: the atomic, durable rewrite of the
// staged bytes (temp + fsync + rename + dir fsync), refused with
// project.ErrConfigChanged when the file no longer holds exactly
// Staged.Before (the CAS runs in this process; nothing about the file is
// stored). The existing file mode is kept; a new file is 0600. No backup
// is taken.
func (r *Registrar) Commit(_ context.Context, c project.Client, st project.Staged) error {
	c, _, err := r.resolveClient(c)
	if err != nil {
		return err
	}
	cur, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return relayWriterError(c, fmt.Errorf("read: %w", err))
	}
	if exists != (st.Before != nil) || !bytes.Equal(cur, st.Before) {
		return fmt.Errorf("%w: %s", project.ErrConfigChanged, c.ConfigPath)
	}
	if err := writeFileSync(c.ConfigPath, st.After, keepMode(c.ConfigPath), 0o755); err != nil {
		return relayWriterError(c, fmt.Errorf("write: %w", err))
	}
	return nil
}

// Revert implements project.Writer: the format-aware reversal of ONLY the
// relay-owned entries named by rows - a wrapped stdio entry gets its
// journaled original command/args back (every other member of the entry,
// and every sibling, keeps its bytes), a relay remote entry is deleted -
// under a read-compare-write CAS (the file is re-read before the write and
// must still hold the bytes the reversal was computed from, else
// project.ErrConfigChanged). An entry that is no longer the wrapper (the
// operator already put it back) is left alone. An empty server object is
// dropped, and a config left with nothing in it at all (the relay created
// it) is removed.
func (r *Registrar) Revert(_ context.Context, c project.Client, rows []project.JournalRow) error {
	c, w, err := r.resolveClient(c)
	if err != nil {
		return err
	}
	raw, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return relayWriterError(c, fmt.Errorf("read: %w", err))
	}
	if !exists {
		return nil
	}
	after, changed, empty, err := w.revert(raw, rows)
	if err != nil {
		return relayWriterError(c, err)
	}
	if !changed {
		return nil
	}
	again, _, err := readConfig(c.ConfigPath)
	if err != nil {
		return relayWriterError(c, fmt.Errorf("re-read: %w", err))
	}
	if !bytes.Equal(again, raw) {
		return fmt.Errorf("%w: %s", project.ErrConfigChanged, c.ConfigPath)
	}
	if empty {
		if err := removeConfigFile(c.ConfigPath, again); err != nil && !errors.Is(err, os.ErrNotExist) {
			return relayWriterError(c, fmt.Errorf("remove: %w", err))
		}
		return nil
	}
	if err := writeFileSync(c.ConfigPath, after, keepMode(c.ConfigPath), 0o755); err != nil {
		return relayWriterError(c, fmt.Errorf("write: %w", err))
	}
	return nil
}

// Owned implements project.Writer: the CURRENT owned digest of each row's
// entry (VerifyApplied's input). An entry that is absent, or a stdio entry
// that no longer reads as a launch, is missing from the map. Only the
// owned part of each entry is hashed, in this process.
func (r *Registrar) Owned(_ context.Context, c project.Client, rows []project.JournalRow) (map[string]string, error) {
	c, w, err := r.resolveClient(c)
	if err != nil {
		return nil, err
	}
	raw, exists, err := readConfig(c.ConfigPath)
	if err != nil {
		return nil, relayWriterError(c, fmt.Errorf("read: %w", err))
	}
	if !exists {
		return nil, credfile.SafeErrorf("mcp.relay-writer %s: %s is absent", c.Tool, c.ConfigPath)
	}
	kinds := make(map[string]project.RowKind, len(rows))
	for _, row := range rows {
		kinds[row.EntryKey] = row.Kind()
	}
	out, err := w.owned(raw, func(key string, _ map[string]any) (project.RowKind, bool) {
		k, ok := kinds[key]
		return k, ok
	})
	if err != nil {
		return nil, relayWriterError(c, err)
	}
	return out, nil
}
