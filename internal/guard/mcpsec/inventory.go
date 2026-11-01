package mcpsec

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// Server is one MCP server observed in a client's config file —
// the §9.1 inventory unit. It carries configuration SHAPE only
// (command, args, env key names), never env values or other content.
type Server struct {
	// Client is the AI client whose config declared the server
	// (locate.Location.Client vocabulary).
	Client string
	// Name is the server's registration name (the config map key).
	Name string
	// Transport is "stdio" for command servers, or the declared
	// remote type ("http", "sse") for URL servers.
	Transport string
	// Command is the launch command for stdio servers, or the URL
	// for remote servers — the §9.2 "command/URL" pin component.
	Command string
	// Args are the launch arguments (stdio servers).
	Args []string
	// EnvKeys are the SORTED env-var names the entry sets. Values
	// are deliberately dropped at parse time: they carry secrets and
	// rotate (doc.go pin-format note).
	EnvKeys []string
}

// rawServerEntry is the tolerant per-server JSON/TOML shape shared by
// every client config this package parses: Claude Code and Cursor use
// it verbatim under "mcpServers"; codex's [mcp_servers] TOML decodes
// into the same field set.
type rawServerEntry struct {
	Command   string            `json:"command" toml:"command"`
	Args      []string          `json:"args" toml:"args"`
	Env       map[string]string `json:"env" toml:"env"`
	URL       string            `json:"url" toml:"url"`
	Type      string            `json:"type" toml:"type"`
	Transport string            `json:"transport" toml:"transport"`
}

// toServer normalizes one raw entry.
func (r *rawServerEntry) toServer(client, name string) Server {
	s := Server{Client: client, Name: name, Args: r.Args}
	for k := range r.Env {
		s.EnvKeys = append(s.EnvKeys, k)
	}
	sort.Strings(s.EnvKeys)
	if r.URL != "" {
		s.Command = r.URL
		s.Transport = firstNonEmpty(r.Type, r.Transport, "http")
		return s
	}
	s.Command = r.Command
	s.Transport = firstNonEmpty(r.Type, r.Transport, "stdio")
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ParseConfig parses one client config file's MCP servers. A file
// without an MCP section yields an empty slice (not an error) — most
// installs have no MCP servers configured. Servers come back sorted
// by name for deterministic downstream hashing and output.
func ParseConfig(loc locate.Location, raw []byte) ([]Server, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	switch loc.Format {
	case locate.FormatCodexTOML:
		return parseCodexTOML(loc.Client, raw)
	default:
		return parseMCPServersJSON(loc.Client, raw)
	}
}

// parseMCPServersJSON handles the shared {"mcpServers": {...}} shape
// (Claude Code ~/.claude.json, Cursor ~/.cursor/mcp.json).
func parseMCPServersJSON(client string, raw []byte) ([]Server, error) {
	var root struct {
		MCPServers map[string]rawServerEntry `json:"mcpServers"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("mcpsec.ParseConfig %s: %w", client, err)
	}
	return collectServers(client, root.MCPServers), nil
}

// parseCodexTOML handles codex's [mcp_servers] table inside
// ~/.codex/config.toml.
func parseCodexTOML(client string, raw []byte) ([]Server, error) {
	var root struct {
		MCPServers map[string]rawServerEntry `toml:"mcp_servers"`
	}
	if err := toml.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("mcpsec.ParseConfig %s: %w", client, err)
	}
	return collectServers(client, root.MCPServers), nil
}

func collectServers(client string, entries map[string]rawServerEntry) []Server {
	if len(entries) == 0 {
		return nil
	}
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]Server, 0, len(names))
	for _, name := range names {
		e := entries[name]
		out = append(out, e.toServer(client, name))
	}
	return out
}

// Inventory parses every location's MCP config through readFile
// (injected I/O — module rule 1). Missing files are normal (client
// not installed / no MCP use) and skipped silently; unreadable or
// malformed files degrade to an issue string per file, never an
// error — a broken cursor config must not hide the codex inventory
// (the guard policy-load failure posture).
func Inventory(locations []locate.Location, readFile func(string) ([]byte, error)) ([]Server, []string) {
	if readFile == nil {
		readFile = os.ReadFile
	}
	var servers []Server
	var issues []string
	for _, loc := range locations {
		// A relocation variable with a relative value hides the client's
		// file: report it rather than skip the client silently (FU-130).
		if reason := loc.Reason(); reason != "" {
			issues = append(issues, reason)
			continue
		}
		raw, err := readFile(loc.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			continue
		case err != nil:
			issues = append(issues, fmt.Sprintf("mcp config %s (%s): %v", loc.Path, loc.Client, err))
			continue
		}
		parsed, err := ParseConfig(loc, raw)
		if err != nil {
			issues = append(issues, fmt.Sprintf("mcp config %s (%s): %v", loc.Path, loc.Client, err))
			continue
		}
		servers = append(servers, parsed...)
	}
	return servers, issues
}
