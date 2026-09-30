// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// mcpinventory_wire.go binds the store's shadow-MCP discovery inventory seam
// (store.MCPInventoryProviders; Agent Access P11 (c), R12.10 / R13.8) to the
// node's REAL MCP inventory: every locate-table client config, parsed by
// internal/guard/mcpsec - the same extraction `observer guard mcp list`
// reads. The store never opens a client config itself (it only sees the
// parsed servers and each config's path, which it hashes), and orgpush.go
// never names any of this. Read errors degrade exactly like mcpsec.Inventory:
// a missing config is normal, a malformed one is skipped - a broken cursor
// config must not hide the codex inventory.

// mcpInventoryProviders returns the inventory seam over home's client
// configs. An unresolvable home yields the zero seam (nothing composed).
func mcpInventoryProviders() store.MCPInventoryProviders {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return store.MCPInventoryProviders{}
	}
	locs := locate.Locations(home)
	return store.MCPInventoryProviders{
		Inventory: func(context.Context) ([]store.MCPInventoryEntry, error) {
			return readMCPInventory(locs, os.ReadFile), nil
		},
		Probe: func(context.Context) (string, error) {
			return statMCPConfigs(locs, os.Stat), nil
		},
	}
}

// readMCPInventory parses every location through mcpsec.ParseConfig and tags
// each server with its config path. Unreadable / malformed files are skipped
// (mcpsec.Inventory's degrade posture).
func readMCPInventory(locs []locate.Location, readFile func(string) ([]byte, error)) []store.MCPInventoryEntry {
	var out []store.MCPInventoryEntry
	for _, loc := range locs {
		raw, err := readFile(loc.Path)
		if err != nil {
			continue
		}
		servers, err := mcpsec.ParseConfig(loc, raw)
		if err != nil {
			continue
		}
		for _, s := range servers {
			out = append(out, store.MCPInventoryEntry{Server: s, ConfigPath: loc.Path})
		}
	}
	return out
}

// statMCPConfigs is the cheap change token: each config's (path, size,
// mtime) - or "absent" - hashed. A config edit moves it; an idle node re-reads
// nothing until the snapshot gate's freshness floor.
func statMCPConfigs(locs []locate.Location, stat func(string) (os.FileInfo, error)) string {
	h := sha256.New()
	for _, loc := range locs {
		fi, err := stat(loc.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			fmt.Fprintf(h, "%s\x00absent\x01", loc.Path)
		case err != nil:
			fmt.Fprintf(h, "%s\x00err\x01", loc.Path)
		default:
			fmt.Fprintf(h, "%s\x00%d\x00%d\x01", loc.Path, fi.Size(), fi.ModTime().UnixNano())
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
