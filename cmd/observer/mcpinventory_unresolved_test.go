package main

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// TestMCPInventorySkipsAnUnresolvedLocationByName pins FU-130 for the
// shadow-MCP inventory seam: a location whose relocation variable holds a
// relative value is never read as "" and adds no server, and the change
// token records the state, so setting or fixing the variable moves it.
func TestMCPInventorySkipsAnUnresolvedLocationByName(t *testing.T) {
	unresolved := []locate.Location{{Client: "cline", Format: locate.FormatMCPServersJSON, Unresolved: "CLINE_DIR"}}
	read := func(p string) ([]byte, error) {
		t.Errorf("readFile(%q) called for an unresolved location", p)
		return nil, os.ErrNotExist
	}
	if got := readMCPInventory(unresolved, read); len(got) != 0 {
		t.Errorf("entries %+v for an unresolved location", got)
	}
	stat := func(p string) (os.FileInfo, error) {
		if p == "" {
			t.Error("stat(\"\") for an unresolved location")
		}
		return nil, os.ErrNotExist
	}
	absent := []locate.Location{{Client: "cline", Path: "/nowhere/cline_mcp_settings.json", Format: locate.FormatMCPServersJSON}}
	if statMCPConfigs(unresolved, stat) == statMCPConfigs(absent, stat) {
		t.Error("the change token does not tell an unresolved location from an absent file")
	}
	other := []locate.Location{{Client: "cline", Format: locate.FormatMCPServersJSON, Unresolved: "CLINE_DATA_DIR"}}
	if statMCPConfigs(unresolved, stat) == statMCPConfigs(other, stat) {
		t.Error("the change token does not name the variable")
	}
}
