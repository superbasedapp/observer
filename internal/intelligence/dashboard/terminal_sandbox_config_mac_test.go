package dashboard

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// TestSandboxConfigPayloadCarriesTheMacBlocks (lane SBX-P5): the macOS
// drivers' blocks round-trip through the dashboard payload, and a client
// that omits them sends nil (the save keeps the stored blocks).
func TestSandboxConfigPayloadCarriesTheMacBlocks(t *testing.T) {
	c := config.Default().Terminal.Sandbox
	c.Seatbelt.AllowKeychain = true
	c.AppleContainer = config.TerminalSandboxAppleContainerConfig{Image: "ghcr.io/x/agent@sha256:" + sixtyFourHex, MemoryMiB: 8192, CPUs: 6}
	p := sandboxConfigPayload(c)
	if p.Seatbelt == nil || !p.Seatbelt.AllowKeychain || p.AppleContainer == nil || p.AppleContainer.CPUs != 6 {
		t.Fatalf("payload %+v %+v", p.Seatbelt, p.AppleContainer)
	}
	next, err := normalizedSandboxConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if next.Seatbelt != c.Seatbelt || next.AppleContainer != c.AppleContainer {
		t.Fatalf("round trip %+v %+v", next.Seatbelt, next.AppleContainer)
	}
	p.AppleContainer.Image = "ghcr.io/x/agent:latest"
	if _, err := normalizedSandboxConfig(p); err == nil {
		t.Fatal("a tag image was accepted")
	}
	p.AppleContainer = nil
	p.Seatbelt = nil
	next, err = normalizedSandboxConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if next.Seatbelt.AllowKeychain || next.AppleContainer.CPUs != 0 {
		t.Fatalf("an omitted block was not left for the save to keep: %+v %+v", next.Seatbelt, next.AppleContainer)
	}
}

const sixtyFourHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
