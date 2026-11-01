package sandbox

import (
	"strings"
	"testing"
)

// TestHostArgvCarriesTheProviderBlock: the block and its extra hosts ride
// on the host helper's command line only for a tier with a gateway, and
// parse back exactly.
func TestHostArgvCarriesTheProviderBlock(t *testing.T) {
	n := NetRequest{Egress: EgressInternet, HostSocketDir: "/tmp/observer-sbx-1", ProxyPort: 8820, ProviderBlock: true, ProviderHosts: []string{"llm.corp.example"}}
	argv, err := HostArgv("/usr/bin/observer", n)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--gateway --provider-block --provider-host llm.corp.example --") {
		t.Fatalf("argv = %s", joined)
	}
	h, err := ParseHostArgs(append(argv[2:], "/usr/bin/bwrap"))
	if err != nil {
		t.Fatal(err)
	}
	if !h.ProviderBlock || len(h.ProviderHosts) != 1 || h.ProviderHosts[0] != "llm.corp.example" {
		t.Fatalf("parsed %+v", h)
	}
	// proxy_only has no gateway: the block is not emitted.
	n.Egress = EgressProxyOnly
	argv, err = HostArgv("/usr/bin/observer", n)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(argv, " "), "--provider") {
		t.Fatalf("a gateway-less tier carries the block: %v", argv)
	}
}

func TestParseHostArgsRefusesAStrayProviderBlock(t *testing.T) {
	for _, args := range [][]string{
		{"--provider-block", "--", "/usr/bin/bwrap"},
		{"--sock-dir", "/tmp/x", "--gateway", "--provider-host", "a.example", "--", "/usr/bin/bwrap"},
		{"--sock-dir", "/tmp/x", "--gateway", "--provider-block", "--provider-host", "-x", "--", "/usr/bin/bwrap"},
	} {
		if _, err := ParseHostArgs(args); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
}
