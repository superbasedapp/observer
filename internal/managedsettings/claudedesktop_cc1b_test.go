package managedsettings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestGenerateClaudeDesktop covers CC-1b (decision D1): an explicit admin
// option, a helper-script credential (never a key), the Desktop's own policy
// channels, and a README that names the trade-off and live check LC2.
func TestGenerateClaudeDesktop(t *testing.T) {
	ok := ClaudeDesktopOptions{GatewayRoute: true, CredentialHelper: "/usr/local/bin/org-gateway-key"}
	cases := []struct {
		name    string
		opts    ClaudeDesktopOptions
		wantErr error
		errText string
		// channels are the artifacts generated: only the OSes that have a
		// helper (a POSIX helper covers Linux and macOS).
		channels []Channel
	}{
		{name: "not chosen", opts: ClaudeDesktopOptions{CredentialHelper: "/x"}, wantErr: ErrClaudeDesktopGatewayNotChosen},
		{name: "no helper", opts: ClaudeDesktopOptions{GatewayRoute: true}, wantErr: ErrClaudeDesktopNoHelper},
		{name: "relative helper", opts: ClaudeDesktopOptions{GatewayRoute: true, CredentialHelper: "bin/key"}, errText: "absolute POSIX path"},
		{name: "relative windows helper", opts: ClaudeDesktopOptions{GatewayRoute: true, CredentialHelperWindows: `key.exe`}, errText: "absolute Windows path"},
		{name: "bad scheme", opts: ClaudeDesktopOptions{GatewayRoute: true, CredentialHelper: "/x", AuthScheme: "basic"}, errText: "auth scheme"},
		{name: "bad url", opts: ClaudeDesktopOptions{GatewayRoute: true, CredentialHelper: "/x", GatewayBaseURL: "ftp://h"}, errText: "http(s) URL"},
		{name: "posix helper only: no Windows import", opts: ok, channels: []Channel{ChannelFile, ChannelProfile}},
		{
			name:     "windows helper only: no Linux file or macOS profile",
			opts:     ClaudeDesktopOptions{GatewayRoute: true, CredentialHelperWindows: `C:\Program Files\Org\key.exe`, AuthScheme: "bearer"},
			channels: []Channel{ChannelRegistry},
		},
		{
			name:     "both helpers: every channel",
			opts:     ClaudeDesktopOptions{GatewayRoute: true, CredentialHelper: "/usr/local/bin/k", CredentialHelperWindows: `C:\k.exe`},
			channels: []Channel{ChannelFile, ChannelProfile, ChannelRegistry},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			arts, err := GenerateClaudeDesktop(tc.opts)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			case tc.errText != "":
				if err == nil || !strings.Contains(err.Error(), tc.errText) {
					t.Fatalf("err = %v, want one naming %q", err, tc.errText)
				}
				return
			case err != nil:
				t.Fatalf("GenerateClaudeDesktop: %v", err)
			}
			channels := map[Channel]bool{}
			for _, a := range arts.Artifacts {
				channels[a.Channel] = true
				if strings.Contains(strings.ToLower(a.Content), "apikey") {
					t.Errorf("%s carries a key field:\n%s", a.Name, a.Content)
				}
			}
			for _, ch := range tc.channels {
				if !channels[ch] {
					t.Errorf("no %s artifact (have %v)", ch, channels)
				}
			}
			if len(channels) != len(tc.channels) {
				t.Errorf("channels %v, want exactly %v", channels, tc.channels)
			}
			for _, a := range arts.Artifacts {
				if a.Channel != ChannelFile {
					continue
				}
				var doc map[string]any
				if err := json.Unmarshal([]byte(a.Content), &doc); err != nil {
					t.Fatalf("%s: %v", a.Name, err)
				}
				if doc["inferenceProvider"] != "gateway" || doc["inferenceCredentialKind"] != "helper-script" {
					t.Errorf("policy file = %v, want gateway mode with a helper-script credential", doc)
				}
				if tc.opts.GatewayBaseURL == "" && doc["inferenceGatewayBaseUrl"] != DefaultClaudeCodeProxyBaseURL {
					t.Errorf("inferenceGatewayBaseUrl = %v, want the node proxy", doc["inferenceGatewayBaseUrl"])
				}
			}
			for _, want := range []string{"Not live-verified (" + ClaudeDesktopLiveCheck + ")", "Remote Control", "cloud environments", "never writes a key"} {
				if !strings.Contains(arts.Readme, want) {
					t.Errorf("README missing %q:\n%s", want, arts.Readme)
				}
			}
		})
	}
}
