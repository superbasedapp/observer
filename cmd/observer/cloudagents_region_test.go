package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
)

// TestCloudAgentsRegionPicker (lane CA-V2): the region is a numbered pick
// from the row's choices, never free text; off a terminal the flag is
// required; a flag value is passed through for ValidateParams to check.
func TestCloudAgentsRegionPicker(t *testing.T) {
	c, ok := cloudagents.ConnectorByID(cloudagents.ConnectorQoderCloud)
	if !ok {
		t.Fatal("no qoder-cloud row")
	}
	p := c.Params[0]
	for in, want := range map[string]string{"1\n": "global", "2\n": "cn", " 2 \n": "cn"} { //nolint:gocritic // the padded key is the case under test: the picker trims the typed answer
		var out bytes.Buffer
		got, err := pickChoice(bufio.NewReader(strings.NewReader(in)), &out, p)
		if err != nil || got != want {
			t.Errorf("pick %q = %q %v, want %q", in, got, err, want)
		}
		if !strings.Contains(out.String(), "China (api.qoder.com.cn)") {
			t.Errorf("prompt %q does not list the choices", out.String())
		}
	}
	for _, in := range []string{"cn\n", "api.qoder.com.cn\n", "0\n", "3\n", ""} {
		if v, err := pickChoice(bufio.NewReader(strings.NewReader(in)), &bytes.Buffer{}, p); err == nil {
			t.Errorf("pick %q accepted as %q", in, v)
		}
	}

	cmd := &cobra.Command{}
	cmd.SetIn(strings.NewReader("token\n"))
	cmd.SetErr(&bytes.Buffer{})
	if _, err := cloudAgentsCredentials(cmd, cloudagents.ConnectorQoderCloud, cloudAgentsParamFlags{}); err == nil ||
		!strings.Contains(err.Error(), "--region") {
		t.Fatalf("no region off a terminal: %v", err)
	}
	cmd.SetIn(strings.NewReader("token\n"))
	cred, err := cloudAgentsCredentials(cmd, cloudagents.ConnectorQoderCloud, cloudAgentsParamFlags{region: "cn"})
	if err != nil || cred.Params[cloudagents.ParamRegion] != "cn" || strings.TrimSpace(cred.Key) != "token" {
		t.Fatalf("region flag: %+v %v", cred.Params, err)
	}
	if _, err := cloudAgentsCredentials(cmd, cloudagents.ConnectorCodexCloud, cloudAgentsParamFlags{region: "cn"}); err == nil {
		t.Fatal("a CLI connector accepted --region")
	}
}
