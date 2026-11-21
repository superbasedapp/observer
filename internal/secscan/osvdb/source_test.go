package osvdb

import (
	"strings"
	"testing"
)

func TestSourcePlan(t *testing.T) {
	cases := []struct {
		name string
		in   SourceInput
		want string
	}{
		{"managed, whatever the setting", SourceInput{Managed: true, Setting: SettingUpstream, FallbackUpstream: true}, "org_mirror"},
		{"import", SourceInput{Setting: SettingImport, FallbackUpstream: true}, "import"},
		{"upstream", SourceInput{Setting: SettingUpstream}, "upstream"},
		{"feed only, the fallback ignored", SourceInput{Setting: SettingFeed, FallbackUpstream: true}, "feed"},
		{"auto with the fallback", SourceInput{Setting: SettingAuto, FallbackUpstream: true}, "feed,upstream"},
		{"empty reads as auto", SourceInput{FallbackUpstream: true}, "feed,upstream"},
		{"auto without the fallback", SourceInput{Setting: SettingAuto}, "feed"},
	}
	for _, c := range cases {
		if got := strings.Join(SourcePlan(c.in), ","); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}
