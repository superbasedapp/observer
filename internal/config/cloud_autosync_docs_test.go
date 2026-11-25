package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// TestCloudAutoSyncDefaultMatchesItsDocs pins G12 (cloud-intelligence parity
// design): the built-in auto-sync default was lowered from 60 to 15 minutes,
// but the [cloud] config comment and the dashboard's interval help kept
// saying 60. Every place that STATES the number is read here and compared with
// CloudAutoSyncDefaultMinutes, so the next change to the default cannot leave
// a stale copy behind.
func TestCloudAutoSyncDefaultMatchesItsDocs(t *testing.T) {
	want := strconv.Itoa(CloudAutoSyncDefaultMinutes)
	cases := []struct {
		file string
		re   *regexp.Regexp
	}{
		// The AutoSyncIntervalMinutes field comment in this package.
		{"cloud.go", regexp.MustCompile(`\(CloudAutoSyncDefaultMinutes, (\d+)\)`)},
		// The Settings -> Cloud Intelligence interval help.
		{
			filepath.Join("..", "..", "web", "src", "pages", "settings", "CloudIntelligenceSection.tsx"),
			regexp.MustCompile(`0 = built-in default \((\d+)\)`),
		},
	}
	for _, c := range cases {
		raw, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		m := c.re.FindAllStringSubmatch(string(raw), -1)
		if len(m) == 0 {
			t.Fatalf("%s no longer states the auto-sync default (pattern %q): update this test with it", c.file, c.re)
		}
		for _, got := range m {
			if got[1] != want {
				t.Errorf("%s says the auto-sync default is %s minutes, the code says %s", c.file, got[1], want)
			}
		}
	}
}
