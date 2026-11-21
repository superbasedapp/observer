package dashapi

import (
	"strings"
	"testing"
)

// TestOSVScannerInstall pins the one install offer both surfaces show: the
// reviewed release in every way that names a version, the pin beside the
// release binary, the vendor's page, and the "installs nothing" sentence;
// Text() prints every way (the CLI form) and a "v" prefix is not doubled.
func TestOSVScannerInstall(t *testing.T) {
	const sha = "abc123"
	cases := []struct {
		name    string
		version string
	}{
		{"bare version", "2.6.0"},
		{"v-prefixed version", "v2.6.0"},
	}
	for _, c := range cases {
		o := NewOSVScannerInstall(c.version, sha)
		if o.DocsURL == "" || !strings.Contains(o.Outro, "installs nothing") {
			t.Fatalf("%s: offer %+v", c.name, o)
		}
		if len(o.Ways) != 3 {
			t.Fatalf("%s: ways %+v", c.name, o.Ways)
		}
		if got := o.Ways[0].Command; got != "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.6.0" {
			t.Errorf("%s: go command %q", c.name, got)
		}
		if got := o.Ways[2].URL; !strings.HasSuffix(got, "/tag/v2.6.0") {
			t.Errorf("%s: release url %q", c.name, got)
		}
		if !strings.Contains(o.Ways[2].Note, sha) {
			t.Errorf("%s: release note %q lacks the pin", c.name, o.Ways[2].Note)
		}
		text := o.Text()
		for _, want := range []string{
			o.DocsURL, o.Ways[0].Command, o.Ways[1].Command, "(macOS or Linux with Homebrew)",
			"a release binary from " + o.Ways[2].URL, sha, "installs nothing",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: text lacks %q:\n%s", c.name, want, text)
			}
		}
		if strings.Contains(text, "vv2") {
			t.Errorf("%s: doubled v prefix:\n%s", c.name, text)
		}
	}
}

// TestOSVScannerInstallTextEmptyLabel: a way with no label renders without
// panicking (lowerFirst of "").
func TestOSVScannerInstallTextEmptyLabel(t *testing.T) {
	o := OSVScannerInstall{Intro: "x", Ways: []OSVScannerInstallWay{{URL: "https://example.test/"}}}
	if got := o.Text(); !strings.Contains(got, "from https://example.test/") {
		t.Fatalf("text %q", got)
	}
}
