package dashapi

import "strings"

// OSVScannerInstall is the guided vendor install offer of osv-scanner (the
// security.scan.osv driver, decision D-766): the vendor's own channels,
// shown for the developer to run. Observer runs none of them. It is the one
// owner of the offer: `observer security scan install-osv-scanner` prints
// Text(), and the Code security page's Scanners card shows the same ways
// under the osv-scanner row's "How to install" (GET
// /api/security/scanners), so the two never drift.
type OSVScannerInstall struct {
	// Intro is the sentence before the ways; DocsURL the vendor's
	// installation page.
	Intro   string `json:"intro"`
	DocsURL string `json:"docs_url"`
	// Ways are the install channels, in the order they are offered.
	Ways []OSVScannerInstallWay `json:"ways"`
	// Outro says what happens until osv-scanner is installed.
	Outro string `json:"outro"`
}

// OSVScannerInstallWay is one install channel: a command to copy, or a
// download (URL) with the check to make on it.
type OSVScannerInstallWay struct {
	Label   string `json:"label"`
	Command string `json:"command,omitempty"`
	URL     string `json:"url,omitempty"`
	Note    string `json:"note,omitempty"`
}

// osvScannerModule is osv-scanner's Go module path (major version 2).
const osvScannerModule = "github.com/google/osv-scanner/v2/cmd/osv-scanner"

// NewOSVScannerInstall returns the offer for the reviewed osv-scanner
// release version (without a leading "v", depscan.OSVScannerMinVersion)
// and that release's linux amd64 sha256 (depscan.OSVScannerLinuxAMD64).
func NewOSVScannerInstall(version, linuxAMD64SHA256 string) OSVScannerInstall {
	tag := "v" + strings.TrimPrefix(version, "v")
	return OSVScannerInstall{
		Intro:   "osv-scanner is not bundled with Observer. To use the security.scan.osv driver, install it yourself from the vendor",
		DocsURL: "https://google.github.io/osv-scanner/installation/",
		Ways: []OSVScannerInstallWay{
			{Label: "With Go", Command: "go install " + osvScannerModule + "@" + tag},
			{Label: "With Homebrew", Command: "brew install osv-scanner", Note: "macOS or Linux with Homebrew"},
			{
				Label: "A release binary", URL: "https://github.com/google/osv-scanner/releases/tag/" + tag,
				Note: "check it against the release's osv-scanner_SHA256SUMS; linux amd64 sha256 " + linuxAMD64SHA256,
			},
		},
		Outro: "Observer installs nothing by itself. Until osv-scanner is on this machine, the driver starts no process and every project's dependencies show as \"not scanned\".",
	}
}

// Text renders the offer as the CLI prints it.
func (o OSVScannerInstall) Text() string {
	var b strings.Builder
	b.WriteString(o.Intro)
	if o.DocsURL != "" {
		b.WriteString(" (" + o.DocsURL + ")")
	}
	b.WriteString(", for example:\n\n")
	for _, w := range o.Ways {
		switch {
		case w.Command != "":
			b.WriteString("  " + w.Command)
			if w.Note != "" {
				b.WriteString("   (" + w.Note + ")")
			}
			b.WriteString("\n")
		default:
			b.WriteString("  " + lowerFirst(w.Label))
			if w.URL != "" {
				b.WriteString(" from " + w.URL)
			}
			b.WriteString("\n")
			if w.Note != "" {
				b.WriteString("    (" + w.Note + ")\n")
			}
		}
	}
	b.WriteString("\n" + o.Outro + "\n")
	return b.String()
}

// lowerFirst lowers a label's first letter for use inside a sentence.
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}
