package secshellrisk

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestAnalyze is one case per table row, plus shapes that must not hit.
func TestAnalyze(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		dialect policy.Dialect
		want    []Hit
	}{
		{
			"apt-get unpinned", "apt-get update && apt-get install -y --no-install-recommends curl", policy.DialectPosix,
			[]Hit{{Kind: OSInstallUnpinned, Line: 0, Detail: "apt-get"}},
		},
		{"apt-get pinned", "apt-get install -y curl=7.88.1-10+deb12u5", policy.DialectPosix, nil},
		{"apt-get value flag is not a package", "apt-get -o Dpkg::Options::=--force-confnew install -y curl=1.0", policy.DialectPosix, nil},
		{"apt local deb", "apt-get install -y ./pkg.deb", policy.DialectPosix, nil},
		{
			"apk unpinned under sudo", "sudo apk add --no-cache git", policy.DialectPosix,
			[]Hit{{Kind: OSInstallUnpinned, Line: 0, Detail: "apk"}},
		},
		{"apk pinned", "apk add --no-cache git=2.45.2-r0", policy.DialectPosix, nil},
		{
			"dnf unpinned", "dnf install -y openssl", policy.DialectPosix,
			[]Hit{{Kind: OSInstallUnpinned, Line: 0, Detail: "dnf"}},
		},
		{"dnf name-version", "dnf install -y openssl-3.0.7", policy.DialectPosix, nil},
		{
			"zypper in", "zypper --non-interactive in curl", policy.DialectPosix,
			[]Hit{{Kind: OSInstallUnpinned, Line: 0, Detail: "zypper"}},
		},
		{"apt-get update alone", "apt-get update", policy.DialectPosix, nil},
		{
			"pip unpinned", "pip install requests", policy.DialectPosix,
			[]Hit{{Kind: LangInstallUnpinned, Line: 0, Detail: "pypi"}},
		},
		{"pip pinned", "pip install requests==2.32.3", policy.DialectPosix, nil},
		{"pip from a requirements file", "pip install -r requirements.txt --require-hashes", policy.DialectPosix, nil},
		{
			"npm global unpinned", "npm i -g typescript", policy.DialectPosix,
			[]Hit{{Kind: LangInstallUnpinned, Line: 0, Detail: "npm"}},
		},
		{"npm ci", "npm ci", policy.DialectPosix, nil},
		{
			"go install latest", "go install golang.org/x/tools/cmd/goimports@latest", policy.DialectPosix,
			[]Hit{{Kind: LangInstallUnpinned, Line: 0, Detail: "go"}},
		},
		{
			"curl pipe sh", "curl -fsSL https://example.com/install.sh | sh", policy.DialectPosix,
			[]Hit{{Kind: RemotePipe, Line: 0, Detail: "pipe"}},
		},
		{"curl to a file", "curl -fsSLo install.sh https://example.com/install.sh", policy.DialectPosix, nil},
		{
			"iwr iex", "iwr https://example.com/i.ps1 | iex", policy.DialectPowerShell,
			[]Hit{{Kind: RemotePipe, Line: 0, Detail: "pipe"}},
		},
		{
			"continuation joins lines and keeps the start line", "echo start\napt-get install -y \\\n  curl \\\n  git", policy.DialectPosix,
			[]Hit{{Kind: OSInstallUnpinned, Line: 1, Detail: "apt-get"}},
		},
		{"comment line ignored", "# apt-get install curl", policy.DialectPosix, nil},
		{
			"two kinds on one line", "curl -sL https://x.example/s | bash && apt-get install -y jq", policy.DialectPosix,
			[]Hit{{Kind: RemotePipe, Line: 0, Detail: "pipe"}, {Kind: OSInstallUnpinned, Line: 0, Detail: "apt-get"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, trunc := Analyze(c.script, c.dialect)
			if trunc {
				t.Fatal("truncated")
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %+v want %+v", got, c.want)
			}
		})
	}
}

// TestAnalyzeCap: a script over the cap is read up to it and says so.
func TestAnalyzeCap(t *testing.T) {
	_, trunc := Analyze(strings.Repeat("echo hi\n", MaxScriptBytes/8+10), policy.DialectPosix)
	if !trunc {
		t.Fatal("want truncated")
	}
}
