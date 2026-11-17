package seclicense

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

func TestReaderForTable(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"package-lock.json", true},
		{"web/package-lock.json", true},
		{"npm-shrinkwrap.json", true},
		{"node_modules/left-pad/package.json", true},
		{"node_modules/@scope/pkg/package.json", true},
		{"node_modules/a/node_modules/b/package.json", true},
		{`node_modules\@scope\pkg\package.json`, true},
		{"package.json", false},
		{"src/package.json", false},
		{"node_modules/@scope/package.json", false},
		{"composer.lock", true},
		{"venv/lib/python3.12/site-packages/requests-2.32.0.dist-info/METADATA", true},
		{"pkg.egg-info/PKG-INFO", false},
		{"vendor/serde/Cargo.toml", true},
		{"Cargo.toml", false},
		{"crates/a/Cargo.toml", false},
		{"README.md", false},
	}
	for _, c := range cases {
		if _, got := ReaderFor(c.path); got != c.want {
			t.Errorf("ReaderFor(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestReadPackageLock(t *testing.T) {
	data := []byte(`{
  "name": "app", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "license": "MIT"},
    "node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL"},
    "node_modules/@scope/b": {"version": "2.0.0", "license": "Apache 2.0"},
    "node_modules/a/node_modules/c": {"version": "0.1.0", "license": "(MIT OR GPL-3.0)"},
    "node_modules/linked": {"resolved": "packages/linked", "link": true},
    "packages/linked": {"version": "1.0.0", "license": "ISC"},
    "node_modules/alias": {"name": "real-name", "version": "4.0.0"},
    "node_modules/obj": {"version": "1.0.0", "license": {"type": "BSD-3-Clause"}}
  }
}`)
	got := Read("package-lock.json", data)
	want := []Entry{
		{Ecosystem: "npm", Name: "@scope/b", Version: "2.0.0", License: "Apache-2.0", Raw: "Apache 2.0", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "c", Version: "0.1.0", License: "(MIT OR GPL-3.0-only)", Raw: "(MIT OR GPL-3.0)", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "real-name", Version: "4.0.0", License: "", Raw: "", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", License: "WTFPL", Raw: "WTFPL", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
		{Ecosystem: "npm", Name: "obj", Version: "1.0.0", License: "BSD-3-Clause", Raw: "BSD-3-Clause", Confidence: policy.FindingConfidenceHigh, Path: "package-lock.json"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestReadPackageJSON(t *testing.T) {
	cases := []struct {
		name, path, data string
		want             Entry
	}{
		{
			"string", "node_modules/x/package.json", `{"name":"x","version":"1.0.0","license":"MIT"}`,
			Entry{Ecosystem: "npm", Name: "x", Version: "1.0.0", License: "MIT", Raw: "MIT"},
		},
		{
			"object", "node_modules/y/package.json", `{"name":"y","version":"2.0.0","license":{"type":"ISC","url":"u"}}`,
			Entry{Ecosystem: "npm", Name: "y", Version: "2.0.0", License: "ISC", Raw: "ISC"},
		},
		{
			"legacy licenses", "node_modules/z/package.json", `{"name":"z","version":"0.0.1","licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`,
			Entry{Ecosystem: "npm", Name: "z", Version: "0.0.1", License: "MIT OR Apache-2.0", Raw: "MIT OR Apache-2.0"},
		},
		{
			"scoped name from path", "node_modules/@s/p/package.json", `{"version":"3.0.0","license":"UNLICENSED"}`,
			Entry{Ecosystem: "npm", Name: "@s/p", Version: "3.0.0", License: ProprietaryID, Raw: "UNLICENSED"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Read(c.path, []byte(c.data))
			c.want.Path = c.path
			c.want.Confidence = policy.FindingConfidenceHigh
			if len(got) != 1 || !reflect.DeepEqual(got[0], c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestReadComposerLock(t *testing.T) {
	data := []byte(`{"packages":[{"name":"monolog/monolog","version":"3.5.0","license":["MIT"]},
		{"name":"dual/pkg","version":"1.0.0","license":["GPL-2.0-or-later","MIT"]}],
		"packages-dev":[{"name":"phpunit/phpunit","version":"10.0.0","license":["BSD-3-Clause"]}]}`)
	got := Read("composer.lock", data)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3: %+v", len(got), got)
	}
	if got[1].License != "GPL-2.0-or-later OR MIT" || got[1].Ecosystem != "Packagist" {
		t.Errorf("dual = %+v", got[1])
	}
	if got[2].Name != "phpunit/phpunit" || got[2].License != "BSD-3-Clause" {
		t.Errorf("dev = %+v", got[2])
	}
}

func TestReadDistInfoMetadata(t *testing.T) {
	const p = "site-packages/x-1.0.dist-info/METADATA"
	cases := []struct {
		name, data string
		lic        string
		conf       policy.FindingConfidence
	}{
		{
			"license expression", "Metadata-Version: 2.4\nName: x\nVersion: 1.0\nLicense-Expression: MIT OR Apache-2.0\nLicense: whatever\n\nbody",
			"MIT OR Apache-2.0", policy.FindingConfidenceHigh,
		},
		{"short license", "Name: x\r\nVersion: 1.0\r\nLicense: BSD-3-Clause\r\n", "BSD-3-Clause", policy.FindingConfidenceMedium},
		{
			"unknown license falls to classifier", "Name: x\nVersion: 1.0\nLicense: UNKNOWN\nClassifier: License :: OSI Approved :: MIT License\n",
			"MIT", policy.FindingConfidenceMedium,
		},
		{
			"long license text falls to classifier", "Name: x\nVersion: 1.0\nLicense: Copyright (c) 2020\n        Permission is hereby granted\nClassifier: License :: OSI Approved :: Apache Software License\nClassifier: License :: OSI Approved :: BSD License\n",
			"Apache-2.0 OR BSD", policy.FindingConfidenceMedium,
		},
		{"no licence", "Name: x\nVersion: 1.0\n", "", policy.FindingConfidenceMedium},
		{"classifier in body ignored", "Name: x\nVersion: 1.0\n\nClassifier: License :: OSI Approved :: MIT License\n", "", policy.FindingConfidenceMedium},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Read(p, []byte(c.data))
			if len(got) != 1 {
				t.Fatalf("got %+v", got)
			}
			e := got[0]
			if e.License != c.lic || e.Confidence != c.conf || e.Name != "x" || e.Version != "1.0" || e.Ecosystem != "PyPI" {
				t.Errorf("got %+v, want licence %q confidence %q", e, c.lic, c.conf)
			}
		})
	}
}

func TestClassifierTableRows(t *testing.T) {
	for _, r := range classifierTable {
		id, ok := classifierID("License :: " + r.Classifier)
		if !ok || id != r.ID {
			t.Errorf("classifierID(%q) = %q, %v; want %q", r.Classifier, id, ok, r.ID)
		}
	}
}

func TestReadVendoredCargo(t *testing.T) {
	cases := []struct {
		name, data string
		want       Entry
		none       bool
	}{
		{
			"plain", "[package]\nname = \"serde\"\nversion = \"1.0.200\"\nlicense = \"MIT OR Apache-2.0\"\n",
			Entry{Name: "serde", Version: "1.0.200", License: "MIT OR Apache-2.0", Raw: "MIT OR Apache-2.0"},
			false,
		},
		{
			"legacy slash", "[package]\nname = \"old\"\nversion = \"0.1.0\"\nlicense = \"MIT/Apache-2.0\"\n",
			Entry{Name: "old", Version: "0.1.0", License: "MIT OR Apache-2.0", Raw: "MIT/Apache-2.0"},
			false,
		},
		{
			"workspace inherited", "[package]\nname = \"ws\"\nversion.workspace = true\nlicense.workspace = true\n",
			Entry{Name: "ws"},
			false,
		},
		{"no package table", "[workspace]\nmembers = []\n", Entry{}, true},
		{"malformed", "[package\nname = ", Entry{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Read("vendor/serde/Cargo.toml", []byte(c.data))
			if c.none {
				if got != nil {
					t.Fatalf("got %+v, want nil", got)
				}
				return
			}
			c.want.Ecosystem, c.want.Path, c.want.Confidence = "crates.io", "vendor/serde/Cargo.toml", policy.FindingConfidenceHigh
			if len(got) != 1 || !reflect.DeepEqual(got[0], c.want) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestReadersRefuseMalformedAndOversized runs every reader table row over
// garbage and over a file past MaxFileBytes: no entries, no panic.
func TestReadersRefuseMalformedAndOversized(t *testing.T) {
	big := []byte(`{"name":"x","license":"MIT","pad":"` + strings.Repeat("a", MaxFileBytes) + `"}`)
	for _, r := range readerTable {
		for _, data := range [][]byte{nil, []byte("{"), []byte("\x00\xff\xfe"), big} {
			got := r.Read("f", data)
			if len(data) > MaxFileBytes && got != nil {
				t.Errorf("%s: oversized file read %+v", r.Name, got)
			}
			if string(data) == "{" && got != nil {
				t.Errorf("%s: malformed file read %+v", r.Name, got)
			}
		}
	}
}

func TestRawIsCapped(t *testing.T) {
	data := []byte(`{"name":"x","version":"1","license":"` + strings.Repeat("é", 400) + `"}`)
	got := Read("node_modules/x/package.json", data)
	if len(got) != 1 || len(got[0].Raw) > MaxRaw {
		t.Fatalf("raw not capped: %d", len(got[0].Raw))
	}
}
