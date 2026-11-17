package secsbom

import "testing"

// TestPurlTableBothDirections pins one case per purl table row: the purl
// PurlFor renders, ParsePurl's reverse, and the round trip.
func TestPurlTableBothDirections(t *testing.T) {
	cases := []struct {
		eco, name, version string
		purl               string
	}{
		{"npm", "@angular/core", "17.0.0", "pkg:npm/%40angular/core@17.0.0"},
		{"PyPI", "requests", "2.19.0", "pkg:pypi/requests@2.19.0"},
		{"Go", "golang.org/x/text", "v0.3.5", "pkg:golang/golang.org/x/text@v0.3.5"},
		{"crates.io", "time", "0.1.42", "pkg:cargo/time@0.1.42"},
		{"RubyGems", "rack", "2.0.0", "pkg:gem/rack@2.0.0"},
		{"Packagist", "symfony/http-kernel", "4.0.0", "pkg:composer/symfony/http-kernel@4.0.0"},
		{"NuGet", "Newtonsoft.Json", "12.0.1", "pkg:nuget/Newtonsoft.Json@12.0.1"},
		{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"Pub", "http", "0.13.2", "pkg:pub/http@0.13.2"},
		{"Hex", "plug", "1.3.4", "pkg:hex/plug@1.3.4"},
		{"Hackage", "aeson", "1.5.6.0", "pkg:hackage/aeson@1.5.6.0"},
		{"SwiftURL", "github.com/apple/swift-nio-http2", "1.19.1", "pkg:swift/github.com/apple/swift-nio-http2@1.19.1"},
		{"Julia", "HTTP", "1.10.16", "pkg:julia/HTTP@1.10.16"},
		{"CRAN", "readxl", "1.2.0", "pkg:cran/readxl@1.2.0"},
		{"GitHub Actions", "tj-actions/changed-files", "v45.0.0", "pkg:githubactions/tj-actions/changed-files@v45.0.0"},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(c.eco, func(t *testing.T) {
			seen[c.eco] = true
			got, ok := PurlFor(c.eco, c.name, c.version)
			if !ok || got != c.purl {
				t.Fatalf("PurlFor(%q, %q, %q) = %q, %v; want %q", c.eco, c.name, c.version, got, ok, c.purl)
			}
			eco, name, version, ok := ParsePurl(c.purl)
			if !ok || eco != c.eco || name != c.name || version != c.version {
				t.Fatalf("ParsePurl(%q) = %q %q %q %v", c.purl, eco, name, version, ok)
			}
			again, _ := PurlFor(eco, name, version)
			if again != c.purl {
				t.Fatalf("round trip %q -> %q", c.purl, again)
			}
		})
	}
	for _, eco := range Ecosystems() {
		if !seen[eco] {
			t.Errorf("purl table row %q has no test case", eco)
		}
		typ, ok := PurlType(eco)
		if !ok {
			t.Errorf("PurlType(%q) missing", eco)
		}
		if back, ok := EcosystemForType(typ); !ok || back != eco {
			t.Errorf("EcosystemForType(%q) = %q, want %q", typ, back, eco)
		}
	}
}

// TestPurlEncodingEdges pins the per-type name rules and percent-encoding.
func TestPurlEncodingEdges(t *testing.T) {
	render := []struct {
		eco, name, version, want string
		ok                       bool
	}{
		{"PyPI", "Django_REST.framework", "3.0", "pkg:pypi/django-rest-framework@3.0", true},
		{"Packagist", "Symfony/Console", "6.0", "pkg:composer/symfony/console@6.0", true},
		{"npm", "lodash", "", "pkg:npm/lodash", true},
		{"Go", "example.com/m", "v1.0.0+incompatible", "pkg:golang/example.com/m@v1.0.0%2Bincompatible", true},
		{"GitHub Actions", "github/codeql-action/init", "v3", "pkg:githubactions/github/codeql-action@v3#init", true},
		{"Maven", "no-colon", "1", "", false},
		{"GitHub Actions", "solo", "v1", "", false},
		{"Julia", "", "1", "", false},
		{"Unknown", "x", "1", "", false},
		{"GIT", "x", "1", "", false},
	}
	for _, c := range render {
		got, ok := PurlFor(c.eco, c.name, c.version)
		if ok != c.ok || got != c.want {
			t.Errorf("PurlFor(%q, %q, %q) = %q, %v; want %q, %v", c.eco, c.name, c.version, got, ok, c.want, c.ok)
		}
	}
	parse := []struct {
		purl, eco, name, version string
		ok                       bool
	}{
		{"pkg:npm/@scope/name@1.0", "npm", "@scope/name", "1.0", true},
		{"PKG:NPM/lodash@4.17.20?vcs_url=x", "npm", "lodash", "4.17.20", true},
		{"pkg:pypi/Django_REST@3.0", "PyPI", "django-rest", "3.0", true},
		{"pkg:githubactions/github/codeql-action@v3#init/", "GitHub Actions", "github/codeql-action/init", "v3", true},
		{"pkg:golang/example.com/m@v1.0.0%2Bincompatible", "Go", "example.com/m", "v1.0.0+incompatible", true},
		{"pkg:maven/org/apache/x@1", "Maven", "org.apache:x", "1", true},
		{"pkg:cargo/serde", "crates.io", "serde", "", true},
		{"pkg:generic/openssl@3.0", "", "", "", false},
		{"pkg:github/actions/checkout@v4", "", "", "", false},
		{"pkg:npm/bad%zz@1", "", "", "", false},
		{"pkg:npm", "", "", "", false},
		{"https://example.com", "", "", "", false},
		{"", "", "", "", false},
	}
	for _, c := range parse {
		eco, name, version, ok := ParsePurl(c.purl)
		if ok != c.ok || eco != c.eco || name != c.name || version != c.version {
			t.Errorf("ParsePurl(%q) = %q %q %q %v; want %q %q %q %v", c.purl, eco, name, version, ok, c.eco, c.name, c.version, c.ok)
		}
	}
}
