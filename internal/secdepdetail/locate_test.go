package secdepdetail

import (
	"reflect"
	"strings"
	"testing"
)

// TestLocateEveryRow: one case per locatorRows row, each a small inline
// lockfile with a decoy entry (another package, or the same package at
// another version) before the real one, so the locator must check both the
// name and the version. Lines are 1-based.
func TestLocateEveryRow(t *testing.T) {
	cases := []struct {
		name       string
		rel        string
		pkg        Package
		body       string
		start, end int
	}{
		{"package-lock v3", "web/package-lock.json", Package{"npm", "lodash", "4.17.20"}, `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "lodash": "^4.17.20"
      }
    },
    "node_modules/lodash-es": {
      "version": "4.17.20"
    },
    "node_modules/lodash": {
      "version": "4.17.20",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"
    }
  }
}`, 13, 16},
		{"package-lock nested", "package-lock.json", Package{"npm", "@scope/pkg", "1.2.3"}, `{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/a/node_modules/@scope/pkg": {
      "version": "1.2.3"
    }
  }
}`, 4, 6},
		{"npm-shrinkwrap v1", "npm-shrinkwrap.json", Package{"npm", "minimist", "1.2.0"}, `{
  "lockfileVersion": 1,
  "dependencies": {
    "minimist": {
      "version": "1.2.0",
      "dev": true
    }
  }
}`, 4, 7},
		{"yarn classic", "yarn.lock", Package{"npm", "@babel/core", "7.1.0"}, `# yarn lockfile v1

"@babel/core@^7.0.0":
  version "7.0.0"

"@babel/core@^7.1.0", "@babel/core@~7.1.0":
  version "7.1.0"
  resolved "https://example.invalid/core.tgz"
`, 6, 8},
		{"yarn berry", "yarn.lock", Package{"npm", "lodash", "4.17.20"}, `__metadata:
  version: 6

"lodash@npm:^4.17.20":
  version: 4.17.20
  resolution: "lodash@npm:4.17.20"
`, 4, 6},
		{"pnpm", "pnpm-lock.yaml", Package{"npm", "lodash", "4.17.20"}, `lockfileVersion: '9.0'

packages:

  lodash@4.17.19:
    resolution: {integrity: sha512-a}

  lodash@4.17.20:
    resolution: {integrity: sha512-b}
    engines: {node: '>=4'}

snapshots:
`, 8, 10},
		{"pnpm v6 peer", "pnpm-lock.yaml", Package{"npm", "@s/p", "1.0.0"}, `packages:
  /@s/p@1.0.0(react@18.2.0):
    dev: false
`, 2, 3},
		{"bun", "bun.lock", Package{"npm", "lodash", "4.17.20"}, `{
  "lockfileVersion": 1,
  "packages": {
    "lodash-es": ["lodash-es@4.17.20", "", {}, "sha512-a"],
    "lodash": ["lodash@4.17.20", "", {}, "sha512-b"],
  }
}`, 5, 5},
		{"go.mod", "go.mod", Package{"Go", "golang.org/x/text", "v0.3.5"}, `module example.invalid/m

go 1.22

require (
	golang.org/x/net v0.3.5
	golang.org/x/text v0.3.5 // indirect
)
`, 7, 7},
		{"go.sum", "go.sum", Package{"Go", "golang.org/x/text", "v0.3.5"}, `golang.org/x/text v0.3.4 h1:aaa=
golang.org/x/text v0.3.5 h1:bbb=
golang.org/x/text v0.3.5/go.mod h1:ccc=
`, 2, 3},
		{"Cargo.lock", "Cargo.lock", Package{"crates.io", "time", "0.1.42"}, `version = 3

[[package]]
name = "time"
version = "0.3.0"

[[package]]
name = "time"
version = "0.1.42"
dependencies = [
 "libc",
]

[[package]]
name = "libc"
version = "0.2.0"
`, 7, 12},
		{"Gemfile.lock", "Gemfile.lock", Package{"RubyGems", "rack", "2.0.0"}, `GEM
  remote: https://rubygems.org/
  specs:
    rack-test (2.0.0)
    rack (2.0.0)
      dep (>= 0)
    rails (7.0.0)

PLATFORMS
`, 5, 6},
		{"composer.lock", "composer.lock", Package{"Packagist", "symfony/http-kernel", "4.0.0"}, `{
    "packages": [
        {
            "name": "symfony/http-kernel",
            "version": "v4.0.0",
            "source": {
                "type": "git"
            }
        }
    ]
}`, 3, 9},
		{"requirements.txt", "requirements-dev.txt", Package{"PyPI", "requests", "2.19.0"}, `# pins
requests-oauthlib==1.0.0
Requests[socks]==2.19.0 ; python_version >= "3" \
    --hash=sha256:abc
flask==2.0.0
`, 3, 4},
		{"poetry.lock", "poetry.lock", Package{"PyPI", "Requests", "2.19.0"}, `[[package]]
name = "requests"
version = "2.19.0"
description = "HTTP"

[package.dependencies]
idna = "*"

[[package]]
name = "idna"
version = "3.0"
`, 1, 7},
		{"uv.lock", "uv.lock", Package{"PyPI", "requests", "2.19.0"}, `version = 1

[[package]]
name = "requests"
version = "2.19.0"
source = { registry = "https://pypi.org/simple" }

[package.metadata]
requires-dist = []
`, 3, 9},
		{"Pipfile.lock", "Pipfile.lock", Package{"PyPI", "requests", "2.19.0"}, `{
    "default": {
        "requests": {
            "hashes": [
                "sha256:abc"
            ],
            "version": "==2.19.0"
        }
    }
}`, 3, 8},
		{"pdm.lock", "pdm.lock", Package{"PyPI", "requests", "2.19.0"}, `[metadata]
groups = ["default"]

[[package]]
name = "requests"
version = "2.19.0"
summary = "HTTP"
`, 4, 7},
		{"packages.lock.json", "packages.lock.json", Package{"NuGet", "Newtonsoft.Json", "12.0.1"}, `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[12.0.1, )",
        "resolved": "12.0.1"
      }
    }
  }
}`, 5, 9},
		{"csproj attribute", "src/App.csproj", Package{"NuGet", "Newtonsoft.Json", "12.0.1"}, `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Serilog" Version="2.0.0" />
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
  </ItemGroup>
</Project>`, 4, 4},
		{"csproj child", "App.csproj", Package{"NuGet", "Newtonsoft.Json", "12.0.1"}, `<ItemGroup>
  <PackageReference Include="Newtonsoft.Json">
    <Version>12.0.1</Version>
  </PackageReference>
</ItemGroup>`, 2, 4},
		{"packages.config", "packages.config", Package{"NuGet", "Newtonsoft.Json", "12.0.1"}, `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="11.0.1" targetFramework="net45" />
  <package id="Newtonsoft.Json" version="12.0.1" targetFramework="net45" />
</packages>`, 4, 4},
		{"pom.xml", "pom.xml", Package{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"}, `<project>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-api</artifactId>
      <version>2.14.1</version>
    </dependency>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>`, 8, 12},
		{"gradle.lockfile", "gradle.lockfile", Package{"Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"}, `# Gradle lockfile
org.apache.logging.log4j:log4j-api:2.14.1=runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=compileClasspath,runtimeClasspath
empty=
`, 3, 3},
	}
	covered := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			row, ok := rowFor(c.rel)
			if !ok {
				t.Fatalf("no row for %s", c.rel)
			}
			covered[row.format] = true
			loc, _ := Locate(c.rel, []byte(c.body), c.pkg, nil)
			if !loc.Found || loc.Reason != "" {
				t.Fatalf("not found: %+v", loc)
			}
			if loc.StartLine != c.start || loc.EndLine != c.end {
				t.Fatalf("lines %d-%d, want %d-%d", loc.StartLine, loc.EndLine, c.start, c.end)
			}
			for _, l := range loc.Context {
				if l.Match != (l.Number >= c.start && l.Number <= c.end) {
					t.Fatalf("match flag wrong on line %d: %+v", l.Number, loc.Context)
				}
			}
			// Same file, a version it does not hold: not found.
			miss := c.pkg
			miss.Version = "9.9.9-nope"
			if loc, _ := Locate(c.rel, []byte(c.body), miss, nil); loc.Found || loc.Reason != ReasonNotFound {
				t.Fatalf("absent version located: %+v", loc)
			}
		})
	}
	for _, r := range locatorRows {
		if !covered[r.format] {
			t.Errorf("locator row %q has no test case", r.format)
		}
	}
}

// TestLocateUnsupportedFormat: a file no row names is never guessed at.
func TestLocateUnsupportedFormat(t *testing.T) {
	loc, rel := Locate("deps/lock.txt", []byte("lodash@4.17.20\n"), Package{"npm", "lodash", "4.17.20"}, nil)
	if loc.Found || loc.Reason != ReasonUnsupportedFormat || !reflect.DeepEqual(rel, Relationship{}) {
		t.Fatalf("unsupported: %+v %+v", loc, rel)
	}
}

// TestLocateContextWindow: up to 3 lines either side, each capped at 300
// bytes, control characters stripped, the clean hook applied.
func TestLocateContextWindow(t *testing.T) {
	long := strings.Repeat("x", 400)
	body := "a\nb\nc\nd\n" + "golang.org/x/text v0.3.5 h1:\x1b[31mzz\n" + long + "\nf\ng\nh\ni\n"
	loc, _ := Locate("go.sum", []byte(body), Package{"Go", "golang.org/x/text", "v0.3.5"}, func(s string) string {
		return strings.ReplaceAll(s, "zz", "[REDACTED]")
	})
	if !loc.Found || loc.StartLine != 5 {
		t.Fatalf("loc: %+v", loc)
	}
	if len(loc.Context) != 7 || loc.Context[0].Number != 2 || loc.Context[6].Number != 8 {
		t.Fatalf("window: %+v", loc.Context)
	}
	if got := loc.Context[3].Text; strings.ContainsRune(got, 0x1b) || !strings.Contains(got, "[REDACTED]") {
		t.Fatalf("line not cleaned: %q", got)
	}
	if len(loc.Context[4].Text) != MaxLineBytes {
		t.Fatalf("line not capped: %d", len(loc.Context[4].Text))
	}
}

// TestRelationship: package-lock v3 and go.mod state the relationship;
// every other format says nothing (except packages.lock.json's own type).
func TestRelationship(t *testing.T) {
	lock := `{
  "lockfileVersion": 3,
  "packages": {
    "": { "dependencies": { "next": "14.1.0" }, "devDependencies": { "jest": "29.0.0" } },
    "node_modules/next": { "version": "14.1.0", "dependencies": { "postcss": "8.4.31" } },
    "node_modules/jest": { "version": "29.0.0", "dev": true },
    "node_modules/vite": { "version": "5.0.0", "dev": true, "dependencies": { "postcss": "^8" } },
    "node_modules/postcss": {
      "version": "8.4.31",
      "devOptional": true
    }
  }
}`
	cases := []struct {
		name string
		rel  string
		body string
		pkg  Package
		want Relationship
	}{
		{
			"npm transitive dev with dependents", "package-lock.json", lock,
			Package{"npm", "postcss", "8.4.31"},
			Relationship{RelTransitive, ScopeDev, []string{"next@14.1.0", "vite@5.0.0"}},
		},
		{
			"npm direct runtime", "package-lock.json", lock,
			Package{"npm", "next", "14.1.0"},
			Relationship{RelDirect, ScopeRuntime, nil},
		},
		{
			"npm direct dev", "package-lock.json", lock,
			Package{"npm", "jest", "29.0.0"},
			Relationship{RelDirect, ScopeDev, nil},
		},
		{
			"go.mod indirect", "go.mod", "require golang.org/x/text v0.3.5 // indirect\n",
			Package{"Go", "golang.org/x/text", "v0.3.5"},
			Relationship{Relationship: RelTransitive},
		},
		{
			"go.mod direct", "go.mod", "require golang.org/x/text v0.3.5\n",
			Package{"Go", "golang.org/x/text", "v0.3.5"},
			Relationship{Relationship: RelDirect},
		},
		{"nuget transitive", "packages.lock.json", `{
  "dependencies": {
    "net6.0": {
      "X": {
        "type": "Transitive",
        "resolved": "1.0.0"
      }
    }
  }
}`, Package{"NuGet", "x", "1.0.0"}, Relationship{Relationship: RelTransitive}},
		{"cargo says nothing", "Cargo.lock", "[[package]]\nname = \"time\"\nversion = \"0.1.42\"\n", Package{"crates.io", "time", "0.1.42"}, Relationship{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			loc, rel := Locate(c.rel, []byte(c.body), c.pkg, nil)
			if !loc.Found {
				t.Fatalf("not found: %+v", loc)
			}
			if !reflect.DeepEqual(rel, c.want) {
				t.Fatalf("relationship %+v, want %+v", rel, c.want)
			}
		})
	}
}
