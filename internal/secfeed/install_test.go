package secfeed

import (
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

func specsOf(t *testing.T, cmd string) Installs {
	t.Helper()
	return ParseInstalls(&policy.Event{Kind: policy.KindShellExec, Target: cmd})
}

func names(in Installs) string {
	var out []string
	for _, s := range in.Specs {
		if s.Invalid {
			out = append(out, "!"+string(s.Eco)+":"+s.Spec)
			continue
		}
		n := string(s.Eco) + ":" + s.Name
		if s.Version != "" {
			n += "@" + s.Version
		}
		out = append(out, n)
	}
	return strings.Join(out, " ")
}

// TestParseInstalls is one case per install table row, plus the flag,
// wrapper and invalid-spec shapes.
func TestParseInstalls(t *testing.T) {
	cases := []struct {
		cmd, want string
		registry  bool
	}{
		{"npm install left-pad", "npm:left-pad", false},
		{"npm i -D @types/node@20.1.0 react", "npm:@types/node@20.1.0 npm:react", false},
		{"npm add lodash@^4", "npm:lodash", false},
		{"npm install", "", false},
		{"npm in evil", "npm:evil", false},
		{"npm ins evil", "npm:evil", false},
		{"npm inst evil", "npm:evil", false},
		{"npm insta evil", "npm:evil", false},
		{"npm instal evil", "npm:evil", false},
		{"npm isnt evil", "npm:evil", false},
		{"npm isnta evil", "npm:evil", false},
		{"npm isntal evil", "npm:evil", false},
		{"npm isntall evil", "npm:evil", false},
		{"npm install-test evil", "npm:evil", false},
		{"npm it evil", "npm:evil", false},
		{"npm it", "", false},
		{"npm exec -- cowsay hi", "npm:cowsay", false},
		{"npm install --registry https://evil.example x", "npm:x", true},
		{"npm install --registry=https://evil.example x", "npm:x", true},
		{"pnpm add zod", "npm:zod", false},
		{"pnpm dlx create-vite app", "npm:create-vite", false},
		{"yarn add axios", "npm:axios", false},
		{"yarn global add typescript", "npm:typescript", false},
		{"bun add hono", "npm:hono", false},
		{"npx -y create-react-app my-app", "npm:create-react-app", false},
		{"npx --package=@scope/tool tool --flag", "npm:@scope/tool", false},
		{"pip install requests==2.31.0 'flask[async]>=2'", "pypi:requests@2.31.0 pypi:flask", false},
		{"pip install -r requirements.txt", "", false},
		{"pip install --index-url https://corp/simple x", "pypi:x", true},
		{"pip3 install --extra-index-url=https://corp x", "pypi:x", true},
		{"python -m pip install numpy", "pypi:numpy", false},
		{"python3 -m pip install -U pandas", "pypi:pandas", false},
		{"uv pip install httpx", "pypi:httpx", false},
		{"uv add rich", "pypi:rich", false},
		{"uv tool install ruff", "pypi:ruff", false},
		{"uvx black --check .", "pypi:black", false},
		{"pipx install poetry", "pypi:poetry", false},
		{"pipx run cowsay", "pypi:cowsay", false},
		{"poetry add pydantic", "pypi:pydantic", false},
		{"cargo add serde", "cargo:serde", false},
		{"cargo install ripgrep --version 14.0.0", "cargo:ripgrep", false},
		{"cargo add x --registry corp", "cargo:x", true},
		{"go get github.com/spf13/cobra@v1.8.0", "go:github.com/spf13/cobra@v1.8.0", false},
		{"go install golang.org/x/tools/gopls@latest", "go:golang.org/x/tools/gopls", false},
		{"go install ./cmd/...", "!go:./cmd/...", false},
		{"gem install rails", "rubygems:rails", false},
		{"composer require monolog/monolog", "packagist:monolog/monolog", false},
		{"dotnet add package Newtonsoft.Json", "nuget:Newtonsoft.Json", false},
		{"dotnet add app.csproj package Serilog", "nuget:Serilog", false},
		{"npm install github:user/repo", "!npm:github:user/repo", false},
		{"npm install user/repo", "!npm:user/repo", false},
		{"npm install ./local-pkg", "!npm:./local-pkg", false},
		{"npm install https://x.example/p.tgz", "!npm:https://x.example/p.tgz", false},
		{"pip install 'pkg @ https://x.example/p.whl'", "!pypi:pkg @ https://x.example/p.whl", false},
		{"pip install git+https://github.com/x/y", "!pypi:git+https://github.com/x/y", false},
		{"sudo npm install -g evil", "npm:evil", false},
		{"cd app && npm install a && pip install b", "npm:a pypi:b", false},
		{"bash -c 'npm install nested'", "npm:nested", false},
		{"PIP_INDEX_URL=https://corp pip install x", "pypi:x", true},
		{"npm test", "", false},
		{"echo npm install x", "", false},
	}
	for _, c := range cases {
		got := specsOf(t, c.cmd)
		if n := names(got); n != c.want || got.CustomRegistry != c.registry {
			t.Errorf("%q: %q registry=%v, want %q registry=%v", c.cmd, n, got.CustomRegistry, c.want, c.registry)
		}
	}
	if s := specsOf(t, "npm install --ignore-scripts x"); !s.IgnoreScripts {
		t.Error("--ignore-scripts not seen")
	}
	if got := ParseInstalls(&policy.Event{Kind: policy.KindFileAccess, Target: "npm install x"}); len(got.Specs) != 0 {
		t.Error("only shell events carry installs")
	}
}

func TestManifestAdditions(t *testing.T) {
	cases := []struct {
		path, old, new, want string
	}{
		{"package.json", `{"dependencies":{"react":"^18"}}`, `{"dependencies":{"react":"^18","lodahs":"^1"},"devDependencies":{"vitest":"1"}}`, "npm:lodahs npm:vitest"},
		{"web/package.json", `    "react": "^18",`, "    \"react\": \"^18\",\n    \"evil\": \"1.0.0\",\n    \"name\": \"1.0.0\",", "npm:evil"},
		{"package.json", "", `  "scripts": { "build": "tsc" }`, ""},
		{"requirements.txt", "requests==2\n", "requests==3\nreqeusts>=1 # typo\n-r other.txt\n", "pypi:reqeusts"},
		{"requirements-dev.txt", "", "pytest\n", "pypi:pytest"},
		{"pyproject.toml", "", "dependencies = [\n  \"httpx>=0.27\",\n  \"rich\",\n]\nrequires-python = \">=3.9\"\n", "pypi:httpx pypi:rich"},
		{"Cargo.toml", "[dependencies]\nserde = \"1\"\n", "[dependencies]\nserde = \"1\"\ntokio = { version = \"1\" }\nedition = \"2021\"\n", "cargo:tokio"},
		{"go.mod", "", "require (\n\tgithub.com/spf13/cobra v1.8.0\n)\n", "go:github.com/spf13/cobra"},
		{"Gemfile", "", "gem \"rails\", \"~> 7\"\n", "rubygems:rails"},
		{"app.csproj", "", `<PackageReference Include="Serilog" Version="3.0.0" />`, "nuget:Serilog"},
		{"composer.json", "", `{"require":{"monolog/monolog":"^3"}}`, "packagist:monolog/monolog"},
		{"README.md", "", "npm install x", ""},
	}
	for _, c := range cases {
		got := names(Installs{Specs: ManifestAdditions(c.path, c.old, c.new)})
		if got != c.want {
			t.Errorf("%s: %q, want %q", c.path, got, c.want)
		}
	}
	if eco, ok := IsManifest("a/b/Cargo.toml"); !ok || eco != EcoCargo {
		t.Error("Cargo.toml not a manifest")
	}
	if _, ok := IsManifest("main.go"); ok {
		t.Error("main.go is not a manifest")
	}
}

// TestDecideTable is one case per verdict table row (section 8.3
// "Outcomes").
func TestDecideTable(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	spec := InstallSpec{Eco: EcoNpm, Name: "pkg"}
	fresh := content.Fresh
	cases := []struct {
		name   string
		in     DecideInput
		want   policy.InstallVerdict
		reason string
	}{
		{"invalid spec", DecideInput{Spec: InstallSpec{Eco: EcoNpm, Spec: "./x", Invalid: true}}, policy.InstallNotChecked, ReasonInvalidLocation},
		{"offline listed", DecideInput{Spec: spec, Offline: Answer{Malicious: true}, IndexFreshness: fresh}, policy.InstallMalicious, ReasonListedOffline},
		{"offline listed, online says fine", DecideInput{Spec: spec, Offline: Answer{Malicious: true}, IndexFreshness: content.Stale, Online: OnlineAnswer{Status: OnlineAnswered}}, policy.InstallMalicious, ReasonListedOffline},
		{"online MAL, pinned", DecideInput{Spec: InstallSpec{Eco: EcoNpm, Name: "pkg", Version: "1.0.0"}, IndexFreshness: fresh, Online: OnlineAnswer{Status: OnlineAnswered, MalIDs: []string{"MAL-1"}}}, policy.InstallMalicious, ReasonListedOnline},
		{"online MAL, unpinned", DecideInput{Spec: spec, IndexFreshness: fresh, Online: OnlineAnswer{Status: OnlineAnswered, MalIDs: []string{"MAL-1"}}}, policy.InstallListedVersion, ReasonListedVersion},
		{"offline some versions, unpinned", DecideInput{Spec: spec, IndexFreshness: fresh, Offline: Answer{ListedVersions: true}}, policy.InstallListedVersion, ReasonListedVersion},
		{"online GHSA is not malicious", DecideInput{Spec: spec, IndexFreshness: fresh, Online: OnlineAnswer{Status: OnlineAnswered, MalIDs: []string{"GHSA-1"}}}, policy.InstallKnownGood, ReasonExists},
		{"popular", DecideInput{Spec: spec, IndexFreshness: fresh, Offline: Answer{Popular: true}}, policy.InstallKnownGood, ReasonPopular},
		{"near miss", DecideInput{Spec: spec, IndexFreshness: fresh, Offline: Answer{NearMiss: "pkgs"}}, policy.InstallNearMiss, ReasonNearMiss},
		{"near miss but private", DecideInput{Spec: spec, Private: true, IndexFreshness: fresh, Offline: Answer{NearMiss: "pkgs"}}, policy.InstallNotChecked, ReasonPrivateOffline},
		{"not found", DecideInput{Spec: spec, IndexFreshness: fresh, Online: OnlineAnswer{Status: OnlineNotFound}}, policy.InstallUnknownName, ReasonNotFound},
		{"too new", DecideInput{Spec: spec, IndexFreshness: fresh, MinAge: 72 * time.Hour, Now: now, Online: OnlineAnswer{Status: OnlineAnswered, FirstPublished: now.Add(-time.Hour)}}, policy.InstallTooNew, ReasonTooNew},
		{"old enough", DecideInput{Spec: spec, IndexFreshness: fresh, MinAge: 72 * time.Hour, Now: now, Online: OnlineAnswer{Status: OnlineAnswered, FirstPublished: now.Add(-100 * time.Hour)}}, policy.InstallKnownGood, ReasonExists},
		{"age unknown (mirror)", DecideInput{Spec: spec, IndexFreshness: fresh, MinAge: 72 * time.Hour, Now: now, Online: OnlineAnswer{Status: OnlineAnswered}}, policy.InstallKnownGood, ReasonExists},
		{"online failed", DecideInput{Spec: spec, IndexFreshness: fresh, Online: OnlineAnswer{Status: OnlineFailed, Reason: "timeout"}}, policy.InstallOnlineUnknown, ReasonOnlineFailed},
		{"index unusable, not asked", DecideInput{Spec: spec, IndexFreshness: content.Unknown}, policy.InstallUnknownName, ReasonIndexUnusable},
		{"index missing its malicious half", DecideInput{Spec: spec, IndexFreshness: fresh, Offline: Answer{MaliciousMissing: true}}, policy.InstallUnknownName, ReasonIndexUnusable},
		{"listing in an index past its age floor stays malicious", DecideInput{Spec: spec, IndexFreshness: content.Unknown, Offline: Answer{Malicious: true}}, policy.InstallMalicious, ReasonListedOffline},
		{"private, offline only", DecideInput{Spec: spec, Private: true, IndexFreshness: fresh}, policy.InstallNotChecked, ReasonPrivateOffline},
		{"private, no usable index: not S-744 every time", DecideInput{Spec: spec, Private: true, IndexFreshness: content.Unknown}, policy.InstallNotChecked, ReasonPrivateOffline},
		{"private, listed offline still malicious", DecideInput{Spec: spec, Private: true, IndexFreshness: content.Unknown, Offline: Answer{Malicious: true}}, policy.InstallMalicious, ReasonListedOffline},
		{"public, not asked", DecideInput{Spec: spec, IndexFreshness: fresh}, policy.InstallNotChecked, ReasonNotAsked},
	}
	for _, c := range cases {
		got := Decide(c.in)
		if got.Verdict != c.want || got.Reason != c.reason {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, got.Verdict, got.Reason, c.want, c.reason)
		}
	}
	v, s := Summarize([]policy.InstallCheck{{Verdict: policy.InstallKnownGood, Source: policy.InstallSourceOffline}, {Verdict: policy.InstallOnlineUnknown, Source: policy.InstallSourceOnline}})
	if v != policy.InstallOnlineUnknown || s != policy.InstallSourceOnline {
		t.Errorf("summary %s %s", v, s)
	}
	if n := SafeName("évil\x1b[31m" + strings.Repeat("x", 300)); len(n) != policy.InstallNameMax || strings.ContainsAny(n, "\x1bé") {
		t.Errorf("SafeName %q", n)
	}
}

// TestParseInstallsBypasses is milestone 2a: each shape the first build
// missed is one row (value-taking flags before the subcommand, missing
// forms, the create and init forms that run a package, versioned pip and
// python names, go run mod@version, uvx --with).
func TestParseInstallsBypasses(t *testing.T) {
	cases := []struct{ cmd, want string }{
		{"pnpm --filter web add evil", "npm:evil"},
		{"pnpm -F web add evil", "npm:evil"},
		{"pnpm -C app add evil", "npm:evil"},
		{"pnpm --dir app add evil", "npm:evil"},
		{"yarn --cwd app add evil", "npm:evil"},
		{"npm --prefix app install evil", "npm:evil"},
		{"npm -w app install evil", "npm:evil"},
		{"npm --workspace app i evil", "npm:evil"},
		{"npm -p install evil", "npm:evil"},
		{"yarn workspace web add evil", "npm:evil"},
		{"yarn workspace web add -D evil other", "npm:evil npm:other"},
		{"cargo +nightly install evil", "cargo:evil"},
		{"cargo +1.80 add evil", "cargo:evil"},
		{"npm x evil --flag", "npm:evil"},
		{"bun x evil", "npm:evil"},
		{"uv run --with evil script.py", "pypi:evil"},
		{"uv run --with evil,other python -c 1", "pypi:evil pypi:other"},
		{"uv run script.py", ""},
		{"uv tool run evil", "pypi:evil"},
		{"uv tool run --from evil cmd", "pypi:evil"},
		{"pipx inject myvenv evil other", "pypi:evil pypi:other"},
		{"npm create vite@5.0.0 my-app", "npm:create-vite@5.0.0"},
		{"npm create vite", "npm:create-vite"},
		{"npm create @scope", "npm:@scope/create"},
		{"npm create @scope/app", "npm:@scope/create-app"},
		{"yarn create react-app x", "npm:create-react-app"},
		{"pnpm create astro", "npm:create-astro"},
		{"bun create hono", "npm:create-hono"},
		{"npm init evil", "npm:create-evil"},
		{"npm init -y", ""},
		{"npm init", ""},
		{"pip3.12 install evil", "pypi:evil"},
		{"python3.12 -m pip install evil", "pypi:evil"},
		{"python -I -m pip install evil", "pypi:evil"},
		{"py -3.12 -m pip install evil", "pypi:evil"},
		{"python3.12 -m venv x", ""},
		{"go run golang.org/x/tools/cmd/stringer@v0.20.0 -type X", "go:golang.org/x/tools/cmd/stringer@v0.20.0"},
		{"go run ./cmd/tool", ""},
		{"go run main.go", ""},
		{"uvx --with evil black", "pypi:evil pypi:black"},
		{"uvx --from evil black", "pypi:evil"},
	}
	for _, c := range cases {
		if got := names(specsOf(t, c.cmd)); got != c.want {
			t.Errorf("%q: %q, want %q", c.cmd, got, c.want)
		}
	}
}

// TestCommandPrivateShapes is lane SEC-D1FIX2 milestones 2b and 2d: each
// shape that points an install at another source makes its packages
// private (never sent online), and S-745 (custom) is raised only for a
// shape that names a registry, never for GOFLAGS, CARGO_HOME or GOENV.
func TestCommandPrivateShapes(t *testing.T) {
	cases := []struct {
		cmd             string
		dialect         policy.Dialect
		private, custom bool
		want            string
	}{
		{"npm i left-pad", "", false, false, "npm:left-pad"},
		{`$env:NPM_CONFIG_REGISTRY = "https://x.example/"; npm i y`, policy.DialectPowerShell, true, true, "npm:y"},
		{`$env:NPM_CONFIG_REGISTRY="https://x.example/"; npm i y`, policy.DialectPowerShell, true, true, "npm:y"},
		{`${env:PIP_INDEX_URL} = "https://x.example/simple"; pip install y`, policy.DialectPowerShell, true, true, "pypi:y"},
		{`Set-Item env:NPM_CONFIG_REGISTRY https://x.example/; npm i y`, policy.DialectPowerShell, true, true, "npm:y"},
		{`Set-Item -Path env:GOPRIVATE -Value corp.example; go get corp.example/x`, policy.DialectPowerShell, true, true, "go:corp.example/x"},
		{"pip install -ihttps://x.example/simple y", "", true, true, "pypi:y"},
		{"pip install -fhttps://x.example/wheels y", "", true, true, "pypi:y"},
		{"pnpm add y --config.registry=https://x.example/", "", true, true, "npm:y"},
		{"pnpm add @corp/y --config.@corp:registry=https://x.example/", "", true, true, "npm:@corp/y"},
		{"pipx run --spec y app", "", false, false, "pypi:y"},
		{"pipx run --spec y --index-url https://x.example/simple app", "", true, true, "pypi:y"},
		{"npm config set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"npm set @corp:registry https://x.example/ && npm i @corp/y", "", true, true, "npm:@corp/y"},
		{"yarn config set npmRegistryServer https://x.example/ && yarn add y", "", true, true, "npm:y"},
		{"pip config set global.index-url https://x.example/simple && pip install y", "", true, true, "pypi:y"},
		{"python -m pip config set global.extra-index-url https://x.example/simple; pip install y", "", true, true, "pypi:y"},
		{"go env -w GOPRIVATE=corp.example && go get corp.example/x", "", true, true, "go:corp.example/x"},
		{"poetry source add corp https://x.example/simple && poetry add y", "", true, true, "pypi:y"},
		// Lane SEC-DEPS3 item 10.
		{"npm config --location project set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"npm config -L user set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"npm c set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"npm config edit && npm i y", "", true, true, "npm:y"},
		{"pip config edit && pip install y", "", true, true, "pypi:y"},
		{"pip config --user set global.index-url https://x.example/simple && pip install y", "", true, true, "pypi:y"},
		{"npm config --location project set fund false && npm i y", "", false, false, "npm:y"},
		// Workspace flags and unknown flags before the verb (fail private).
		{"npm config --workspace a set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"npm config -w a set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"pnpm config -w set registry https://x.example/ && pnpm add y", "", true, true, "npm:y"},
		{"npm config --some-new-flag v set registry https://x.example/ && npm i y", "", true, true, "npm:y"},
		{"npm config --workspace a set fund false && npm i y", "", false, false, "npm:y"},
		{"npm config get registry && npm i y", "", false, false, "npm:y"},
		{"pip config list && pip install y", "", false, false, "pypi:y"},
		{"npm i y && npm config set registry https://x.example/", "", false, false, "npm:y"},
		{"npm config set fund false && npm i y", "", false, false, "npm:y"},
		{"go env -w GOFLAGS=-mod=mod && go get example.com/x", "", false, false, "go:example.com/x"},
		{"GOFLAGS=-mod=mod go get example.com/x", "", false, false, "go:example.com/x"},
		{"CARGO_HOME=/tmp/c cargo add serde", "", true, false, "cargo:serde"},
		{"GOENV=/tmp/e go get example.com/x", "", true, false, "go:example.com/x"},
		{"export CARGO_HOME=/tmp/c && cargo add serde", "", true, false, "cargo:serde"},
		{"export NPM_CONFIG_REGISTRY=https://x.example/ && npm i y", "", true, true, "npm:y"},
	}
	for _, c := range cases {
		got := ParseInstalls(&policy.Event{Kind: policy.KindShellExec, Target: c.cmd, Dialect: c.dialect})
		if names(got) != c.want {
			t.Errorf("%q: specs %q, want %q", c.cmd, names(got), c.want)
			continue
		}
		for _, s := range got.Specs {
			if s.Private != c.private {
				t.Errorf("%q: %s private=%v, want %v", c.cmd, s.Name, s.Private, c.private)
			}
		}
		if got.CustomRegistry != c.custom {
			t.Errorf("%q: custom=%v, want %v", c.cmd, got.CustomRegistry, c.custom)
		}
	}
}
