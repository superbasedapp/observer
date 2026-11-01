package invariant

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// dockerignore_test.go pins the repo-root .dockerignore, the build context of
// every root-context image (org, mcpgw, cloud, devnode, node, edge, gateway).
//
// T-936 (found by the 2026-10-21 demo roll): the demo box builds its images
// from ~/sbo-demo, which is also its running kit, and every one of those
// Dockerfiles has a `COPY . .` build stage. Before this file, a build from a
// kit sent the kit's state/ (generated passwords, rendered config) and .env
// (operator secrets) into the build stage and the builder's cache, and
// deploy/embed.go's `all:observer-org/production all:modules` would go:embed
// a filled production .env, secrets/ or a local tofu state into the
// observer-org binary itself. And once Caddy had made state/router/caddy
// root 0700 (direct public mode), `deploy.sh build` failed outright with
// "permission denied".
//
// The matcher below follows moby/patternmatcher (what BuildKit uses): the
// LAST matching pattern wins, a pattern also matches when it matches any
// parent directory, `**` spans any number of directories, `*` and `?` stay
// inside one path element.

// dockerignorePattern is one parsed line of a .dockerignore.
type dockerignorePattern struct {
	raw       string
	exception bool
	re        *regexp.Regexp
}

// loadRootDockerignore parses the repo-root .dockerignore.
func loadRootDockerignore(t *testing.T) []dockerignorePattern {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), ".dockerignore"))
	if err != nil {
		t.Fatalf("read .dockerignore: %v", err)
	}
	var out []dockerignorePattern
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := dockerignorePattern{raw: line}
		if strings.HasPrefix(line, "!") {
			p.exception = true
			line = strings.TrimSpace(line[1:])
		}
		line = path.Clean(line)
		if len(line) > 1 && line[0] == '/' {
			line = line[1:]
		}
		p.re = regexp.MustCompile(dockerignoreRegexp(line))
		out = append(out, p)
	}
	if len(out) == 0 {
		t.Fatal(".dockerignore has no patterns")
	}
	return out
}

// dockerignoreRegexp converts one cleaned pattern the way patternmatcher does.
func dockerignoreRegexp(p string) string {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				i++
				if i+1 < len(p) && p[i+1] == '/' {
					i++
				}
				if i+1 >= len(p) {
					b.WriteString(".*")
				} else {
					b.WriteString("(.*/)?")
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	return b.String()
}

// excludedFromContext reports whether file (slash-separated, relative to the
// repo root) is left out of the build context.
func excludedFromContext(patterns []dockerignorePattern, file string) bool {
	file = path.Clean(file)
	dirs := strings.Split(path.Dir(file), "/")
	matched := false
	for _, p := range patterns {
		if p.exception != matched {
			continue
		}
		m := p.re.MatchString(file)
		if !m && path.Dir(file) != "." {
			for i := range dirs {
				if p.re.MatchString(strings.Join(dirs[:i+1], "/")) {
					m = true
					break
				}
			}
		}
		if m {
			matched = !p.exception
		}
	}
	return matched
}

// TestDockerignoreExceptionsHaveNoWildcards: one wildcard `!` pattern makes
// BuildKit walk into every excluded directory to look for re-included files,
// so an excluded directory the builder cannot read (state/router/caddy, root
// 0700) still fails the build. Measured on docker 28.1.1 / buildx 0.23.0:
// `state` excluded plus `!docs/*.md` (the pattern this file used to carry)
// fails with "permission denied"; the same with plain-path exceptions builds.
func TestDockerignoreExceptionsHaveNoWildcards(t *testing.T) {
	for _, p := range loadRootDockerignore(t) {
		if p.exception && strings.ContainsAny(p.raw[1:], `*?[\`) {
			t.Errorf(".dockerignore exception %q has a wildcard: BuildKit then walks every excluded directory and an unreadable one (the demo box's root 0700 state/router/caddy) fails the build. Name the re-included paths one by one.", p.raw)
		}
	}
}

// TestDockerignoreExcludesKitStateAndSecrets: the runtime state and secret
// paths of every deploy kit in the tree stay out of the build context.
func TestDockerignoreExcludesKitStateAndSecrets(t *testing.T) {
	patterns := loadRootDockerignore(t)
	for _, f := range []string{
		// demo box kit (deploy/demo-box/deploy.sh: STATE, ENV_FILE)
		"deploy/demo-box/state/generated.env",
		"deploy/demo-box/state/compose.env",
		"deploy/demo-box/state/config.toml",
		"deploy/demo-box/state/.deploy.lock",
		"deploy/demo-box/state/cloud/edge_secret",
		"deploy/demo-box/state/router/caddy/certificates/x.key",
		"deploy/demo-box/.env",
		"deploy/demo-box/.env.bak",
		"deploy/demo-box/.env.local",
		// cloud box kit (cloud-box.sh: the SBCI_BOX_STATE_DIR default)
		"deploy/cloud-box/state/api.env",
		"deploy/cloud-box/state/pg_admin_pw",
		// org compose kits: keygen.sh's .env, the production .env and the
		// secrets/ dir its compose bind-mounts (both go:embedded otherwise)
		"deploy/observer-org/.env",
		"deploy/observer-org/production/.env",
		"deploy/observer-org/production/secrets/session.key",
		"deploy/observer-org/production/secrets/gateway.token",
		// Agent Access companion and gateway kits
		"deploy/observer-mcpgw/.env",
		"deploy/observer-gateway/config/config.toml",
		// any other .env, including the repo root's
		".env",
		".env.local",
		"examples/copilot-harness/.env",
		// local OpenTofu state, provider cache and filled tfvars
		"deploy/modules/compact/azure/app/terraform.tfstate",
		"deploy/modules/compact/azure/app/terraform.tfstate.backup",
		"deploy/modules/compact/azure/app/terraform.tfvars",
		"deploy/modules/appliance/aws/data/prod.auto.tfvars",
		"deploy/modules/compact/azure/app/.terraform/providers/p",
		"deploy/ops/azure-vm-watchdog/sbdemo.tfvars",
		"deploy/ops/azure-vm-watchdog/terraform.tfstate",
	} {
		if !excludedFromContext(patterns, f) {
			t.Errorf("%s is in the docker build context: a `COPY . .` build stage (and, under deploy/observer-org/production or deploy/modules, the observer-org go:embed) would carry it. Exclude it in .dockerignore.", f)
		}
	}
}

// TestDockerignoreKeepsBuildInputs: the exclusions do not reach what an image
// build reads.
func TestDockerignoreKeepsBuildInputs(t *testing.T) {
	skipInPublicTree(t, repoRoot(t), "docs/embed.go and the org image build inputs")
	patterns := loadRootDockerignore(t)
	keep := []string{
		"go.mod",
		"go.sum",
		"cmd/observer-org/main.go",
		"internal/orgserver/server.go",
		"scripts/sync-web-embed.sh",
		"package.json",
		"web/package.json",
		"web2/package.json",
		"web2/src/main.tsx",
		"shared/styles/tokens.css",
		// go:embedded by deploy/embed.go and shipped by `deploy export`
		"deploy/observer-org/production/.env.example",
		"deploy/observer-org/production/docker-compose.yaml",
		"deploy/observer-org/production/config.production.toml",
		"deploy/supervisor/README.md",
		"deploy/modules/compact/azure/app/main.tf",
		"deploy/modules/compact/azure/app/.terraform.lock.hcl",
		"deploy/modules/compact/azure/app/tests/fixtures/RA-0.tfvars",
		"deploy/modules/_shared/aws/secrets/main.tf",
		"deploy/observer-devnode/entrypoint.sh",
		"deploy/demo-box/deploy.sh",
		"docs/embed.go",
	}
	keep = append(keep, docsEmbedFiles(t)...)
	for _, f := range keep {
		if excludedFromContext(patterns, f) {
			t.Errorf("%s is excluded from the docker build context, but an image build reads it", f)
		}
	}
	// Spot checks that the matcher reads the file the way BuildKit does.
	for _, f := range []string{"web/src/main.tsx", "docs/plans/x.md", "docs/README.md", "web2/node_modules/a/b.js", "marketing/x"} {
		if !excludedFromContext(patterns, f) {
			t.Errorf("matcher self-check: %s should be excluded by the existing rules", f)
		}
	}
}

// docsEmbedFiles returns the files docs/embed.go's go:embed line names.
func docsEmbedFiles(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "embed.go"))
	if err != nil {
		t.Fatalf("read docs/embed.go: %v", err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "//go:embed "); ok {
			for _, f := range strings.Fields(rest) {
				out = append(out, "docs/"+f)
			}
		}
	}
	if len(out) == 0 {
		t.Fatal("docs/embed.go has no //go:embed line")
	}
	return out
}

// TestDockerignoreKeepsTrackedEmbedRoots: every tracked file under the
// observer-org go:embed roots is in the context, so a working-tree image
// embeds what `git archive` would. The one documented gap: the OpenTofu
// test-bundle .env fixtures under deploy/modules/**/tests/ (the `**/.env`
// rule takes them; `observer-org deploy export` prunes tests/ anyway).
func TestDockerignoreKeepsTrackedEmbedRoots(t *testing.T) {
	root := repoRoot(t)
	skipInPublicTree(t, root, "the observer-org go:embed roots under deploy/")
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	out, err := exec.Command("git", "-C", root, "ls-files", "--",
		"deploy/observer-org/production", "deploy/supervisor", "deploy/modules", "deploy/catalog").Output()
	if err != nil {
		t.Skipf("not a git checkout (%v)", err)
	}
	patterns := loadRootDockerignore(t)
	seen := 0
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" {
			continue
		}
		seen++
		if strings.Contains(f, "/tests/") && path.Base(f) == ".env" {
			continue
		}
		if excludedFromContext(patterns, f) {
			t.Errorf("tracked %s is excluded from the docker build context; a working-tree observer-org image would embed less than a release build", f)
		}
	}
	if seen == 0 {
		t.Fatal("git ls-files found nothing under the embed roots; the roots moved, update this test")
	}
}
