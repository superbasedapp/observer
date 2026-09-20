BINARY := observer
PKG    := github.com/marmutapp/superbased-observer
CMD    := ./cmd/observer

GO         ?= go
GOFLAGS    ?=
BUILD_DIR  := bin
COVER_OUT  := coverage.txt

WEB_DIR        := web
WEB_DIST       := $(WEB_DIR)/dist
WEB_EMBED_DIST := internal/intelligence/dashboard/webapp/dist

.PHONY: all build test test-race test-invariant render-module-fixtures lint fmt vet tidy clean run cover \
        build-observer build-antigravity-bridge build-node-inspection install-node-inspection \
        web-install web-dev web-build web-clean \
        plugins-build verify-plugins-build \
        taxonomy-build verify-taxonomy-build verify-taxonomy-ts \
        config-schema-build verify-config-schema \
        taxonomy-migration-build verify-taxonomy-migration \
        assistant-migration-build verify-assistant-migration \
        reasoning-migration-build verify-reasoning-migration \
        verify-webcloud-dist

# Targets whose INPUTS are private-only paths (cmd/observer-org*,
# cmd/observer-edge, web2/, deploy/, docs/, website/, tools/toolcountgen)
# live in Makefile.private, which is excluded from the public snapshot
# via PRIVATE_ONLY_FILES in scripts/release.sh. `-include` (leading dash)
# tolerates its absence, so the public tree's `make build` builds exactly
# what README.md documents: bin/observer + the antigravity bridge.
# Private tree behaviour is unchanged.
PRIVATE_BUILD_TARGETS :=
-include Makefile.private

# `-include` fails SILENTLY, so a private-tree accident (rename, bad
# merge) would quietly stop `make build` producing bin/observer-org.
# CLAUDE.md is in PRIVATE_ONLY_PATHS and is physically removed from the
# public staging worktree, so this guard can only fire here.
ifeq ($(wildcard Makefile.private),)
ifneq ($(wildcard CLAUDE.md),)
$(error Makefile.private is missing on the private tree — restore it; \
        the Enterprise build targets live there)
endif
endif

all: fmt vet lint test build

build: build-observer build-antigravity-bridge $(PRIVATE_BUILD_TARGETS)

build-observer:
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)

# Cross-compile the Antigravity Windows-side gRPC bridge. Used by
# observer-on-WSL2 to reach Antigravity's local language_server,
# which binds to Windows-side 127.0.0.1 and isn't reachable from
# inside a WSL distro under default networking. The bridge is a
# tiny Go binary (~8 MB) that runs Windows-side under powershell.exe,
# does process discovery + the gRPC call, and returns Markdown via
# stdout. Skipped silently on non-Linux build hosts where it'd
# never be invoked.
build-antigravity-bridge:
	@mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/antigravity-bridge.exe ./cmd/antigravity-bridge

# observer-node-inspection is a DEPLOY-ONLY artifact (docs/security.md
# ledger row INT-1): a root-owned, read-only Linux process-identity helper
# (cmd/observer-node-inspection/doc.go) that the managed node-intervention
# controller dials over a Unix socket. It is deliberately absent from
# `build` above and from every npm/PyPI distribution channel — it is never
# something an ordinary `observer` install needs, and shipping a root-
# privileged helper through a package registry that auto-updates is a
# different risk posture than shipping bin/observer. Build and install it
# explicitly on a Linux host you administer; see
# deploy/supervisor/README.md and deploy/supervisor/observer-node-inspection@.service.
build-node-inspection:
	@mkdir -p $(BUILD_DIR)
ifneq ($(shell uname -s),Linux)
	$(error build-node-inspection: observer-node-inspection is Linux-only (cross-compile explicitly with GOOS=linux GOARCH=... $(GO) build if you must build it elsewhere))
endif
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/observer-node-inspection ./cmd/observer-node-inspection

# install-node-inspection documents the root install; it does NOT perform
# it. Installing a root-privileged helper is a deliberate, once-per-host
# operator action — never something `make` does silently as root.
install-node-inspection: build-node-inspection
	@echo "observer-node-inspection is NOT installed automatically by this target."
	@echo "To install it by hand on the target Linux host:"
	@echo "  sudo install -o root -g root -m 0755 $(BUILD_DIR)/observer-node-inspection /usr/local/bin/observer-node-inspection"
	@echo "  sudo cp deploy/supervisor/observer-node-inspection@.service /etc/systemd/system/"
	@echo "  sudo systemctl daemon-reload"
	@echo "  sudo systemctl enable --now observer-node-inspection@<enrolled-developer-uid>.service"
	@echo "See deploy/supervisor/README.md for the full explanation, the socket/permission"
	@echo "contract, and the hardening notes."

run: build
	$(BUILD_DIR)/$(BINARY)

test:
	$(GO) test $(GOFLAGS) ./...

# -timeout 40m matches ci.yml's test step. Without it the local run
# inherits go test's 10m per-binary default, and cmd/observer already
# measures 593s under -race on a developer box (2026-07-26) — ~7s of
# headroom, so a busy machine fails RED with `panic: test timed out`
# and nothing actually broken. The release checklist calls for a full
# race suite, which is exactly when that false failure would land.
test-race:
	$(GO) test $(GOFLAGS) -race -timeout 40m ./...

# Single-user-local invariant net: seeds a fixed corpus, drives the
# dashboard's headline endpoints, and diffs the canonicalised JSON
# against goldens captured before the org-mode (Teams) code landed. A
# non-empty diff means an additive change leaked into a solo-local
# response — the one thing the Teams feature must never do. Regenerate
# the goldens intentionally with `go test ./tests/invariant -update`.
test-invariant:
	$(GO) test $(GOFLAGS) ./tests/invariant/...

# Regenerates the OpenTofu module fixtures the render tests pin byte-for-
# byte: deploy/modules/{compact,appliance}/{azure,aws}/<layer>/tests/
# fixtures/<id>.tfvars, one file per CONTRACT.md fixture row per cloud
# (RA-0/RA-1a/RA-1b compact; RA-2/RA-2-selfhosted/RA-3/RA-3-selfhosted
# appliance), each the SAME bytes `observer-org deploy plan` renders for
# that answer set. `tofu test` reads them; TestModuleFixturesMatchRender
# fails on any drift and names this target. Run it after a deliberate
# change to the render or the catalog, then commit the files.
render-module-fixtures:
	UPDATE_FIXTURES=1 $(GO) test $(GOFLAGS) ./deploy/catalog/render/ -run TestModuleFixturesMatchRender

cover:
	$(GO) test $(GOFLAGS) -race -coverprofile=$(COVER_OUT) -covermode=atomic ./...
	$(GO) tool cover -func=$(COVER_OUT) | tail -1

# golangci-lint is deliberately NOT a `go tool` dependency: it pins its
# own Go version and must be built with the tree's Go (CI uses
# install-mode: goinstall for exactly that reason — see ci.yml). Resolve
# it from PATH first, then $(GOPATH)/bin, which is where `go install`
# puts it and which is not on PATH in every shell.
#
# A missing linter FAILS. It used to `exit 0`, which made every local
# `make lint` a green that meant "I didn't look" — the binary lives in
# $(GOPATH)/bin here and was never on PATH, so the guard fired every
# time and no local lint has ever actually run. CI was unaffected (it
# calls golangci-lint-action, not this target).
GOLANGCI_LINT ?= $(shell command -v golangci-lint 2>/dev/null || echo $(shell $(GO) env GOPATH)/bin/golangci-lint)

lint:
	@test -x "$(GOLANGCI_LINT)" || { echo "golangci-lint not found at '$(GOLANGCI_LINT)' — install it (https://golangci-lint.run/, install-mode goinstall) or pass GOLANGCI_LINT=/path/to/golangci-lint"; exit 1; }
	$(GOLANGCI_LINT) run ./...

fmt:
	$(GO) tool gofumpt -w .

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BUILD_DIR) $(COVER_OUT)

# ---------------------------------------------------------------
# Web (redesigned React/Vite dashboard, mounted at /v2/).
#
# `make build` stays pure-Go and does NOT require Node. The built
# artifacts at $(WEB_EMBED_DIST) are committed; regenerate them
# via `make web-build` whenever you touch web/ sources, before
# committing.
# ---------------------------------------------------------------
web-install:
	npm ci

web-dev:
	cd $(WEB_DIR) && npm run dev

web-build:
	npm ci --silent
	cd $(WEB_DIR) && npm run build
	@rm -rf $(WEB_EMBED_DIST)
	@mkdir -p $(WEB_EMBED_DIST)
	@cp -R $(WEB_DIST)/. $(WEB_EMBED_DIST)/
	@echo "web: rebuilt $(WEB_EMBED_DIST) from $(WEB_DIST)"

web-clean:
	rm -rf $(WEB_DIST) $(WEB_DIR)/node_modules

# ---------------------------------------------------------------
# In-tool plugin manifests (plugins/). plugins/plugingen RUNS the real
# `observer init` registrars — internal/mcp's Registrar and
# internal/hook's Registry — against a throwaway sandbox HOME and
# transposes exactly what they wrote into each surface's own packaging
# format: a Claude Code plugin + marketplace catalog, and the static
# Cursor one-click MCP install deeplink. Run after any change to those
# registrars (a new hook event, a changed MCP argument) or after a
# version stamp, so plugin wiring can never fork from init wiring —
# see docs/plans/adapter-plugins-distribution-plan-2026-07-31.md §3.
# ---------------------------------------------------------------
plugins-build:
	$(GO) run ./plugins/plugingen

# Drift gate for the plugin manifests: copies plugins/ into a scratch
# dir, regenerates THERE and diffs against the committed files. Fails if
# a registrar moved without a matching `make plugins-build` + commit.
# Never mutates the working tree. Mirrors verify-track-build's
# build-into-temp pattern.
verify-plugins-build:
	@scripts/verify-plugins-build.sh

# ---------------------------------------------------------------
# Dashboard action taxonomy (shared/lib/actiontax.gen.*). web/taxgen
# mirrors internal/tooltax — the one owner of the cross-adapter tool/MCP
# taxonomy — into the shape shared/lib/actions.ts reads: the canonical
# category list, the action-type → {category, label} registry, and the
# MCP name-parse rules (actiontax.gen.json), the ActionCategory literal
# union (actiontax.gen.ts), and the parity vectors the TypeScript gate
# runs (actiontax.vectors.gen.json). Run after any change to the tooltax
# action-type registry, categories or MCP constants, so the dashboard can
# never fork its own taxonomy again — see
# docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §1/§7.
# ---------------------------------------------------------------
taxonomy-build:
	$(GO) run ./web/taxgen

# Drift gate for the generated taxonomy: regenerates into a scratch dir
# and byte-diffs each artifact against the committed one. Fails if
# tooltax moved without a matching `make taxonomy-build` + commit. Never
# mutates the working tree. Mirrors verify-plugins-build's
# build-into-temp pattern.
verify-taxonomy-build:
	@scripts/verify-taxonomy-build.sh

# Cross-language parity gate: compiles the REAL shared/lib/actions.ts
# (esbuild, from web/node_modules) and runs it against the generated
# vectors, whose expectations come from tooltax.MCPIdentity. Separate
# target from verify-taxonomy-build because it needs node + web deps,
# while the drift gate needs only Go. Both run in ci.yml's
# taxonomy-build-drift job.
verify-taxonomy-ts:
	@scripts/verify-taxonomy-ts.sh

# ---------------------------------------------------------------
# Dashboard config schema (internal/config/schema/schema.gen.json +
# web/src/lib/configschema.gen.ts). web/cfgschema serializes
# internal/configschema — the one owner of config.Config's structure +
# classification (tier / restart class / Settings section / prominence)
# — plus every field's Go doc comment, into the artifact GET
# /api/config/schema serves (go:embed'd, so it always describes THIS
# daemon's build) and the ConfigKeyPath literal union that makes a
# removed key a tsc error. Run after any change to a config struct or
# to internal/configschema/annotations.go — see
# docs/plans/dashboard-config-management-plan-2026-08-28.md §1.
# ---------------------------------------------------------------
config-schema-build:
	$(GO) run ./web/cfgschema

# Drift gate for the generated config schema: regenerates into a scratch
# dir and byte-diffs both artifacts against the committed ones. Fails if
# a config struct or the annotation table moved without a matching
# `make config-schema-build` + commit. Never mutates the working tree.
# Mirrors verify-taxonomy-build's build-into-temp pattern.
verify-config-schema:
	@scripts/verify-config-schema-build.sh

# ---------------------------------------------------------------
# webcloud portal dist drift gate (gap 3.7). cmd/observer-cloud go:embed's
# the committed webcloud/dist (webcloud/embed.go: //go:embed all:dist) — a
# src/ change that never got rebuilt would ship a stale portal silently.
# Never mutates the working tree; builds into a scratch dir and diffs
# against the committed dist. Needs webcloud/node_modules (npm workspace:
# run `npm ci` from the repo root, or from webcloud/ — both resolve against
# the root package-lock.json).
# ---------------------------------------------------------------
verify-webcloud-dist:
	@scripts/verify-webcloud-dist.sh

# ---------------------------------------------------------------
# Historical-data repair for the same taxonomy (internal/db/migrations/
# 077_tooltax_action_type_backfill.sql). internal/db/taxbackfillgen
# transposes the internal/tooltax table into one
# `UPDATE actions SET action_type = ... WHERE action_type = 'unknown'`
# per (tool, action type), so the rows already on disk get the categories
# their adapters only started emitting in WP-T3 — the plan's §3
# requirement that the repair SQL be SOURCED FROM the table rather than
# transcribed by hand.
# ---------------------------------------------------------------
taxonomy-migration-build:
	$(GO) run ./internal/db/taxbackfillgen

# Drift gate for the generated migration: regenerates into a scratch dir
# and byte-diffs against the committed file. Fails on a hand-edit, or on
# a tooltax row that moved without a matching
# `make taxonomy-migration-build` + commit. Never mutates the working
# tree. Mirrors verify-taxonomy-build's build-into-temp pattern.
verify-taxonomy-migration:
	@scripts/verify-taxonomy-migration.sh

# ---------------------------------------------------------------
# Historical-data repair for the assistant-text action-type relabel
# (internal/db/migrations/078_assistant_text_action_type_relabel.sql).
# internal/db/asstbackfillgen transposes the `<tool>.assistant_text`
# emit-site inventory into one
# `UPDATE actions SET action_type = 'assistant_message'
#   WHERE tool = ... AND action_type = 'task_complete' AND raw_tool_name
#   IN (...)` per tool, so the rows already on disk get the type the
# adapters emit after the WP-T6/B2a sweep.
#
# SIBLING of taxonomy-migration-build, deliberately not folded into it:
# 077 is sourced from internal/tooltax and is unknown-only (it can only
# move rows OUT of the unknown bucket), while 078 rewrites rows an
# adapter already classified. Regenerating 077 must never absorb 078's
# rewrite, so the generators, artifacts and gates stay separate.
# ---------------------------------------------------------------
assistant-migration-build:
	$(GO) run ./internal/db/asstbackfillgen

# Drift gate for the generated relabel migration: regenerates into a
# scratch dir and byte-diffs against the committed file. Fails on a
# hand-edit, or on an emit site that moved without a matching
# `make assistant-migration-build` + commit. Never mutates the working
# tree. Mirrors verify-taxonomy-migration's build-into-temp pattern.
verify-assistant-migration:
	@scripts/verify-assistant-migration.sh

# ---------------------------------------------------------------
# Historical-data repair for the B3 reasoning convergence
# (internal/db/migrations/079_reasoning_row_convergence.sql).
# internal/db/reasoninggen transposes the retired codex reasoning emit
# site's PLACEHOLDER shapes — `(reasoning)` and
# `(encrypted reasoning, N bytes)` — into a tool-scoped DELETE preceded
# by the retention.go dependency protocol, plus the cursor
# `cursor.assistant_response` pair rewrite that 078's `.assistant_text`
# scoping could not reach.
#
# SIBLING of assistant-migration-build, deliberately not folded into it:
# 078 REWRITES rows, 079 DELETES them. A delete is a strictly more
# dangerous mode and gets its own generator, its own artifact and its own
# gate, so one regeneration mistake can never turn a relabel into a
# deletion.
reasoning-migration-build:
	$(GO) run ./internal/db/reasoninggen

# Drift gate for the generated convergence migration: regenerates into a
# scratch dir and byte-diffs against the committed file. Fails on a
# hand-edit, or on a producer shape / dependency table that moved without
# a matching `make reasoning-migration-build` + commit. Never mutates the
# working tree.
verify-reasoning-migration:
	@scripts/verify-reasoning-migration.sh
