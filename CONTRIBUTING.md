# Contributing to SuperBased Observer

Thanks for considering a contribution. This document covers how the
project is developed, how to set up a local build, and what we're
looking for in a pull request.

## Before you start

For anything beyond a small fix (typo, obvious bug, small doc
improvement), please open an issue or a
[Discussion](https://github.com/superbasedapp/observer/discussions)
first to align on approach before investing time in a large diff.
This avoids duplicate work and saves you a rewrite if the design
needs to go a different direction.

## How this project is developed

Day-to-day development happens on a private mainline; it interleaves
implementation work with operational and planning material that isn't
meant for a public history, so that full history isn't published. What
you see in this public repository is a sanitized snapshot taken at
each release. As of this writing, each new release snapshot is parented
on the previous public commit, so history accumulates from here
forward (earlier releases appeared as a single replaced commit; that
was a pipeline gap, since fixed).

External pull requests are reviewed publicly on GitHub like any other
project. When a PR is self-contained and touches only public-safe
paths, a maintainer can merge it **directly onto public `main`**, where
it stays; the release snapshot now parents on the public head, so a
direct-merged commit is carried forward, not overwritten. When a change
instead has to be integrated with work that lives only on the private
mainline, the maintainer folds it in there and it ships in the next
sanitized snapshot. Either way you're credited in `CHANGELOG.md` and the
release notes; the "How you get credit" section below spells out exactly
what shows up where.

We think this is worth stating plainly rather than leaving you to
infer it from a repository that otherwise looks like a normal
single-history project.

## How you get credit

Because the public repo is a sanitized snapshot authored by the release
pipeline (not a byte-for-byte copy of the private mainline), we want to
be upfront about exactly how your work gets attributed. We use a
three-tier ladder, in order of preference:

1. **Direct-merge (contributors graph).** When your PR is
   self-contained and touches only public-safe paths, a maintainer
   merges it **directly onto public `main`**. This is the *only* path
   that puts you on the repository's GitHub contributors graph: your
   commits land in the public history under your own name. We prefer
   this route whenever it's feasible, so keeping a PR focused and clear
   of private-only paths is the single best thing you can do to be
   credited this way.

2. **Co-authored-by (provenance trailer).** Some changes can't be
   merged directly: they touch paths that can't be public, or they
   have to be integrated with work that lives only on the private
   mainline. Those flow through the private mainline, and we record your
   authorship with a `Co-authored-by: Your Name <you@example.com>`
   trailer on the private commit that carries the change. Here's the
   honest limit of what that does **today**: the public repo receives a
   fresh snapshot commit (fixed author, generated message), so the
   trailer lives on the *private* commit and does **not** appear in the
   public history. It's durable provenance we keep, and it would surface
   publicly only if the project ever moves to a public day-to-day
   mainline. So for a change that takes this route, your guaranteed
   *public* credit today is the CHANGELOG line below, not a public
   avatar or a contributors-graph entry (only a direct-merge does that).

3. **CHANGELOG credit (always).** Regardless of which path your change
   takes, every external contribution gets a named credit line in
   `CHANGELOG.md` and the release notes. This is the guaranteed-visible
   floor: you're credited even when neither of the routes above
   applies.

If you'd like to be credited under a specific name/email or a GitHub
handle, say so in the PR and we'll match it. The maintainer-side
mechanics for all three tiers live in the maintainers' internal release
runbook, so this policy is applied consistently rather than
case-by-case.

## Development setup

Requirements: **Go 1.27+**. Observer uses `modernc.org/sqlite` (pure
Go, no CGO). No C toolchain needed.

```bash
git clone https://github.com/superbasedapp/observer.git
cd observer
make build     # go build -o bin/observer ./cmd/observer
make test      # go test -race ./...
make lint      # golangci-lint run
make fmt       # gofmt -w .
make all       # fmt + vet + lint + test + build
```

The dashboard frontend lives in `web/` (a separate npm project). If
you touch anything under `web/`, rebuild the embedded assets before
building the Go binary:

```bash
make web-install   # first time only
make web-build     # regenerates internal/intelligence/dashboard/webapp/dist
make build
```

## Code conventions

- **Conventional commits**: `feat:`, `fix:`, `docs:`, `test:`,
  `chore:`, `refactor:`, `perf:`.
- **Table-driven tests** are the expected style for new logic.
- **Every exported function gets a doc comment.**
- Errors are wrapped with context, e.g.
  `fmt.Errorf("store.InsertAction: %w", err)`.
- No `panic()` outside `main.go`; no `log.Fatal()` / `os.Exit()`
  outside `main.go` either.
- Don't hardcode paths; use `os.UserHomeDir()`, `os.UserConfigDir()`,
  `filepath.Join()`.

## What we especially welcome

- **New AI-tool adapters.** Observer supports 26 coding tools today;
  if yours isn't one of them, this is the highest-leverage
  contribution you can make. Look at an existing adapter under
  `internal/adapter/` for the shape.
- **Sanitized test fixtures**: anonymized real session logs that
  exercise an edge case we don't have coverage for.
- **Windows / WSL fixes.** Cross-platform path handling and
  cross-OS hook bridging are an ongoing source of edge cases.
- **Pricing-table updates**, with a source (a provider pricing page
  or changelog entry) linked in the PR description.
- **Documentation and dashboard improvements.**

## Pull request expectations

- `make test` and `make lint` pass locally.
- Diffs are focused: one logical change per PR. Large refactors are
  easier to review (and land) if you flag them in an issue first.
- No secrets, real file paths from your own machine, or private data
  in the diff or in any test fixtures.
- New behavior gets a test. Bug fixes ideally include a regression
  test.

We'll review as promptly as we can and will always leave a comment
even if the answer is "not right now"; silence isn't the intended
experience here.
