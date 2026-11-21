// Package secdockerfile is the security pillar's native Dockerfile and
// base-image rules, S-750 to S-755 (OS and CI vulnerability scanning plan
// docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md sections
// 4.1 to 4.3). It is the container_config row of internal/secverify's
// detector table, and the node runs it on the Dockerfiles a commit
// changes (the quick scan) and when it rechecks an open finding.
//
// One closed rule table, one test case per row:
//
//	S-750 FROM with no tag or with :latest (a moving target)
//	S-751 FROM with a tag but no @sha256: digest (the tag can move)
//	S-752 FROM a base whose distribution release or language runtime is
//	      past end of life (high) or within 90 days of it (medium), read
//	      from the compiled end-of-life table in eol.go
//	S-753 RUN installs OS packages with no version (flag only)
//	S-754 RUN installs language packages with no version (flag only)
//	S-755 RUN pipes remote content into an interpreter
//
// S-753 to S-755 are decided by internal/secshellrisk, the one owner of
// those three classifications (the CI workflow rules S-780 to S-782 ask
// it the same questions); this package only finds the RUN scripts.
//
// What a FROM line is, as an ordered parse: FROM [--flag=...] <ref>
// [AS <name>]. A ref that names an earlier stage is not an image, scratch
// is not an image, and ${VAR} / $VAR are substituted only from ARG lines
// with a literal default before the first FROM (the global build
// arguments). A FROM whose image still names a variable is not checked
// and is counted in Report.UncheckedFrom, never read as clean. Parser
// directives (# escape=), line continuations, comments, heredocs
// (RUN <<EOF) and JSON-form RUN ["sh", "-c", "..."] are handled; RUN
// scripts are classified in the shell a SHELL instruction set (POSIX
// unless it named pwsh, powershell or cmd).
//
// The input is untrusted repository text: the parser reads at most
// MaxDockerfileBytes, findings carry a rule, a line and fixed text (the
// rule's message and, for S-752, the product, cycle and date from the
// compiled table), never repository text, and nothing is executed.
//
// The package is pure: no SQL, no HTTP, no process, no filesystem
// (imports_test.go).
package secdockerfile
