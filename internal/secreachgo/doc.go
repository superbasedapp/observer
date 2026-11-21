// Package secreachgo is the pure core of the Go symbol-level reachability
// check (OS and CI vulnerability scanning plan section 14.5 item 3b, spike
// RG-0): everything the scan child does around one govulncheck binary-mode
// run except the run itself (internal/secreachgovuln) and the file system.
//
//   - Inspect reads an executable through an io.ReaderAt with the standard
//     library's debug/elf, debug/pe and debug/macho and reports whether it
//     keeps what govulncheck needs: a symbol table naming the Go function
//     symbol and the Go line table. A stripped binary is reported (RG-0
//     G2: govulncheck would otherwise substitute every known vulnerable
//     symbol and print function-level traces for an advisory nothing calls)
//     and never run;
//   - ParseRecord reads one OSV record's Go affected entries: per module,
//     the listed packages and their symbols;
//   - ParseStream reads govulncheck's -format json stream into the first
//     frame of every finding;
//   - Verdicts groups a binary's matched advisories by alias (one flaw),
//     builds each record's facts and decides them through
//     internal/secreach's table (secreach.DecideSymbol), then combines a
//     group: called over no claim over not called, and a record that
//     lists no imports (a GitHub advisory in the Go export) adds nothing;
//   - source mode, 3b-src (source.go): ParseScannerOutput reads one
//     go.mod's osv-scanner --call-analysis=go JSON, SourceVerdicts decides
//     its groups through the same table (osv-scanner's own "called" is
//     never used as is: a record listing no symbols, or a whole package
//     beside symbols, gets no claim), and ClassifyRun says why a run
//     decided nothing (timed out, out of memory, no toolchain, a go.mod
//     needing a newer Go, a module not downloaded, a failed analysis).
//
// It is PURE (CLAUDE.md "Module Boundaries" rule 1, imports_test.go): no
// os, os/exec, net/http, database/sql or fsnotify; the binary's bytes, the
// records and the stream are handed in.
package secreachgo
