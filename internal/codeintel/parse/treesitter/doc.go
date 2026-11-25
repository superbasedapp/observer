// Package treesitter implements a parse.Parser backed by tree-sitter
// grammars compiled to self-contained WASI modules and hosted under
// wazero. It is CGO-free (wazero is pure Go) and produces EXACT byte/line
// spans, so the languages it serves report ExactSpans=true and become
// body-collapse sources (ADR-0005), upgrading them from the heuristic
// fallback's approximate spans.
//
// All tree-sitter C-API use (which passes TSNode structs by value) lives
// INSIDE the wasm module (grammars/extract.c); the Go host only exchanges a
// flat pointer/length ABI with the module, so no struct marshalling crosses
// the boundary. The grammar set is DATA: each language is one embedded
// codeintel_<lang>.wasm.zst + one <lang>.scm query (regenerate with
// grammars/build.sh; see docs/codeintel/adding-a-language.md).
//
// # Embedded-grammar relief valve (W1, ADR-0006)
//
// Each .wasm statically links a copy of the tree-sitter core, so the raw
// grammar set would approach the ≤20MB/binary embed budget as more languages
// land. To keep breadth affordable, the embedded artifacts are zstd-compressed
// (grammars/*.wasm.zst, produced by grammars/build.sh) and decompressed
// IN-MEMORY at New() time, straight into wazero's CompileModule — no on-disk
// cache. zstd decompression (~GB/s, pure-Go klauspost/compress, CGO-free) is
// negligible next to the wasm→machine-code compile that New() already pays, so
// a decompressed-wasm cache would add race/invalidation/fail-open complexity to
// shave a cost that isn't the bottleneck. See docs/codeintel/decisions.md
// ADR-0006 for the full rationale (incl. why wazero's compilation cache, not a
// decompressed-wasm cache, is the right lever if startup ever needs speeding).
//
// It is a pure backend (CLAUDE.md anti-spaghetti rule 1 / imports_test.go):
// bytes in, codeintel.ParseResult out. No SQL, HTTP, fsnotify.
package treesitter
