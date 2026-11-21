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

import (
	"bytes"
	"context"
	"embed"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse"
	"github.com/marmutapp/superbased-observer/internal/codeintel/parse/complexity"
)

// grammarFS holds the zstd-compressed grammar modules and their co-located
// .scm queries. The .wasm.zst blobs are decompressed in-memory at New() time
// (see the package doc / ADR-0006); the raw .wasm is build-output only and is
// gitignored, never embedded.
//
//go:embed grammars/*.wasm.zst grammars/*.scm
var grammarFS embed.FS

// maxExcerpt bounds every excerpt this backend emits (signatures, import /
// call raw text). Like the other backends, it never stores a body.
const maxExcerpt = 500

// langSpec names the embedded artifacts for one language. wasmFile (a
// zstd-compressed .wasm.zst) and queryFile are paths within grammarFS.
type langSpec struct {
	lang      codeintel.Language
	wasmFile  string
	queryFile string
}

// specs is the static served-language table — the single source of truth
// for which languages this backend can serve and where their artifacts
// live. Adding a language adds a row here plus the two embedded files
// (data, not code).
var specs = []langSpec{
	{parse.LangRust, "grammars/codeintel_rust.wasm.zst", "grammars/rust.scm"},
	{parse.LangTypeScript, "grammars/codeintel_typescript.wasm.zst", "grammars/typescript.scm"},
	{parse.LangTSX, "grammars/codeintel_tsx.wasm.zst", "grammars/tsx.scm"},
	{parse.LangPython, "grammars/codeintel_python.wasm.zst", "grammars/python.scm"},
	{parse.LangJavaScript, "grammars/codeintel_javascript.wasm.zst", "grammars/javascript.scm"},
	{parse.LangJSX, "grammars/codeintel_javascript.wasm.zst", "grammars/javascript.scm"},
	{parse.LangJava, "grammars/codeintel_java.wasm.zst", "grammars/java.scm"},
	{parse.LangC, "grammars/codeintel_c.wasm.zst", "grammars/c.scm"},
	{parse.LangCPP, "grammars/codeintel_cpp.wasm.zst", "grammars/cpp.scm"},
	{parse.LangCSharp, "grammars/codeintel_csharp.wasm.zst", "grammars/csharp.scm"},
	{parse.LangRuby, "grammars/codeintel_ruby.wasm.zst", "grammars/ruby.scm"},
	{parse.LangPHP, "grammars/codeintel_php.wasm.zst", "grammars/php.scm"},
	{parse.LangKotlin, "grammars/codeintel_kotlin.wasm.zst", "grammars/kotlin.scm"},
	{parse.LangSwift, "grammars/codeintel_swift.wasm.zst", "grammars/swift.scm"},
	{parse.LangScala, "grammars/codeintel_scala.wasm.zst", "grammars/scala.scm"},
	{parse.LangBash, "grammars/codeintel_bash.wasm.zst", "grammars/bash.scm"},
	{parse.LangLua, "grammars/codeintel_lua.wasm.zst", "grammars/lua.scm"},
}

// servedCapability is what every successfully-compiled language reports:
// full extraction with EXACT spans (the whole point of this backend).
var servedCapability = codeintel.LanguageCapability{
	Symbols:    true,
	ExactSpans: true,
	Imports:    true,
	Calls:      true,
}

// langModule is a compiled grammar module plus its query bytes and a pool
// of reusable instances (a wazero instance is single-threaded; the pool
// gives each concurrent Parse its own).
type langModule struct {
	compiled api.Closer // wazero.CompiledModule
	query    []byte
	// cquery is the language's decision query generated from
	// parse/complexity's rule table (nil when the language has no rows).
	// It runs as a second pass over the same instance and only feeds
	// Node.Complexity.
	cquery []byte
	// free is a BOUNDED free-list of reusable instances (SR27-A2). It
	// replaced a sync.Pool: wazero links every instance into its runtime's
	// module list, so an instance the pool dropped at GC was never closed
	// and its linear memory stayed reachable - memory grew without bound
	// over an index pass. Every instance is now either parked here or
	// closed.
	free    chan *instance
	newInst func() *instance
}

// Resource bounds for one parse (security review 2026-09-27, SR27-A1). A
// hostile source file (e.g. 2 MiB of "(") drives tree-sitter's error
// recovery super-linearly: measured 15 s for 64 KiB and still running after
// 8.5 min / 1.8 GB for 2 MiB, with the caller's deadline ignored because the
// runtime never checked it. The runtime is now built to abort a call when its
// context ends, each Parse carries its own deadline, and the guest's linear
// memory is capped.
const (
	// parseTimeout bounds one Parse call. A legitimate file at the index's
	// 2 MiB size cap parses in well under a second.
	parseTimeout = 20 * time.Second
	// memoryLimitPages caps each instance's linear memory (64 KiB pages):
	// 8192 pages = 512 MiB, far above a real parse, far below wazero's 4 GiB
	// default.
	memoryLimitPages = 8192
	// freeListSize bounds the parked instances per language.
	freeListSize = 8
)

// get returns a parked instance or mints a fresh one (nil on failure).
func (lm *langModule) get() *instance {
	select {
	case in := <-lm.free:
		return in
	default:
		return lm.newInst()
	}
}

// put parks a healthy instance, closing it when the free-list is full.
func (lm *langModule) put(in *instance) {
	if in == nil {
		return
	}
	select {
	case lm.free <- in:
	default:
		in.close()
	}
}

// backend is the wazero-hosted tree-sitter parse.Parser. Constructed once
// by New (which compiles the embedded modules); it serves only the
// languages whose module compiled, so a broken artifact silently leaves
// that language on the heuristic fallback (registered first).
type backend struct {
	runtime wazero.Runtime
	modules map[codeintel.Language]*langModule
}

// New compiles the embedded grammar modules and returns a parse.Parser. A
// module that fails to compile is logged via the returned warnings and its
// language is dropped (so Languages() never claims a language it cannot
// actually parse). New itself never returns an error: a fully-empty
// backend simply serves nothing and every language stays on the fallback.
func New() (parse.Parser, []string) {
	ctx := context.Background()
	// SR27-A1: abort a guest call when its context ends (otherwise a
	// pathological parse ignores every deadline) and cap guest memory.
	rt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(memoryLimitPages))
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)

	// One decoder decompresses every embedded .wasm.zst in-memory (ADR-0006);
	// it holds no per-stream state across DecodeAll calls and is closed once
	// all modules are compiled.
	dec, derr := zstd.NewReader(nil)
	if derr != nil {
		// Pure-Go zstd construction never fails in practice; if it somehow
		// does, the backend serves nothing and every language stays on the
		// heuristic fallback (fail-open, like a broken artifact).
		return &backend{runtime: rt, modules: make(map[codeintel.Language]*langModule)},
			[]string{fmt.Sprintf("treesitter: zstd reader: %v", derr)}
	}
	defer dec.Close()

	b := &backend{runtime: rt, modules: make(map[codeintel.Language]*langModule)}
	// Languages that share an artifact pair (e.g. js + jsx) reuse one compiled
	// module + instance pool — compile each distinct wasm only once.
	shared := make(map[string]*langModule)
	var warnings []string
	for _, s := range specs {
		key := s.wasmFile + "\x00" + s.queryFile
		if lm, ok := shared[key]; ok {
			b.modules[s.lang] = lm
			continue
		}
		zstBytes, err := grammarFS.ReadFile(s.wasmFile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("treesitter: %s: %v", s.lang, err))
			continue
		}
		wasmBytes, err := dec.DecodeAll(zstBytes, nil)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("treesitter: %s decompress: %v", s.lang, err))
			continue
		}
		query, err := grammarFS.ReadFile(s.queryFile)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("treesitter: %s query: %v", s.lang, err))
			continue
		}
		compiled, err := rt.CompileModule(ctx, wasmBytes)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("treesitter: %s compile: %v", s.lang, err))
			continue
		}
		lm := &langModule{compiled: compiled, query: query, free: make(chan *instance, freeListSize)}
		if cq := complexity.Query(s.lang); cq != "" {
			lm.cquery = []byte(cq)
		}
		lm.newInst = func() *instance { return b.newInstance(ctx, compiled) }
		shared[key] = lm
		b.modules[s.lang] = lm
	}
	return b, warnings
}

// instance is one live module instance with its exported functions resolved
// once. A nil instance (instantiation failed) is handled by Parse.
type instance struct {
	mod    api.Module
	alloc  api.Function
	free   api.Function
	run    api.Function
	outPtr api.Function
	outLen api.Function
}

// newInstance instantiates the compiled module as a WASI reactor (calling
// _initialize for libc ctors) and resolves the flat ABI exports. It returns
// nil on failure; the pool stores nil and Parse fails open.
func (b *backend) newInstance(ctx context.Context, compiled api.Closer) *instance {
	cm, ok := compiled.(wazero.CompiledModule)
	if !ok {
		return nil
	}
	mod, err := b.runtime.InstantiateModule(ctx, cm,
		wazero.NewModuleConfig().WithName("").WithStartFunctions("_initialize"))
	if err != nil {
		return nil
	}
	return &instance{
		mod:    mod,
		alloc:  mod.ExportedFunction("ci_alloc"),
		free:   mod.ExportedFunction("ci_free"),
		run:    mod.ExportedFunction("ci_run"),
		outPtr: mod.ExportedFunction("ci_out_ptr"),
		outLen: mod.ExportedFunction("ci_out_len"),
	}
}

// close releases the instance's module (and its linear memory) from the
// runtime. Safe on nil and on an instance wazero already closed.
func (in *instance) close() {
	if in == nil || in.mod == nil {
		return
	}
	_ = in.mod.Close(context.Background())
}

// Languages reports the languages whose module compiled, in a stable order.
func (b *backend) Languages() []codeintel.Language {
	out := make([]codeintel.Language, 0, len(b.modules))
	for lang := range b.modules {
		out = append(out, lang)
	}
	slices.Sort(out)
	return out
}

// Capabilities reports exact-span full extraction for a served language and
// the zero value otherwise.
func (b *backend) Capabilities(lang codeintel.Language) codeintel.LanguageCapability {
	if _, ok := b.modules[lang]; ok {
		return servedCapability
	}
	return codeintel.LanguageCapability{}
}

// Parse runs the grammar module over src and returns a ParseResult with
// exact spans. It is best-effort and panic-free: an unserved language, an
// instantiation failure, or a module-side error yields a result with the
// correct capability flags but no nodes (callers fail open), never a panic.
// It extracts the base set; ParseWith adds the optional extractions.
func (b *backend) Parse(ctx context.Context, src []byte, lang codeintel.Language, filename string) (codeintel.ParseResult, error) {
	return b.ParseWith(ctx, src, lang, filename, parse.Options{})
}

// ParseWith is Parse under opts (parse.OptionParser): the decision query of
// the complexity pass runs only when opts.Complexity is set.
func (b *backend) ParseWith(ctx context.Context, src []byte, lang codeintel.Language, _ string, opts parse.Options) (codeintel.ParseResult, error) {
	res := codeintel.ParseResult{
		Lang:       lang,
		Capability: b.Capabilities(lang),
		Parser:     "treesitter:" + string(lang),
	}
	lm, ok := b.modules[lang]
	if !ok {
		res.Capability = codeintel.LanguageCapability{}
		res.Parser = "treesitter"
		return res, nil
	}
	if len(src) == 0 {
		return res, nil
	}

	inst := lm.get()
	if inst == nil {
		return res, fmt.Errorf("treesitter.Parse: instantiate %s failed", lang)
	}

	callCtx, cancel := context.WithTimeout(ctx, parseTimeout)
	out, err := inst.runExtract(callCtx, src, lm.query)
	cancel()
	if err != nil {
		// Never re-park an instance whose call failed: a deadline closed
		// it (WithCloseOnContextDone) or it may hold half-written state.
		inst.close()
		return res, fmt.Errorf("treesitter.Parse: %w", err)
	}
	// Complexity pass: the decision query runs as its own extraction (the
	// harness's record stream has no decision record type, so mixing its
	// captures into the main query would be ambiguous with call sites). A
	// failure here leaves the figure uncounted (Complexity 0) and never
	// fails the parse.
	var decisions []int
	counted := false
	if opts.Complexity && len(lm.cquery) > 0 {
		cctx, ccancel := context.WithTimeout(ctx, parseTimeout)
		cout, cerr := inst.runExtract(cctx, src, lm.cquery)
		ccancel()
		if cerr != nil {
			inst.close()
			inst = nil
		} else {
			decisions, counted = decisionOffsets(cout), true
		}
	}
	if inst != nil {
		lm.put(inst)
	}
	decodeInto(&res, out, src)
	sortResult(&res)
	if counted {
		complexity.Count(res.Nodes, decisions)
	}
	return res, nil
}

// decisionOffsets reads the start byte of every record of a decision-query
// run (each pattern captures its decision token as `@name @reference.call`,
// so every record is a 'C' record at the token).
func decisionOffsets(b []byte) []int {
	var offs []int
	for len(b) >= 22 {
		rectype := b[0]
		sb := binary.LittleEndian.Uint32(b[1:])
		nl := binary.LittleEndian.Uint32(b[18:])
		b = b[22:]
		if uint32(len(b)) < nl {
			break
		}
		b = b[nl:]
		if rectype == 'C' {
			offs = append(offs, int(sb))
		}
	}
	return offs
}

// runExtract copies src + query into the module, calls ci_run, and returns a
// COPY of the output record stream (read out before the buffers are freed).
func (in *instance) runExtract(ctx context.Context, src, query []byte) ([]byte, error) {
	mem := in.mod.Memory()
	srcPtr, err := in.put(ctx, src)
	if err != nil {
		return nil, err
	}
	// free is best-effort scratch-buffer cleanup; a failure here only affects
	// this pooled instance's wasm memory and cannot be acted on in a defer.
	defer func() { _, _ = in.free.Call(ctx, uint64(srcPtr)) }()
	qPtr, err := in.put(ctx, query)
	if err != nil {
		return nil, err
	}
	defer func() { _, _ = in.free.Call(ctx, uint64(qPtr)) }()

	rc, err := in.run.Call(ctx, uint64(srcPtr), uint64(len(src)), uint64(qPtr), uint64(len(query)))
	if err != nil {
		return nil, err
	}
	if code := int32(rc[0]); code != 0 {
		return nil, fmt.Errorf("ci_run rc=%d", code)
	}
	op, err := in.outPtr.Call(ctx)
	if err != nil {
		return nil, err
	}
	ol, err := in.outLen.Call(ctx)
	if err != nil {
		return nil, err
	}
	raw, ok := mem.Read(uint32(op[0]), uint32(ol[0]))
	if !ok {
		return nil, fmt.Errorf("read output failed")
	}
	// raw aliases module memory; copy before it is reused/freed.
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

// put allocates a module buffer and writes b into it, returning the pointer.
func (in *instance) put(ctx context.Context, b []byte) (uint32, error) {
	res, err := in.alloc.Call(ctx, uint64(len(b)))
	if err != nil {
		return 0, err
	}
	p := uint32(res[0])
	if !in.mod.Memory().Write(p, b) {
		return 0, fmt.Errorf("write %d bytes failed", len(b))
	}
	return p, nil
}

// kindByte maps the module's one-byte kind code to the codeintel Kind
// vocabulary.
var kindByte = map[byte]string{
	'f': "function", 'm': "method", 'c': "class",
	'i': "interface", 't': "type", 'o': "module", 'M': "macro",
}

// kindRank ranks specificity for dedup: when two definitions share a span
// (e.g. a method matched by both the method and the plain-function pattern),
// the higher-ranked kind wins.
var kindRank = map[string]int{
	"method": 10, "class": 5, "interface": 5, "module": 5,
	"macro": 5, "type": 4, "function": 3,
}

// decodeInto walks the binary record stream and appends Nodes / Calls /
// Imports to res, deduping definitions that share a byte span.
func decodeInto(res *codeintel.ParseResult, b, src []byte) {
	type key struct{ sb, eb uint32 }
	nodeIdx := make(map[key]int)
	for len(b) >= 18 {
		rectype := b[0]
		sb := binary.LittleEndian.Uint32(b[1:])
		eb := binary.LittleEndian.Uint32(b[5:])
		sr := binary.LittleEndian.Uint32(b[9:])
		er := binary.LittleEndian.Uint32(b[13:])
		kind := b[17]
		b = b[18:]
		if len(b) < 4 {
			break
		}
		nl := binary.LittleEndian.Uint32(b[0:])
		b = b[4:]
		if uint32(len(b)) < nl {
			break
		}
		name := string(b[:nl])
		b = b[nl:]

		switch rectype {
		case 'D':
			k := kindByte[kind]
			if k == "" {
				k = "type"
			}
			n := codeintel.Node{
				Kind:      k,
				Name:      name,
				FQN:       name, // tree-sitter tags carry no receiver; FQN==Name
				StartLine: int(sr) + 1,
				EndLine:   int(er) + 1,
				StartByte: int(sb),
				EndByte:   int(eb),
				Signature: firstLineExcerpt(src, int(sb)),
			}
			ky := key{sb, eb}
			if idx, ok := nodeIdx[ky]; ok {
				if kindRank[k] > kindRank[res.Nodes[idx].Kind] {
					res.Nodes[idx].Kind = k
					res.Nodes[idx].Name = name
					res.Nodes[idx].FQN = name
				}
				continue
			}
			nodeIdx[ky] = len(res.Nodes)
			res.Nodes = append(res.Nodes, n)
		case 'C':
			res.Calls = append(res.Calls, codeintel.CallSite{
				Name:      name,
				Enclosing: -1, // resolved after sort
				StartLine: int(sr) + 1,
				StartByte: int(sb),
				// The record's span is the @name capture (the bare callee),
				// so widen the excerpt back over the receiver chain: the
				// module-scoped resolver classifies ns.foo() from it.
				RawText: callExcerpt(src, int(sb)),
			})
		case 'I':
			res.Imports = append(res.Imports, codeintel.Import{
				Path:      unquote(name),
				StartLine: int(sr) + 1,
				StartByte: int(sb),
				// Full statement line (not just the path node onward) so the
				// scoped module resolver can read the imported names — the
				// `@_import.path` capture anchors mid-statement at the path.
				RawText: fullLineExcerpt(src, int(sb)),
			})
		}
	}
}

// excerptScan bounds how far either excerpt helper looks from its anchor
// for a line break. An excerpt is at most maxExcerpt bytes, so looking
// further only matters for a line that is longer than this window, and
// there it changes nothing that survives the clip unless the line opens
// with more than excerptScan-maxExcerpt bytes of whitespace. Without
// the bound a minified bundle, one line of 800 KB or more, cost one
// line-sized copy per record: the tinymce.min.js in litemall has about
// 23,000 records, so one parse allocated and kept about 9.7 GB (ADR-0010).
const excerptScan = 4 * maxExcerpt

// fullLineExcerpt returns the source line containing byte offset off
// (scanning back to the prior newline and forward to the next), trimmed and
// clipped — used for import sites so the excerpt carries the statement's
// imported names even though the path capture anchors mid-line. On a line
// longer than the scan window, the excerpt starts maxExcerpt/2 bytes before
// off instead of at the line start, so it still holds the path (ADR-0010).
func fullLineExcerpt(src []byte, off int) string {
	if off < 0 || off > len(src) {
		return ""
	}
	lo := max(0, off-excerptScan)
	start := lo
	if i := bytes.LastIndexByte(src[lo:off], '\n'); i >= 0 {
		start = lo + i + 1
	} else if lo > 0 {
		start = runeStart(src, max(0, off-maxExcerpt/2))
	}
	return lineExcerpt(src, start)
}

// firstLineExcerpt returns the line beginning at byte offset start, trimmed
// and clipped to maxExcerpt — a bounded declaration/call excerpt, never a
// body.
func firstLineExcerpt(src []byte, start int) string {
	if start < 0 || start >= len(src) {
		return ""
	}
	return lineExcerpt(src, start)
}

// lineExcerpt returns the text from start to the next newline, looking at
// most excerptScan bytes ahead, trimmed and clipped to maxExcerpt. It
// works on the byte slice and copies only the clipped result, so the
// excerpt never shares (and keeps alive) a line-sized allocation.
func lineExcerpt(src []byte, start int) string {
	hi := min(len(src), start+excerptScan)
	end := hi
	if i := bytes.IndexByte(src[start:hi], '\n'); i >= 0 {
		end = start + i
	}
	return string(clipBytes(bytes.TrimSpace(src[start:end]), maxExcerpt))
}

// runeStart moves i back to the start of the UTF-8 rune that contains it.
func runeStart(src []byte, i int) int {
	for i > 0 && i < len(src) && src[i]&0xC0 == 0x80 {
		i--
	}
	return i
}

// callExcerpt is the call-site excerpt for a call whose callee NAME starts
// at nameStart. The extractor's call record spans the @name capture, not the
// @reference.call expression, so firstLineExcerpt alone turns
// `relay.forward(x)` into `forward(x)` and the module-scoped resolver
// (resolve.splitCallGeneric) can no longer tell a namespace call from a bare
// one. callExcerpt prepends the receiver chain recovered by callQualifier, so
// the excerpt starts where the call expression does (`relay.forward(x)`, the
// shape the goast backend already stores). CallSite.Name, StartByte and
// StartLine stay on the name.
func callExcerpt(src []byte, nameStart int) string {
	line := firstLineExcerpt(src, nameStart)
	if line == "" {
		return ""
	}
	return string(clipBytes([]byte(callQualifier(src, nameStart)+line), maxExcerpt))
}

// maxQualifierSegments bounds the backward receiver-chain scan.
const maxQualifierSegments = 8

// memberOps are the member-access operators a receiver chain may use, longest
// first so `?.` / `?->` / `->` / `::` win over a bare `.`.
var memberOps = []string{"?->", "?.", "->", "::", "&.", "."}

// callQualifier walks backwards from the callee name over the receiver chain
// (`ident <op> ident <op> ... name`, whitespace and newlines between tokens
// ignored) and returns it with whitespace dropped: "relay.", "self.db.",
// "$this->", "std::", or "" for a bare call. A receiver that is not an
// identifier (`a().foo()`, `arr[i].foo()`, `"s".foo()`) contributes only its
// closing character, so the excerpt reads `).foo(...)` and the resolver
// classifies it as complex rather than bare. `..` (JS spread, ranges, Lua
// concatenation) is not a member operator.
func callQualifier(src []byte, nameStart int) string {
	if nameStart <= 0 || nameStart > len(src) {
		return ""
	}
	var parts []string // receiver chain, innermost first
	i := nameStart
	for n := 0; n < maxQualifierSegments; n++ {
		j := skipSpaceBack(src, i)
		op := memberOpBefore(src, j)
		if op == "" {
			break
		}
		k := skipSpaceBack(src, j-len(op))
		s := identStartBack(src, k)
		if s == k {
			if k > 0 {
				parts = append(parts, op, string(src[k-1]))
			}
			break
		}
		parts = append(parts, op, string(src[s:k]))
		i = s
	}
	var b bytes.Buffer
	for p := len(parts) - 1; p >= 0; p-- {
		b.WriteString(parts[p])
	}
	return b.String()
}

// skipSpaceBack returns the smallest index <= i such that src[index:i] is
// all whitespace.
func skipSpaceBack(src []byte, i int) int {
	for i > 0 {
		switch src[i-1] {
		case ' ', '\t', '\r', '\n':
			i--
		default:
			return i
		}
	}
	return i
}

// memberOpBefore returns the member operator ending at src[:j], or "".
func memberOpBefore(src []byte, j int) string {
	for _, op := range memberOps {
		if j < len(op) || string(src[j-len(op):j]) != op {
			continue
		}
		if op == "." && j >= 2 && src[j-2] == '.' {
			return "" // `..` / `...`: spread, range, concatenation
		}
		return op
	}
	return ""
}

// identStartBack returns the start of the identifier ending at src[:k] (k
// itself when there is none). `$` covers PHP/JS names; bytes >= 0x80 keep
// non-ASCII identifiers whole.
func identStartBack(src []byte, k int) int {
	for k > 0 {
		c := src[k-1]
		switch {
		case c == '_' || c == '$' || c >= 0x80,
			c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			k--
		default:
			return k
		}
	}
	return k
}

// unquote strips a single pair of surrounding quotes (" ' or `) from an
// import path string node.
func unquote(s string) string {
	if len(s) >= 2 {
		switch s[0] {
		case '"', '\'', '`':
			if s[len(s)-1] == s[0] {
				return s[1 : len(s)-1]
			}
		}
	}
	return s
}

// clipBytes bounds b to max bytes without splitting a UTF-8 rune.
func clipBytes(b []byte, max int) []byte {
	if len(b) <= max {
		return b
	}
	cut := max
	for cut > 0 && b[cut]&0xC0 == 0x80 {
		cut--
	}
	return b[:cut]
}

// sortResult makes the output deterministic and resolves each call's
// enclosing node by byte containment against the sorted node slice (the
// smallest containing span wins, so a call lands in the innermost symbol).
func sortResult(res *codeintel.ParseResult) {
	sort.SliceStable(res.Nodes, func(i, j int) bool {
		if res.Nodes[i].StartLine != res.Nodes[j].StartLine {
			return res.Nodes[i].StartLine < res.Nodes[j].StartLine
		}
		return res.Nodes[i].Name < res.Nodes[j].Name
	})
	sort.SliceStable(res.Imports, func(i, j int) bool {
		if res.Imports[i].StartLine != res.Imports[j].StartLine {
			return res.Imports[i].StartLine < res.Imports[j].StartLine
		}
		return res.Imports[i].Path < res.Imports[j].Path
	})
	for i := range res.Calls {
		res.Calls[i].Enclosing = enclosingNode(res.Nodes, res.Calls[i].StartByte)
	}
	sort.SliceStable(res.Calls, func(i, j int) bool {
		if res.Calls[i].StartLine != res.Calls[j].StartLine {
			return res.Calls[i].StartLine < res.Calls[j].StartLine
		}
		return res.Calls[i].StartByte < res.Calls[j].StartByte
	})
}

// enclosingNode returns the index of the smallest node whose byte span
// contains off, or -1 when off is outside every node.
func enclosingNode(nodes []codeintel.Node, off int) int {
	best := -1
	bestSize := -1
	for i, n := range nodes {
		if n.StartByte <= off && off < n.EndByte {
			size := n.EndByte - n.StartByte
			if best == -1 || size < bestSize {
				best = i
				bestSize = size
			}
		}
	}
	return best
}
