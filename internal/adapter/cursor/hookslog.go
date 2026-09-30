package cursor

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// # The IDE hooks output-channel log (layoutHooksLog)
//
// Cursor's IDE writes every hook invocation — the verbatim INPUT payload
// it sent, the hook's OUTPUT and STDERR — to a per-window output channel:
//
//	<Cursor userData>/logs/<launch>/window<N>[_wb<M>]/output_<ts>/cursor.hooks[.workspaceId-<id>][.<n>].log
//
// (userData = %APPDATA%\Cursor on Windows, ~/Library/Application
// Support/Cursor on macOS, ~/.config/Cursor on Linux; see
// cursorUserDataDir). Grounded 2026-09-23 on Cursor 3.17.21 / 3.20.21 /
// 3.21.13: it is the ONLY local, durable, vendor-written record of the
// per-request usage Cursor sends on `stop` / `afterAgentResponse`
// (transcripts, store.db, state.vscdb bubbles and the IDE structured
// logs all carry none for IDE sessions), and of every hook event a live
// receiver failed to persist — the ingest-deadline drops
// (`observer-hook: cursor stop insert deadline exceeded`, 2026-09-19
// session 8be96a3f lost 2,783,511 input / 21,724 output tokens that
// way) and whole windows whose hook registration pointed at a receiver
// that did not exist.
//
// This reader REPLAYS those payloads through the exact functions the
// live hook uses (buildEvent / buildTokenEvent / BuildAfterOutcome), so
// every row it produces carries the live hook's (source_file,
// source_event_id) identity — `cursor:hook` + `<generation>:<event>...`
// — and dedups against a row the live hook already landed through the
// store's UNIQUE upsert. It is a durable backstop, not a second source:
// replaying a log whose every event already landed is a no-op.
//
// Deliberate differences from the live hook:
//
//   - Reasoning (afterAgentThought) is carried by an IN-MEMORY carrier
//     scoped to one parse (memoryReasoning), never the live on-disk
//     stash: the replay must not consume a thought a concurrently
//     running Cursor session is waiting to attach.
//   - The stop-time transcript walk (BuildStopTranscriptEvents) is NOT
//     replayed: it reads the transcript's LAST turn, which at replay time
//     is no longer the turn that stop closed.
//   - Timestamps come from the log (the `[<RFC3339>]` line that precedes
//     each block — Cursor's "Running hook N" line, i.e. hook start),
//     not from time.Now(), so historical rows price at their own dated
//     rate. A live row that already landed keeps its own timestamp (the
//     upsert does not rewrite it).
//   - After-event tool output is scrubbed and capped before it becomes
//     an outcome update.
//
// Privacy: the log holds full hook payloads (prompts, file bodies, tool
// output). Everything this reader keeps passes through the same scrubber
// and caps as the live hook; the file is opened read-only and never
// written.

// hooksLogMaxLine bounds one physical line. The only realistically huge
// line inside a payload is afterAgentResponse's `text` (or a Read's
// `content`); an oversize line is replaced by a JSON-safe `"<key>": null`
// placeholder so the usage scalars around it still decode.
const hooksLogMaxLine = 1 << 20

// hooksLogMaxBlock bounds one INPUT payload; a larger block is skipped.
const hooksLogMaxBlock = 8 << 20

// hooksLogTSLine matches the timestamp prefix Cursor puts on every
// non-payload log line: `[2026-09-19T14:15:08.420Z] Running hook 1 ...`.
var hooksLogTSLine = regexp.MustCompile(`^\[(\d{4}-\d{2}-\d{2}T[0-9:.]+Z)\]`)

// hooksLogKeyLine extracts the JSON key of an (oversize) payload line.
var hooksLogKeyLine = regexp.MustCompile(`^(\s*"[^"\\]+"\s*):`)

// matchesHooksLog reports whether path is a Cursor IDE hooks output-
// channel log: base name `cursor.hooks.*.log` (covers the
// `.workspaceId-<id>` variant and the rotated `.1.log`), directly under
// an `output_*` directory, somewhere below a `Cursor/logs/` tree.
// Separators are normalised and the match is case-insensitive (Windows
// paths reach a WSL observer as /mnt/c/... with mixed case).
func matchesHooksLog(path string) bool {
	norm := strings.ToLower(strings.ReplaceAll(path, `\`, "/"))
	slash := strings.LastIndex(norm, "/")
	if slash < 0 {
		return false
	}
	base := norm[slash+1:]
	if !strings.HasPrefix(base, "cursor.hooks.") || !strings.HasSuffix(base, ".log") {
		return false
	}
	dir := norm[:slash]
	parent := dir[strings.LastIndex(dir, "/")+1:]
	return strings.HasPrefix(parent, "output_") && strings.Contains(norm, "/cursor/logs/")
}

// hooksLogRoots returns one `<Cursor userData>/logs` watch root per
// home. These are disjoint from every other adapter's roots (the
// VS Code-fork extension adapters watch `<Cursor>/User/globalStorage/
// <ext>`), which the watcher's root-based dispatch requires.
func hooksLogRoots(homes []crossmount.HomeRoot) []string {
	var roots []string
	for _, h := range homes {
		if dir := cursorUserDataDir(h); dir != "" {
			roots = append(roots, filepath.Join(dir, "logs"))
		}
	}
	return roots
}

// HooksLogRoots returns the Cursor IDE log roots for every cross-mount
// home on this host (so a WSL observer finds the Windows-side logs).
// Used by `observer backfill --cursor-hook-usage`.
func HooksLogRoots() []string { return hooksLogRoots(crossmount.AllHomes()) }

// IsHooksLog reports whether path is a Cursor IDE hooks output-channel
// log (see matchesHooksLog). Exported for the backfill walker.
func IsHooksLog(path string) bool { return matchesHooksLog(path) }

// ParseHooksLog replays one hooks log from offset 0 through the same
// reader the watcher uses. Exported for `observer backfill`.
func (a *Adapter) ParseHooksLog(ctx context.Context, path string) (adapter.ParseResult, error) {
	return a.parseHooksLog(ctx, path, 0)
}

// parseHooksLog is the layoutHooksLog parser. It seeks to fromOffset and
// streams forward (StreamsFromCursor), never passing a partial final
// line or an unfinished INPUT block; see scanHooksLog for the offset
// rules. fromOffset beyond the file size (rotation / truncation) resets
// to 0.
func (a *Adapter) parseHooksLog(ctx context.Context, path string, fromOffset int64) (adapter.ParseResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseHooksLog: open: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseHooksLog: stat: %w", err)
	}
	// Cursor's rotating logger renames `cursor.hooks.<id>.log` to
	// `.1.log` (~30 MB) and restarts the SAME path empty, so a persisted
	// cursor past EOF means a new file: read it from 0. The layout
	// declares RewindsOnTruncate, so the watcher stores the lower
	// NewOffset this returns instead of MAX-merging it with the stale
	// cursor (watcher.persistProcessCursor).
	start := fromOffset
	if start < 0 || start > fi.Size() {
		start = 0
	}
	if start == fi.Size() {
		return adapter.ParseResult{NewOffset: start}, nil
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseHooksLog: seek: %w", err)
	}
	blocks, next, err := scanHooksLog(ctx, io.LimitReader(f, fi.Size()-start), start)
	if err != nil {
		return adapter.ParseResult{}, fmt.Errorf("cursor.parseHooksLog: %w", err)
	}
	res := replayHookBlocks(blocks, a.scrubber, fi.ModTime().UTC())
	a.reconcileReplay(ctx, &res)
	res.NewOffset = next
	return res, nil
}

// hookLogBlock is one decoded INPUT payload plus its log context.
type hookLogBlock struct {
	// header is the event name from the block's banner (the fallback
	// when the payload lacks hook_event_name).
	header string
	// ts is the most recent `[<RFC3339>]` line before the block; zero
	// when the parse window started inside a block's preamble.
	ts   time.Time
	body []byte
	// off is the absolute byte offset of the block's `INPUT:` line, for
	// content-safe diagnostics.
	off int64
	// skipped, when non-empty, is why the payload was not kept (the
	// block is reported, never silently advanced past).
	skipped string
}

// scanHooksLog walks r (which starts at absolute offset base) and returns
// every complete INPUT block plus the offset the next pass must resume
// from. Resume rules:
//
//   - never past a partial final line (no trailing newline yet);
//   - when EOF lands inside an open INPUT block, resume at the timestamp
//     line that preceded it (or the block's own `INPUT:` line when none
//     was seen this pass), so the next pass re-reads the block WITH its
//     timestamp — the blocks re-emitted by that overlap dedup by key.
func scanHooksLog(ctx context.Context, r io.Reader, base int64) ([]hookLogBlock, int64, error) {
	br := bufio.NewReaderSize(r, 64*1024)
	var (
		blocks     []hookLogBlock
		off        = base
		committed  = base
		ts         time.Time
		tsOff      = int64(-1)
		afterRule  bool
		header     string
		inBlock    bool
		blockStart int64
		blockTS    time.Time
		blockHdr   string
		inputOff   int64
		body       []byte
		tooBig     bool
	)
	for {
		if err := ctx.Err(); err != nil {
			return nil, base, err
		}
		line, size, oversize, complete, err := readHooksLogLine(br)
		if !complete {
			// EOF (possibly with a partial, unterminated tail) or a read
			// error: stop without consuming the partial line.
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, base, err
			}
			break
		}
		lineStart := off
		off += size
		text := strings.TrimRight(string(line), "\r\n")

		if inBlock {
			if text == "OUTPUT:" {
				switch {
				case tooBig:
					blocks = append(blocks, hookLogBlock{header: blockHdr, ts: blockTS, off: inputOff, skipped: "payload exceeds the 8 MiB block cap"})
				case len(body) > 0:
					blocks = append(blocks, hookLogBlock{header: blockHdr, ts: blockTS, off: inputOff, body: append([]byte(nil), body...)})
				}
				inBlock, tooBig, body = false, false, body[:0]
				committed = off
				continue
			}
			if tooBig {
				continue
			}
			if oversize {
				text = oversizePlaceholder(line)
			}
			if len(body)+len(text)+1 > hooksLogMaxBlock {
				tooBig = true
				continue
			}
			body = append(body, text...)
			body = append(body, '\n')
			continue
		}

		switch {
		case text == "INPUT:":
			inBlock, tooBig, body = true, false, body[:0]
			blockStart, inputOff = lineStart, lineStart
			if tsOff >= 0 {
				blockStart = tsOff
			}
			blockTS, blockHdr = ts, header
		case strings.HasPrefix(text, "═"):
			afterRule = true
			committed = off
			continue
		default:
			if m := hooksLogTSLine.FindStringSubmatch(text); m != nil {
				if t, perr := time.Parse(time.RFC3339Nano, m[1]); perr == nil {
					ts, tsOff = t.UTC(), lineStart
				}
			} else if afterRule && text != "" && !strings.Contains(text, " ") {
				header = text
			}
		}
		afterRule = false
		committed = off
	}
	if inBlock {
		return blocks, blockStart, nil
	}
	return blocks, committed, nil
}

// readHooksLogLine reads one '\n'-terminated line. It returns
// complete=false (and consumes nothing the caller should count) when the
// reader hits EOF before a newline. A line longer than hooksLogMaxLine
// is returned as its first 256 bytes plus its final non-space byte
// (oversize=true) so the caller can build a placeholder without holding
// it.
func readHooksLogLine(r *bufio.Reader) (line []byte, size int64, oversize, complete bool, err error) {
	var last byte
	for {
		part, rerr := r.ReadSlice('\n')
		size += int64(len(part))
		if !oversize {
			if int64(len(line))+int64(len(part)) <= hooksLogMaxLine {
				line = append(line, part...)
			} else {
				oversize = true
				if len(line) > 256 {
					line = line[:256]
				}
			}
		}
		if t := strings.TrimRight(string(part), " \t\r\n"); t != "" {
			last = t[len(t)-1]
		}
		if errors.Is(rerr, bufio.ErrBufferFull) {
			continue
		}
		if rerr != nil {
			return line, size, oversize, false, rerr
		}
		if oversize {
			line = append(line, last)
		}
		return line, size, oversize, true, nil
	}
}

// oversizePlaceholder turns an oversize payload line into a JSON-safe
// `"<key>": null` (keeping its trailing comma), so the surrounding
// object still decodes. The last byte of line is the original line's
// final non-space byte (readHooksLogLine).
func oversizePlaceholder(line []byte) string {
	m := hooksLogKeyLine.FindSubmatch(line)
	if m == nil {
		return ""
	}
	out := string(m[1]) + ": null"
	if len(line) > 0 && line[len(line)-1] == ',' {
		out += ","
	}
	return out
}

// replayHookBlocks turns decoded payloads into the rows the live hook
// would have written. The dispatch is a TABLE over the payload's own
// event name (hookReplayKind), never a per-tool branch.
func replayHookBlocks(blocks []hookLogBlock, sc *scrub.Scrubber, fallback time.Time) adapter.ParseResult {
	var res adapter.ParseResult
	carrier := newMemoryReasoning()
	// skip records a block the replay could not use. The warning is
	// content-safe (offset, event name, a builder's own error text —
	// never payload bytes) and reaches the watcher log / backfill
	// summary, so a decode regression is visible instead of silently
	// advanced past.
	skip := func(b hookLogBlock, event, why string) {
		if event == "" {
			event = "unknown"
		}
		res.Warnings = append(res.Warnings, fmt.Sprintf("cursor: hooks log block at offset %d (%s) skipped: %s", b.off, event, why))
	}
	for _, b := range blocks {
		if b.skipped != "" {
			skip(b, b.header, b.skipped)
			continue
		}
		var head struct {
			Event string `json:"hook_event_name"`
		}
		if err := json.Unmarshal(b.body, &head); err != nil {
			skip(b, b.header, "undecodable JSON payload")
			continue
		}
		event := head.Event
		if event == "" {
			event = b.header
		}
		ts := b.ts
		if ts.IsZero() {
			ts = fallback
		}
		kind := hookReplayKind[event]
		if kind.tokens {
			tk, ok, err := buildTokenEvent(b.body, event)
			switch {
			case err != nil:
				skip(b, event, "usage: "+err.Error())
			case ok:
				tk.Timestamp = ts
				tk.Model = resolvePlaceholderModelAllHomes(tk.Model, tk.SessionID, tk.MessageID)
				res.TokenEvents = append(res.TokenEvents, tk)
			}
		}
		if kind.outcome {
			up, ok, err := BuildAfterOutcome(event, b.body)
			if err != nil {
				skip(b, event, err.Error())
			}
			if err == nil && ok {
				out := up.Output
				if sc != nil {
					out = sc.String(out)
				}
				res.OutcomeUpdates = append(res.OutcomeUpdates, models.ActionOutcomeUpdate{
					SourceFile:    up.SourceFile,
					SourceEventID: up.SourceEventID,
					SuccessKnown:  true,
					Success:       up.Success,
					ErrorMessage:  up.ErrorMessage,
					ToolOutput:    contentcap.Cap(out, contentcap.DefaultMaxBytes),
					DurationMs:    up.DurationMs,
				})
			}
			continue
		}
		if kind.noRow {
			continue
		}
		ev, ok, err := buildEvent(event, b.body, sc, carrier)
		if err != nil {
			skip(b, event, err.Error())
			continue
		}
		if !ok || ev.SessionID == "" || ev.ProjectRoot == "" {
			continue
		}
		ev.Timestamp = ts
		res.ToolEvents = append(res.ToolEvents, ev)
	}
	markProvenRestatements(res.TokenEvents)
	return res
}

// restatementWindow bounds how far after the afterAgentResponse a
// mislabelled stop can land and still be read as its restatement. Grounded
// 2026-09-23 on every Cursor hook token row in the live DB: the three
// restatements sit 0.37 s / 0.81 s / 1.35 s after the row they restate.
const restatementWindow = 10 * time.Second

// markProvenRestatements marks every `stop` usage event in one replayed log
// that is PROVEN, by both halves in the log itself, to be Cursor's
// mislabelled restatement (review finding F3, 2026-09-26): the stop carries
// generation B, the SAME conversation's afterAgentResponse for a DIFFERENT
// generation A precedes it within [restatementWindow] with the SAME model
// and the byte-identical usage, and no afterAgentResponse for B precedes
// it. That last clause is the discriminator counter equality cannot give:
// a real request's stop always follows its OWN afterAgentResponse, while
// the mislabelled stop names the NEXT request, whose afterAgentResponse
// has not fired yet (grounded cc8322af 3.17.21: 93c94255's own tool calls
// start after that stop). Two real consecutive requests with equal
// counters therefore never match. The event is marked, not dropped: the
// store owns what a proven restatement does to a row it already holds.
func markProvenRestatements(evs []models.TokenEvent) {
	for i := range evs {
		s := &evs[i]
		if s.HookEvent != EventStop {
			continue
		}
		restated := ""
		for j := i - 1; j >= 0; j-- {
			a := evs[j]
			if a.HookEvent != EventAfterAgentResponse || a.SessionID != s.SessionID {
				continue
			}
			if a.MessageID == s.MessageID {
				restated = "" // B's own afterAgentResponse already fired: a real stop
				break
			}
			gap := s.Timestamp.Sub(a.Timestamp)
			if restated == "" && gap >= 0 && gap <= restatementWindow && sameHookUsage(a, *s) {
				restated = a.MessageID
			}
		}
		s.Restates = restated
	}
}

// sameHookUsage reports whether two hook usage events carry the same model
// and every billed dimension identically.
func sameHookUsage(a, b models.TokenEvent) bool {
	return a.Model == b.Model &&
		a.InputTokens == b.InputTokens && a.OutputTokens == b.OutputTokens &&
		a.CacheReadTokens == b.CacheReadTokens && a.CacheCreationTokens == b.CacheCreationTokens &&
		a.CacheCreation1hTokens == b.CacheCreation1hTokens && a.ReasoningTokens == b.ReasoningTokens &&
		a.WebSearchRequests == b.WebSearchRequests && a.Fast == b.Fast
}

// hookReplayShape declares what a replayed event contributes.
type hookReplayShape struct {
	// tokens: the payload carries per-request usage (buildTokenEvent).
	tokens bool
	// outcome: an after-event that enriches its before-row in place
	// (BuildAfterOutcome) instead of minting a row.
	outcome bool
	// noRow: contributes no action row (stop's only row is its tokens;
	// its transcript walk is deliberately not replayed).
	noRow bool
}

// hookReplayKind is the replay dispatch table. An event absent from the
// table replays through buildEvent exactly as the live hook would
// (which itself decides row / no-row / reasoning-carry).
var hookReplayKind = map[string]hookReplayShape{
	EventStop:                {tokens: true, noRow: true},
	EventAfterAgentResponse:  {tokens: true},
	EventPostToolUse:         {outcome: true},
	EventAfterShellExecution: {outcome: true},
	EventAfterMCPExecution:   {outcome: true},
}

// memoryReasoning is the replay's reasoningCarrier: the same
// last-wins / consumed-once / user-turn-discard semantics as the live
// on-disk stash, held in memory for one parse.
type memoryReasoning struct {
	pending map[string]string
	taken   map[string]string
}

func newMemoryReasoning() *memoryReasoning {
	return &memoryReasoning{pending: map[string]string{}, taken: map[string]string{}}
}

func (m *memoryReasoning) stash(conversationID, preview string) {
	if conversationID == "" || preview == "" {
		return
	}
	m.pending[conversationID] = preview
}

func (m *memoryReasoning) take(conversationID, eventID string) string {
	if v, ok := m.taken[eventID]; ok && eventID != "" {
		return v
	}
	v := m.pending[conversationID]
	delete(m.pending, conversationID)
	if eventID != "" && v != "" {
		m.taken[eventID] = v
	}
	return v
}

func (m *memoryReasoning) clear(conversationID string) { delete(m.pending, conversationID) }
