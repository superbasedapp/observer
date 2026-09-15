package antigravity

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strconv"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// agySurfaceRow is one row of the trajectory_meta.source table.
type agySurfaceRow struct {
	surface models.SessionSurface
	note    string
}

// agySourceSurface is THE table that resolves trajectory_meta.source —
// a numeric enum that differs by the client that drove the agy
// backend — into the normalized capture-surface vocabulary. Live-
// grounded 2026-09-03 on the operator's box, one conversation each:
//
//	17  the `agy` CLI itself (cascade_id = the conversation uuid)
//	 1  the VS Code extension Google.google-antigravity (bundled agy,
//	    writes into the DESKTOP tree)
//
// A value that is not a row falls back to the TREE default in
// agyTreeDefaultSurface (desktop tree → ide/antigravity, the tree's
// own product; CLI tree → no stamp, the honest zero — a JetBrains /
// Zed / Xcode integration driving agy would land there with a value
// nobody has seen) and the raw value is kept in
// ActionMetadata.CaptureSource on the user_prompt rows plus a parse
// warning, so the next grounded value is one table row away. A .db
// with NO trajectory_meta row yet stamps nothing at all: the store's
// first-wins semantics would otherwise let a guessed tree default
// pre-empt the real value written moments later.
var agySourceSurface = map[int64]agySurfaceRow{
	17: {surface: models.SessionSurface{Surface: models.SurfaceCLI, SurfaceHost: "antigravity-cli"}, note: "agy CLI"},
	1:  {surface: models.SessionSurface{Surface: models.SurfaceIDE, SurfaceHost: "vscode"}, note: "VS Code extension"},
}

// agyTreeDefaultSurface is the fallback stamp per tree for an UNMAPPED
// trajectory_meta.source value.
var agyTreeDefaultSurface = map[Layout]models.SessionSurface{
	LayoutDesktopDB: {Surface: models.SurfaceIDE, SurfaceHost: "antigravity"},
}

// agyDBEnrichment is what an agy .db contributes to the rows the
// sibling transcript synthesizes, read once per parse by EITHER owner
// so the two produce byte-identical rows: the raw source, the resolved
// surface, and the first generation's API model id.
type agyDBEnrichment struct {
	source  int64
	hasMeta bool
	model   string
}

// surface applies the two tables. stamp is false when nothing should
// be written (no trajectory_meta row, or an unmapped value in the CLI
// tree); known is false when the tree default was used.
func (e agyDBEnrichment) surface(layout Layout) (surf models.SessionSurface, known, stamp bool) {
	if !e.hasMeta {
		return models.SessionSurface{}, false, false
	}
	if row, ok := agySourceSurface[e.source]; ok {
		return row.surface, true, true
	}
	surf, stamp = agyTreeDefaultSurface[layout]
	return surf, false, stamp
}

// captureSource is the raw discriminator string for ActionMetadata.
func (e agyDBEnrichment) captureSource() string {
	if !e.hasMeta {
		return ""
	}
	return "trajectory_meta.source=" + strconv.FormatInt(e.source, 10)
}

// readAgyDBEnrichment reads trajectory_meta.source (first row — one
// trajectory per .db in every live sample) and the first gen_metadata
// model id from an open .db. Absent tables degrade to the zero value.
func readAgyDBEnrichment(ctx context.Context, db *sql.DB) agyDBEnrichment {
	var e agyDBEnrichment
	var v sql.NullInt64
	if err := db.QueryRowContext(ctx, "SELECT source FROM trajectory_meta LIMIT 1").Scan(&v); err == nil && v.Valid {
		e.source, e.hasMeta = v.Int64, true
	}
	rows, err := db.QueryContext(ctx, "SELECT data FROM gen_metadata ORDER BY idx")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if rows.Scan(&data) != nil {
				continue
			}
			if g := decodeGenMetadata(data); g.model != "" {
				e.model = g.model
				break
			}
		}
	}
	return e
}

// openAgyDB opens an agy .db read-only.
func openAgyDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1&_pragma=busy_timeout(2000)", sqlitedsn.Escape(path))
	return sql.Open("sqlite", dsn)
}

// agyDBEnrichmentFor is the transcript-side entry: when a sibling .db
// exists for the conversation, read its enrichment so the transcript
// parse emits the same rows the .db parse would. ok is false when
// there is no readable sibling.
func agyDBEnrichmentFor(ctx context.Context, dbPath string) (agyDBEnrichment, bool) {
	if dbPath == "" || !fileExists(dbPath) {
		return agyDBEnrichment{}, false
	}
	db, err := openAgyDB(dbPath)
	if err != nil {
		return agyDBEnrichment{}, false
	}
	defer db.Close()
	return readAgyDBEnrichment(ctx, db), true
}

// parseCLIDB reads an agy-backed conversation store —
// .gemini/antigravity-cli/conversations/<uuid>.db (the CLI, verified
// 2026-06-26) or .gemini/antigravity/conversations/<uuid>.db (the VS
// Code extension's bundled agy, verified 2026-09-03; identical schema:
// battle_mode_infos / executor_metadata / gen_metadata /
// parent_references / steps / trajectory_meta / trajectory_metadata_blob).
// The SQLite blobs are PLAINTEXT protobuf, so no OSCrypt decryption or
// gRPC bridge is needed: gen_metadata yields one TokenEvent per
// generation, trajectory_meta.source the surface, trajectory_metadata_blob
// the project, and the sibling brain/<uuid> transcript the conversation
// TEXT + tool ACTIONS — keyed on the TRANSCRIPT path with the same ids
// the transcript session file uses (see conversationOwner), so the two
// owners never double-list a conversation whichever is parsed first.
//
// Each gen_metadata.data blob is the per-generation message (the same shape
// the structured .pb decoder sees as `1.3[]`), so its usage submessage at
// path 1.17.2.X uses the IDENTICAL field map as structured.go's
// `1.3.1.17.2.X` (1=input, 2=cacheCreation, 5=cacheRead, 9=reasoning,
// 10=output; .3 == .9 + .10, confirmed in live data). The model id is the
// string at 1.19. This reuses the documented mapping rather than guessing.
//
// What the field map MEANS, re-read 2026-09-03 against 20 real Gemini
// generations (10 VS Code-extension + 10 CLI): field 1 is CONSTANT per
// conversation (1071 / 1318) while fields 2 and 5 sum to the growing
// prompt (field 5 absent on the cache-miss generations, where field 2
// carries the whole prompt), and field 3 = field 9 + field 10. That is
// exactly the Anthropic-style split Antigravity normalizes every
// provider onto — 1 = the uncached, un-written suffix (the per-request
// ephemeral context), 2 = the prefix newly written to cache, 5 = the
// prefix read from cache — so the map is not mislabelled; it is NOT
// Gemini's own usage_metadata numbering (1 prompt / 2 candidates /
// 3 cached / 4 total / 10 thoughts), which this proto does not follow.
// Cost caveat: Gemini bills an uncached prompt at the input rate with no
// cache-write premium, so a pricing row whose CacheCreation rate exceeds
// its Input rate overstates the field-2 portion for Gemini-model rows.
func (a *Adapter) parseCLIDB(ctx context.Context, path string, fromOffset, watermark int64) (adapter.ParseResult, error) {
	res := adapter.ParseResult{NewOffset: watermark}
	layout := classifyLayout(path)

	conversationID := uuidFromFilename(path)
	if conversationID == "" {
		return res, nil
	}
	projectRoot, gitRemote, projectIdentity := "[antigravity]", "", git.Identity{}
	if idx := a.lookupCLIIndexEntry(path, conversationID); idx != nil && idx.workspaceURI != "" {
		if root, remote, id := decodeFileURIToRoot(idx.workspaceURI); root != "" {
			projectRoot = root
			gitRemote = remote
			projectIdentity = id
		}
	}

	db, err := openAgyDB(path)
	if err != nil {
		return res, fmt.Errorf("antigravity.parseCLIDB: open: %w", err)
	}
	defer db.Close()

	// The .db carries its own conversation→project binding in
	// trajectory_metadata_blob (field 18 = project id), which resolves to the
	// workspace folder via ~/.gemini/config/projects/<id>.json. This is more
	// reliable for the .db layout than lookupCLIIndexEntry's cli-*.log regex
	// (which depends on log retention and only matches UUID project ids), so
	// it fills the gap when the log path missed. A no-workspace conversation
	// (the default-cli-project) resolves to "" here and is left for the
	// transcript recovery below.
	if projectRoot == "[antigravity]" {
		if root, remote, id := projectRootFromTrajectoryMeta(ctx, db, path); root != "" {
			projectRoot = root
			gitRemote = remote
			projectIdentity = id
		}
	}

	// Surface: trajectory_meta.source through the table.
	enrich := readAgyDBEnrichment(ctx, db)
	if surf, known, stamp := enrich.surface(layout); stamp {
		surf.SessionID = conversationID
		res.SessionSurfaces = append(res.SessionSurfaces, surf)
		if !known && fromOffset == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf(
				"antigravity: %s has an unmapped trajectory_meta.source=%d (grounded values: 1 = VS Code extension, 17 = agy CLI); surface falls back to the tree default",
				filepath.Base(path), enrich.source))
		}
	} else if enrich.hasMeta && fromOffset == 0 {
		res.Warnings = append(res.Warnings, fmt.Sprintf(
			"antigravity: %s has an unmapped trajectory_meta.source=%d (grounded values: 1 = VS Code extension, 17 = agy CLI); no surface stamped",
			filepath.Base(path), enrich.source))
	}

	rows, err := db.QueryContext(ctx, "SELECT idx, data FROM gen_metadata ORDER BY idx")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			if ctx.Err() != nil {
				adapter.ApplyProjectIdentity(&res, projectIdentity)
				return res, ctx.Err()
			}
			var idx int64
			var data []byte
			if err := rows.Scan(&idx, &data); err != nil {
				continue
			}
			gen := decodeGenMetadata(data)
			if gen.input == 0 && gen.output == 0 && gen.cacheRead == 0 && gen.cacheCreation == 0 && gen.reasoning == 0 {
				continue
			}
			res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
				SourceFile:          path,
				SourceEventID:       fmt.Sprintf("antigravity-cli-db:%s:gen:%d", conversationID, idx),
				SessionID:           conversationID,
				ProjectRoot:         projectRoot,
				GitRemote:           gitRemote,
				Tool:                models.ToolAntigravity,
				Model:               gen.model,
				InputTokens:         int64(gen.input),
				OutputTokens:        int64(gen.output),
				CacheReadTokens:     int64(gen.cacheRead),
				CacheCreationTokens: int64(gen.cacheCreation),
				ReasoningTokens:     int64(gen.reasoning),
				Source:              models.TokenSourceJSONL,
				Reliability:         models.ReliabilityApproximate,
				MessageID:           fmt.Sprintf("%s:gen:%d", conversationID, idx),
			})
		}
		if err := rows.Err(); err != nil {
			adapter.ApplyProjectIdentity(&res, projectIdentity)
			return res, fmt.Errorf("antigravity.parseCLIDB: scan: %w", err)
		}
	}
	// (A schema without gen_metadata degrades to no token rows rather
	// than failing the whole parse.)
	adapter.ApplyProjectIdentity(&res, projectIdentity)

	// gen_metadata yields only token usage — recover the conversation TEXT
	// (user prompts, assistant/planner responses) AND the tool ACTIONS from
	// the sibling brain/<uuid>/.system_generated/logs/transcript.jsonl.
	// Without this the dashboard shows token rows with no message body
	// ("API call (no recovered text)"). The transcript is also the last
	// rung of the project-root ladder (tool-call Cwd, then the IDE's
	// ADDITIONAL_METADATA stamp) for workspace-less conversations.
	transcriptPath := transcriptPathFor(path, conversationID)
	entries := readTranscriptEntries(transcriptPath, false)
	if len(entries) == 0 {
		// No brain/ transcript yet (fresh agy session, or a cleaned-up
		// brain/ dir): the CLI tree still has the global history.jsonl
		// user-input log to fall back on; the desktop tree has nothing.
		a.augmentResultFromHistory(path, conversationID, projectRoot, gitRemote, &res)
		return res, nil
	}
	if projectRoot == "[antigravity]" {
		if cwd := transcriptProjectRootHint(entries); cwd != "" {
			if r, rem := rootFromWorkingDir(cwd); r != "" {
				projectRoot, gitRemote = r, rem
			}
		}
	}
	if projectRoot == "[antigravity]" {
		if derived := extractProjectRootFromTranscript(entries); derived != "" {
			projectRoot = derived
		}
	}
	applyResolvedProjectRoot(&res, projectRoot)
	var sc Scrubber
	if a.scrubber != nil {
		sc = a.scrubber
	}
	coveredUser, coveredAssistant := a.legacyTextCoverage(path, conversationID)
	res.ToolEvents = append(res.ToolEvents, synthesizeDesktopTranscriptEvents(transcriptSynthInput{
		// Keyed on the TRANSCRIPT, not this .db, so the transcript
		// session file's own parse produces the identical rows.
		sessionPath:      transcriptPath,
		conversationID:   conversationID,
		projectRoot:      projectRoot,
		gitRemote:        gitRemote,
		scrubber:         sc,
		entries:          entries,
		coveredUser:      coveredUser,
		coveredAssistant: coveredAssistant,
		// The .db names the real API model id per generation; it beats
		// the transcript's vendor DISPLAY name on the text/action rows.
		modelOverride: enrich.model,
		captureSource: enrich.captureSource(),
	})...)
	return res, nil
}

// legacyTextCoverage collects the user_prompt / assistant-text Targets
// already persisted for this conversation under the source_files older
// builds wrote them to — the encrypted .pb (the pre-2026-09-03
// augmentation) and the .db itself (the text-only augmentation that
// keyed rows on the .db) — so the cut-over to transcript-keyed rows
// never re-lists a prompt or reply. Best-effort: nil without a
// TargetCoverageReader. Tool rows were never emitted by either legacy
// path, so they need no coverage; the one exception (a host where .pb
// decrypt worked and structured.* tool rows exist) is documented in
// doc.go as a known upgrade duplicate.
func (a *Adapter) legacyTextCoverage(path, conversationID string) (user, asst []string) {
	if a.targetCoverageReader == nil {
		return nil, nil
	}
	var candidates []string
	switch classifyLayout(path) {
	case LayoutDesktopTranscript:
		candidates = append(candidates,
			desktopSiblingPath(path, conversationID, ".pb"),
			desktopSiblingPath(path, conversationID, ".db"))
	case LayoutDesktopDB:
		candidates = append(candidates, path, desktopSiblingPath(path, conversationID, ".pb"))
	case LayoutCLIDB:
		candidates = append(candidates, path)
		if cliRoot, _ := cliRootsFor(path); cliRoot != "" {
			candidates = append(candidates, filepath.Join(cliRoot, "conversations", conversationID+".pb"))
		}
	}
	for _, c := range candidates {
		if c == "" || !fileExists(c) {
			continue
		}
		u, t := a.loadPersistedTargetCoverage(c)
		user = append(user, u...)
		asst = append(asst, t...)
	}
	return user, asst
}

// projectRootFromTrajectoryMeta resolves a conversation's workspace root
// from the .db's own trajectory_metadata_blob: field 18 is the project id,
// which maps to a workspace folder via ~/.gemini/config/projects/<id>.json
// (projectResources.resources[].gitFolder.folderUri for the CLI's own
// projects, resources[].folderUri for the VS Code extension's). Returns ""
// when the blob/field/project-file is absent or the project has no
// workspace folder (e.g. the default-cli-project), so the caller falls back.
func projectRootFromTrajectoryMeta(ctx context.Context, db *sql.DB, sessionPath string) (root, remote string, id git.Identity) {
	var data []byte
	row := db.QueryRowContext(ctx, "SELECT data FROM trajectory_metadata_blob LIMIT 1")
	if err := row.Scan(&data); err != nil || len(data) == 0 {
		return "", "", git.Identity{}
	}
	projectID := projectIDFromTrajectoryBlob(data)
	if projectID == "" {
		return "", "", git.Identity{}
	}
	geminiRoot := geminiRootFor(sessionPath)
	if geminiRoot == "" {
		return "", "", git.Identity{}
	}
	proj, ok := readCLIProjectFile(filepath.Join(geminiRoot, "config", "projects", projectID+".json"))
	if !ok {
		return "", "", git.Identity{}
	}
	if uri := proj.workspaceURI(); uri != "" {
		return decodeFileURIToRoot(uri)
	}
	return "", "", git.Identity{}
}

// projectIDFromTrajectoryBlob walks a trajectory_metadata_blob protobuf and
// returns the top-level field 18 (project id) string. protowire.Walk yields
// top-level fields before recursing and treats malformed nested payloads as
// soft failures, so field 18 is reached even past the opaque field 15.
func projectIDFromTrajectoryBlob(data []byte) string {
	var id string
	_ = protowire.Walk(data, func(f protowire.Field) error {
		if id == "" && len(f.Path) == 1 && f.Path[0] == 18 &&
			f.WireType == protowire.WireBytes && protowire.IsLikelyText(f.Bytes) {
			id = string(f.Bytes)
		}
		return nil
	})
	return id
}

// genUsage holds the per-generation model + token counts decoded from a
// gen_metadata.data protobuf blob.
type genUsage struct {
	model         string
	input         uint64
	output        uint64
	cacheRead     uint64
	cacheCreation uint64
	reasoning     uint64
}

// decodeGenMetadata walks a gen_metadata.data blob and pulls the model id
// (1.19) and the usage counts (1.17.2.X) using the same field map the
// structured .pb decoder applies to 1.3.1.17.2.X.
func decodeGenMetadata(buf []byte) genUsage {
	var g genUsage
	_ = protowire.Walk(buf, func(f protowire.Field) error {
		switch {
		case pathEq(f.Path, 1, 19) && f.WireType == protowire.WireBytes:
			if g.model == "" && protowire.IsLikelyText(f.Bytes) {
				g.model = string(f.Bytes)
			}
		case len(f.Path) == 4 && pathPrefix(f.Path, 1, 17, 2) && f.WireType == protowire.WireVarint:
			switch f.Path[3] {
			case 1:
				g.input = f.Varint
			case 2:
				g.cacheCreation = f.Varint
			case 5:
				g.cacheRead = f.Varint
			case 9:
				g.reasoning = f.Varint
			case 10:
				g.output = f.Varint
			}
		}
		return nil
	})
	return g
}
