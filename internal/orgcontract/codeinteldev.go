package orgcontract

// CodeintelDevRow is the W2.4 per-developer/project code-intelligence wire
// row: one row per (org_id, user_email, project_hash, language), mirroring
// internal/store/codeintelsummary.go's SelectCodeintelSummaries aggregation
// exactly (same COUNT(DISTINCT ...) math over the node's codeintel_files /
// codeintel_nodes / codeintel_edges tables) but composed under the
// shipsRawContent() gate (enterprise-raw wire) instead of the
// share.CodeintelDetail opt-in tier. This is DELIBERATELY a new
// table/row, not a retrofit of CodeintelSummaryRow/codeintel_summaries —
// the existing teams-tier surface stays byte-identical and
// admin-only/identity-blind (see
// docs/plans/org-parity-full-depth-plan-2026-08-24.md §0, §4 "W2.4").
//
// ProjectHash stays the stable join/dedup key (the same one-way
// domain-separated hash CodeintelSummaryRow carries), and ProjectRoot
// carries the RAW git-root path alongside it — codeintel_files.project IS
// the raw path, and the enterprise posture ships raw paths to the admin
// (plan §0.1, operator ruling 2026-08-24: "all paths shall be carried").
// The teams-tier CodeintelSummaryRow remains hash-only and untouched.
// Symbol names / signatures / per-file paths are not at this row's grain
// (project × language counts); they belong to the org-wide search /
// codeintel drill tracks.
type CodeintelDevRow struct {
	// OrgID / UserEmail are the agent-stamped attribution (same stamping
	// rule as every other wire row — see ingest.go forcePusherOrgID /
	// forcePusherEmail).
	OrgID     string `json:"org_id,omitempty"`
	UserEmail string `json:"user_email,omitempty"`

	// ProjectHash is hashCodeintelProject(project) — opaque, one-way,
	// domain-separated SHA-256 hex. Natural key component (with
	// Language) on the server, same hash CodeintelSummaryRow carries.
	ProjectHash string `json:"project_hash"`
	// ProjectRoot is the RAW git-root path (codeintel_files.project,
	// verbatim) — enterprise wire under shipsRawContent(), so the admin
	// sees the real repository identity, not just a hash (§0.1). Empty on
	// rows pushed by older agents (both-direction compat).
	ProjectRoot string `json:"project_root,omitempty"`
	// ProjectRootHash is the PROJECT-IDENTITY hash — sha256 of the
	// normalized git-root path, byte-for-byte the same value
	// SessionRow.ProjectRootHash carries for the same root (both are
	// store.sha256Hex(normalizeProjectRoot(root)); see
	// internal/store/codeintelsummary.go::projectRootHashForPath and
	// store.upsertProjectBase, which is what writes projects.root_path_hash).
	// It belongs to the SAME hash-only always-ship class as
	// SessionRow.ProjectRootHash: an unsalted, content-free, cross-node
	// joinable digest of a path, never the path itself.
	//
	// WHY IT IS HERE. ProjectHash above is domain-separated
	// ("codeintel:project:v1:" + path), a DIFFERENT hash space from the
	// project identity every other org surface keys on, so a codeintel row
	// could not be joined to (or linked at) /projects/{id}. Carrying the
	// project-identity hash alongside it closes that gap without weakening
	// ProjectHash's domain separation — both ship, each for its own job.
	//
	// NOT A NEW DISCLOSURE on this wire: this row already carries
	// ProjectRoot RAW (it rides shipsRawContent()), so the server can
	// already compute this digest itself. It is carried explicitly so the
	// server never has to re-derive it — a re-derivation is exactly where a
	// normalization drift would silently 404 the link.
	//
	// Empty on rows pushed by older agents; every read must treat empty as
	// "unknown", never as a project id.
	ProjectRootHash string `json:"project_root_hash,omitempty"`
	// Language is the resolved codeintel.Language for this bucket
	// (codeintel_files.lang).
	Language string `json:"language"`

	// Files / Symbols / Edges are COUNT(DISTINCT ...) over
	// codeintel_files / codeintel_nodes / codeintel_edges for this
	// (project, lang) bucket — identical math to CodeintelSummaryRow.
	Files   int64 `json:"files"`
	Symbols int64 `json:"symbols"`
	Edges   int64 `json:"edges"`

	// LastIndexed is MAX(codeintel_files.indexed_at) for this bucket — a
	// unix-seconds timestamp of the most recent successful index pass,
	// 0 if the bucket has never completed one.
	LastIndexed int64 `json:"last_indexed"`
}
