package secposture

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Layout under the security directory (section 4.8).
const (
	// DirName is the security directory under the observer home.
	DirName = "security"
	// PostureDirName holds the per-project posture files and the key.
	PostureDirName = "posture"
	// DirtyDirName holds the per-project dirty markers.
	DirtyDirName = "dirty"
	// SeenDirName holds the per-project seen marks.
	SeenDirName = "seen"
	// KeyFilename is the posture HMAC key, inside PostureDirName.
	KeyFilename = "posture.key"
	// PostureExt is the posture file extension.
	PostureExt = ".json"
)

// Caps and timing (section 4.8, revision 2.4 [JSP-2]).
const (
	// SchemaVersion is the posture file schema this package writes.
	SchemaVersion = 1
	// MaxFileBytes caps one project's posture file; a bigger file reads as
	// unknown.
	MaxFileBytes = 16 << 10
	// MaxBlocking caps the open blocking local keys a file lists; beyond it
	// Overflow is set, and an overflowed file reads as unknown.
	MaxBlocking = 256
	// MaxHeld caps the held commits a file lists (HeldOverflow beyond it);
	// MaxRemotes caps the remotes a file names, per held commit and in
	// HistoryOnlyOn (lane sec-gate4). A dropped remote only makes a push
	// to it gated, never looser.
	MaxHeld    = 16
	MaxRemotes = 16
	// DefaultTTL is how long a signed file stays fresh.
	DefaultTTL = 5 * time.Minute
	// ResignEvery is how often the daemon re-signs at the latest (and on
	// every change).
	ResignEvery = 2 * time.Minute
	// MACDomain separates this file's HMAC from every other signed file.
	MACDomain = "sbo-security-posture-v1"
)

// Count is one cell of the open-finding counts by category and severity.
type Count struct {
	Category policy.FindingCategory `json:"category"`
	Severity policy.FindingSeverity `json:"severity"`
	N        int                    `json:"n"`
}

// HeldCommit is one held commit in a posture file: its full lower-case id
// and the remotes that already have it.
type HeldCommit struct {
	Commit  string   `json:"commit"`
	Remotes []string `json:"remotes,omitempty"`
}

// File is one project's signed posture file (section 4.8). Every field but
// MAC is covered by the MAC.
type File struct {
	// Schema is SchemaVersion.
	Schema int `json:"schema"`
	// ProjectRootHash names the project; it must equal the file name.
	ProjectRootHash string `json:"project_root_hash"`

	// File-level fields (every file carries them).

	// Packs is the active pack set: the pillar children that are active
	// (component ids), so the hook needs no component state. Empty means
	// no pillar child is active, which reads as absent.
	Packs []string `json:"packs"`
	// PolicyVersion is the security.scanning family version the file was
	// computed under; BundleVersion the guard bundle version. A file naming
	// other versions than the hook loaded reads as unknown.
	PolicyVersion string `json:"policy_version"`
	BundleVersion string `json:"bundle_version"`
	// Sequence is monotonic per node; a file below the seen mark is a
	// rollback and reads as unknown.
	Sequence  uint64    `json:"sequence"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// Project fields.

	// Blocking lists the open blocking findings' local keys (at most
	// MaxBlocking): new (or untrusted_baseline under a managed floor) and
	// high-confidence. Overflow reports that the list was capped.
	Blocking []string `json:"blocking"`
	Overflow bool     `json:"overflow"`
	// HistoryOnly lists the Blocking keys an unpushed commit alone holds
	// open: no file sighting is left (lane sec-gate3 audit finding 2). The
	// push gate counts them, the commit gate does not. Always a subset of
	// Blocking; omitted when empty, so a file without such a hold signs
	// byte for byte as before.
	HistoryOnly []string `json:"history_only,omitempty"`
	// HistoryOnlyOn counts, per remote, the HistoryOnly keys every holding
	// commit of which that remote's tracking refs already have (lane
	// sec-gate4 milestone 1a): the push gate does not count them for a
	// push to that remote. At most len(HistoryOnly) per remote; omitted
	// when empty.
	HistoryOnlyOn map[string]int `json:"history_only_on,omitempty"`
	// Held lists the unpushed commits that hold the HistoryOnly keys open
	// (at most MaxHeld, sorted by commit), each with the remotes that
	// already have it, for the gate's wording and the pre-push hook;
	// HeldOverflow reports the cap. Omitted when empty.
	Held         []HeldCommit `json:"held,omitempty"`
	HeldOverflow bool         `json:"held_overflow,omitempty"`
	// DefaultPushRemote is the remote a plain `git push` goes to, as the
	// daemon resolved it for every checked-out branch of the repository
	// (lane sec-gate4 audit finding 5): the push gate reads a plain push
	// as a push to it. Kept only with a history-only hold and a remote
	// name; omitted when empty, so a file without one signs as before.
	DefaultPushRemote string `json:"default_push_remote,omitempty"`
	// Counts are the open findings by category and severity.
	Counts []Count `json:"counts"`
	// Trust and TrustReasons are the repository trust verdict and its
	// reason codes (section 5.1).
	Trust        policy.TrustVerdict `json:"trust"`
	TrustReasons []string            `json:"trust_reasons"`
	// ScannedAt is the scan freshness: when the newest full set of the
	// project's scans finished.
	ScannedAt time.Time `json:"scanned_at"`
	// DatabaseEpoch is the advisory database epoch in force.
	DatabaseEpoch string `json:"database_epoch"`
	// DirtyCleanEpoch is the dirty counter value the last clean quick scan
	// covered. A dirty counter above it reads as dirty.
	DirtyCleanEpoch uint64 `json:"dirty_clean_epoch"`
	// QuickScanAvailable reports whether the daemon's quick-scan service
	// is serving.
	QuickScanAvailable bool `json:"quick_scan_available"`
	// OrgProjectIDs and AssignmentEpoch are the project audience match
	// (section 7.11 [JSP-10]). Reserved by Phase A, filled by Phase P.
	OrgProjectIDs   []string `json:"org_project_ids,omitempty"`
	AssignmentEpoch uint64   `json:"assignment_epoch,omitempty"`
	// CommitGateFloor and PrelaunchTrustFloor are the org security.scanning
	// floors in force for the project (lane SEC-P4 decision 9): the
	// commit gate's "quick_scan" and the launch trust step's "ask" or
	// "refuse". Omitted when none, so a file without a floor signs byte for
	// byte as before and an older file reads no floor; the MAC covers them.
	CommitGateFloor     string `json:"commit_gate_floor,omitempty"`
	PrelaunchTrustFloor string `json:"prelaunch_trust_floor,omitempty"`
	// QuickScanBudgetS is the commit gate's quick-scan budget in force for
	// the project, in seconds ([security.scanning].quick_scan_budget_s
	// raised by an org floor, lane LEFT-SEC); omitted at the built-in 2 s,
	// so a file at the default signs byte for byte as before.
	QuickScanBudgetS int `json:"quick_scan_budget_s,omitempty"`
	// MaxScanStalenessMin is the oldest scan the commit gate trusts, in
	// minutes: a ScannedAt older than this reads as unknown
	// (ReasonScanStale). Omitted (0) when off, the default.
	MaxScanStalenessMin int `json:"max_scan_staleness_min,omitempty"`
	// HistoryCapped lists the HistoryOnly keys every holding commit of
	// which is reached only past a reflog cap ([security.scanning]
	// reflog_hold_max_age_days or reflog_hold_max_entries, lane LEFT-SEC):
	// no longer held for a deny, so the push gate asks instead (S-792's
	// capped row). Always a subset of HistoryOnly; omitted when empty.
	HistoryCapped []string `json:"history_capped,omitempty"`

	// MAC is the hex HMAC-SHA256 over the canonical form under the key.
	MAC string `json:"mac"`
}
