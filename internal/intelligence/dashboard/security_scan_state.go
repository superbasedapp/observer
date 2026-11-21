package dashboard

import (
	"context"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_scan_state.go is the in-memory state of the Code security
// page's "Scan now" job (security_scan_now.go): at most one job at a time,
// the last one kept for the page to read, dropped on a daemon restart. It
// carries no security package import so a build that omits the pillar
// still compiles the Server struct that holds it.

// securityScanJobs owns the scan job state.
type securityScanJobs struct {
	mu     sync.Mutex
	job    *securityScanJobJS
	cancel context.CancelFunc
	// steps caches the scanners list (each ready check opens a scanner's
	// env), refreshed at most once per securityScanStepsTTL.
	steps   []dashapi.SecurityScanStep
	stepsAt time.Time
	// online caches the online dependency check's state for the GET, at
	// most securityScanOnlineTTL old.
	online   *dashapi.SecurityScanOnline
	onlineAt time.Time
}

// securityScanJobJS is one job as GET /api/security/scan shows it. Steps
// are the scanner step ids the job runs on each project, in order (the
// chosen ones, or every ready one); Online reports that the job asked the
// dependency step to also match online (each project's result says
// whether it did).
type securityScanJobJS struct {
	ID         string                  `json:"id"`
	State      string                  `json:"state"`
	Scope      string                  `json:"scope"`
	StartedAt  string                  `json:"started_at"`
	FinishedAt string                  `json:"finished_at,omitempty"`
	Total      int                     `json:"total"`
	Done       int                     `json:"done"`
	Steps      []string                `json:"steps"`
	Online     bool                    `json:"online,omitempty"`
	Current    *securityScanCurrentJS  `json:"current,omitempty"`
	Projects   []securityScanProjectJS `json:"projects"`
}

// securityScanCurrentJS is the project and step a running job is on: the
// step's label (Step), its id and when it started (RFC3339).
type securityScanCurrentJS struct {
	ProjectRootHash string `json:"project_root_hash"`
	Name            string `json:"name"`
	Step            string `json:"step"`
	StepID          string `json:"step_id,omitempty"`
	StartedAt       string `json:"started_at,omitempty"`
}

// securityScanProjectJS is one project's results in a job.
type securityScanProjectJS struct {
	ProjectRootHash string                       `json:"project_root_hash"`
	ProjectID       int64                        `json:"project_id,omitempty"`
	Name            string                       `json:"name"`
	Steps           []dashapi.SecurityScanResult `json:"steps"`
}

// The job states.
const (
	securityScanRunning   = "running"
	securityScanDone      = "done"
	securityScanCancelled = "cancelled"
)
