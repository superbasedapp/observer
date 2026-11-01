package sandboxremote

import (
	"context"
	"errors"
	"io"
	"time"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// provider.go is the one seam between the remote drivers and a vendor's
// wire client (CLAUDE.md rule 2): the cmd layer speaks Client, each of the
// e2b, modal and vercel packages implements it, and no vendor type leaks
// past it.

// The wire-client errors the drivers branch on.
var (
	// ErrNotFound: the vendor no longer has the box (delete confirmed, or a
	// lost create proved absent).
	ErrNotFound = errors.New("remote box not found")
	// ErrNotSupported: the vendor documents no such operation (reattach on
	// Modal and Vercel).
	ErrNotSupported = errors.New("not supported by this provider")
	// ErrRateLimited: the vendor answered 429 after the client's own bounded
	// retries.
	ErrRateLimited = errors.New("provider rate limit")
	// ErrCreateUnknown: the create call's outcome is unknown (the response
	// was lost); the box may exist under its label.
	ErrCreateUnknown = errors.New("create outcome unknown")
	// ErrTemplateUnavailable: the vendor refused the create because the
	// template, image or runtime it was given is not one it can start (no
	// box was made).
	ErrTemplateUnavailable = errors.New("template not available")
)

// LabelKey is the metadata key every box carries, valued with the run id.
const LabelKey = "observer-run"

// BoxSpec is what a create asks for.
type BoxSpec struct {
	RunID string
	// Labels are set as vendor metadata or tags (LabelKey always).
	Labels map[string]string
	// Template is the vendor template, image or runtime the user named
	// ("" for the vendor default).
	Template string
	// TimeoutSeconds is the vendor's own box timeout (never zero).
	TimeoutSeconds int
	Tier           vocab.Tier
	Region         string
	// Env is the box's base environment (never a provider credential of the
	// sandbox vendor; a model credential only under an in-box custody).
	Env map[string]string
}

// BoxInfo is what a vendor says about one box.
type BoxInfo struct {
	ID     string
	Region string
	// Running is false once the vendor reports the box stopped.
	Running bool
	Labels  map[string]string
	// Extra carries vendor identifiers other than the id (never a secret).
	Extra    map[string]string
	Deadline time.Time
	// EnvdToken is a per-box access secret the vendor returned (E2B); the
	// cmd layer writes it owner-only and deletes it at teardown.
	EnvdToken string
}

// ExecSpec is one process in the box.
type ExecSpec struct {
	Argv []string
	Env  map[string]string
	Cwd  string
	// PTY asks the vendor for a terminal (only when the vendor documents a
	// resize; otherwise the guest helper owns the PTY).
	PTY        bool
	Rows, Cols uint16
	// Stdin: the process reads a streaming stdin.
	Stdin bool
	// AsRoot runs the process as the box's root user (E2B's root user,
	// Vercel's sudo; Modal runs as root): used only for the setup step that
	// creates the workspace path and hands it to the box user.
	AsRoot bool
	// Stderr, when set, receives a non-PTY process's stderr (nil discards
	// it, as before). The relay process's stderr reaches the run's kept
	// relay log through it (lane SBX-UPD, finding H1).
	Stderr io.Writer
}

// Process is one running process in a box. Read returns its output (stdout
// and, for a PTY, the terminal; stderr of a non-PTY process is discarded
// by the client unless it says otherwise), Write feeds its stdin or
// terminal. A vendor stream has no deadlines: the relay wraps it in a
// deadline adapter.
type Process interface {
	io.Reader
	io.Writer
	// PID is the vendor's process handle (for a reattach).
	PID() string
	// Resize changes the terminal size (ErrNotSupported without a
	// documented resize).
	Resize(ctx context.Context, rows, cols uint16) error
	// Wait returns the exit code once the process ends.
	Wait(ctx context.Context) (int, error)
	// Kill ends the process.
	Kill(ctx context.Context) error
	// Close releases the stream (the process keeps running where the vendor
	// keeps it).
	Close() error
}

// UploadFile is one file to write into a box.
type UploadFile struct {
	// Path is absolute in the box.
	Path string
	Mode uint32
	Size int64
	// Open returns the content (called once, closed by the client).
	Open func() (io.ReadCloser, error)
}

// Client is one vendor's wire client over one credential.
type Client interface {
	Create(ctx context.Context, spec BoxSpec) (BoxInfo, error)
	Get(ctx context.Context, id string) (BoxInfo, error)
	ListByLabel(ctx context.Context, key, value string) ([]BoxInfo, error)
	Delete(ctx context.Context, id string) error
	WriteFiles(ctx context.Context, id string, files []UploadFile) error
	ReadFile(ctx context.Context, id, path string, max int64) ([]byte, error)
	Exec(ctx context.Context, id string, spec ExecSpec) (Process, error)
	// Reattach reconnects to a running process by its PID (ErrNotSupported
	// where the vendor documents none).
	Reattach(ctx context.Context, id, pid string) (Process, error)
}
