// Package deletionjournal is the append-only account-deletion journal that
// lives OUTSIDE the Postgres restore domain (divergence remediation plan §3
// W6d, rev-4 F8).
//
// Why it exists: replaying a restored database's own deletion_requests to
// re-apply tombstones is circular — a point-in-time restore to a moment BEFORE
// a deletion request contains no request to replay, so the restored service
// would reopen with the deleted account's data resurrected. The journal is a
// SEPARATE durable record, on a different lifecycle from DB backups, that the
// restore runbook ingests to re-apply every completed/accepted deletion BEFORE
// the restored service reopens.
//
// The interface is injected into the store (an I/O boundary, like the blob
// store). Two implementations ship: FileJournal (an append-only JSONL file on a
// durable volume — the local/default impl, and what the tests use) and the
// production target, an Azure append blob in the storage account, bound at
// deploy time (a documented operator-owed infra item; the FileJournal contract
// is the same shape). The journal is a HARD dependency of the deletion path:
// the store refuses to run a deletion with no journal configured, so a deletion
// can never reach 'done' without a durable, restore-surviving record of it.
package deletionjournal

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is the deletion lifecycle point a record marks.
type Event string

const (
	// EventAccepted is written BEFORE the destructive transaction commits, so a
	// restore to any point after the request still finds it. This is the record
	// that drives restore-suppression.
	EventAccepted Event = "accepted"
	// EventDone is written after the deletion transaction commits. It is
	// informational — suppression only needs EventAccepted — so a crash between
	// commit and this write is harmless.
	EventDone Event = "done"
)

// Record is one immutable journal line. It carries NO account content — only the
// opaque account UUID, the request id, the event, and the time. That is all the
// restore runbook needs to re-tombstone.
type Record struct {
	Event     Event     `json:"event"`
	AccountID string    `json:"account_id"`
	RequestID string    `json:"request_id"`
	At        time.Time `json:"at"`
}

// Journal is the append-only sink + reader the store depends on.
type Journal interface {
	// Append durably records one line. It MUST return only after the record is
	// durably persisted (an fsync for the file impl) so a crash immediately
	// after cannot lose it.
	Append(ctx context.Context, rec Record) error
	// Records returns every record ever appended, in append order. The restore
	// runbook reads this to re-apply suppressions.
	Records(ctx context.Context) ([]Record, error)
}

// FileJournal is an append-only JSONL file. Each Append opens the file with
// O_APPEND, writes one JSON line, and fsyncs — durable and crash-safe for the
// rare deletion event. A process-level mutex serializes concurrent appends so
// two deletions can never interleave a partial line.
type FileJournal struct {
	path string
	mu   sync.Mutex
}

// NewFileJournal returns a FileJournal writing to path, creating the parent
// directory if needed. It does not open the file until the first Append.
func NewFileJournal(path string) (*FileJournal, error) {
	if path == "" {
		return nil, fmt.Errorf("deletionjournal: empty path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("deletionjournal: mkdir: %w", err)
	}
	return &FileJournal{path: path}, nil
}

// Append writes one record as a JSON line and fsyncs before returning.
func (j *FileJournal) Append(_ context.Context, rec Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("deletionjournal.Append: marshal: %w", err)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.OpenFile(j.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("deletionjournal.Append: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("deletionjournal.Append: write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("deletionjournal.Append: fsync: %w", err)
	}
	return nil
}

// Records reads every appended record in order. A missing file is an empty
// journal (no deletions yet), not an error.
func (j *FileJournal) Records(_ context.Context) ([]Record, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	f, err := os.Open(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("deletionjournal.Records: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("deletionjournal.Records: corrupt line: %w", err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("deletionjournal.Records: scan: %w", err)
	}
	return out, nil
}

// AcceptedAccounts returns the set of account ids that have an EventAccepted
// record — the accounts a restore must re-suppress. Deduplicated.
func AcceptedAccounts(records []Record) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, r := range records {
		if r.Event != EventAccepted {
			continue
		}
		if _, ok := seen[r.AccountID]; ok {
			continue
		}
		seen[r.AccountID] = struct{}{}
		out = append(out, r.AccountID)
	}
	return out
}
