package firstrunstate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/planechoice"
)

// Filename is the state file's name beside the node database.
const Filename = "firstrun-state.json"

// Schema is the file's schema version.
const Schema = 1

const maxBytes = 64 << 10

// Install is what the install looked like when it was first recorded.
type Install string

// The install kinds.
const (
	// InstallUnknown: nothing recorded yet.
	InstallUnknown Install = ""
	// InstallFresh: the database held no sessions at the first record.
	InstallFresh Install = "fresh"
	// InstallExisting: the database already held sessions (an upgrade).
	InstallExisting Install = "existing"
)

// State is the persisted first-run state.
type State struct {
	Schema     int        `json:"schema"`
	Install    Install    `json:"install,omitempty"`
	RecordedAt *time.Time `json:"recorded_at,omitempty"`
	// SeenAt is when the owner closed the view for good; nil while unseen.
	SeenAt *time.Time `json:"seen_at,omitempty"`
	// Dismissed records, per dashboard notice key, when the owner dismissed
	// it for good (WINNODE2 16b: the product tour, the "Review components"
	// card). Kept on the daemon so a dismissal holds when the browser's
	// own storage does not (a profile whose storage is not persisted, a
	// second browser). The dashboard owns the closed set of keys.
	Dismissed map[string]time.Time `json:"dismissed,omitempty"`
	// Snoozed records, per dashboard notice key, when the owner last put
	// the notice away for a while (the Overview "Get started" panel, which
	// comes back as a one-line strip after a week). Unlike Dismissed, a
	// later snooze replaces the earlier time. The dashboard owns the closed
	// set of keys and the return interval.
	Snoozed map[string]time.Time `json:"snoozed,omitempty"`
	// Receipt is the first-prompt receipt milestone (the live ribbon's
	// first milestone): armed once, fired once. Additive; a state written
	// before it existed reads as never armed.
	Receipt *Receipt `json:"receipt,omitempty"`
	// Focus is what the owner chose the machine is for (Settings > General
	// "What you use superbased for", the first-run switch): coding, apps or
	// both, "" while never chosen (first-run plan 2.5 and 6, review P-17).
	// Additive; validated on read against planechoice's closed table.
	Focus planechoice.Choice `json:"focus,omitempty"`
	// Intent is the FIRST arrival intent seen on this machine (a for= link,
	// the connect hand-off, `observer apps on`, the installer's --apps),
	// kept so an upgrade or a second visit gives the same answer (plan 2.2,
	// review P-06). Later intents never replace it.
	Intent *Intent `json:"intent,omitempty"`
}

// Intent is one recorded arrival intent.
type Intent struct {
	Choice planechoice.Choice       `json:"choice"`
	Source planechoice.IntentSource `json:"source"`
	At     time.Time                `json:"at"`
}

// IntentChoice returns the recorded intent's choice, "" when none.
func (s State) IntentChoice() planechoice.Choice {
	if s.Intent == nil {
		return planechoice.ChoiceNone
	}
	return s.Intent.Choice
}

// Receipt is the once-per-install "Your first captured prompt" milestone.
// ArmedAt is when the dashboard first asked for it (the first ribbon read):
// only a session that STARTED after it may fire it. FiredAt, SessionID and
// Body are set once, when it fires; Body is the caller's own JSON summary
// (counts and labels only, never content or paths), kept so the receipt
// shows the numbers it fired with. Whether the owner has seen it is a
// dismissal (Dismissed), not a field here.
type Receipt struct {
	ArmedAt   time.Time       `json:"armed_at"`
	FiredAt   *time.Time      `json:"fired_at,omitempty"`
	SessionID string          `json:"session_id,omitempty"`
	Body      json.RawMessage `json:"body,omitempty"`
}

// maxReceiptBody bounds a fired receipt's summary.
const maxReceiptBody = 4 << 10

// DismissedKeys returns the dismissed notice keys, sorted.
func (s State) DismissedKeys() []string {
	out := make([]string, 0, len(s.Dismissed))
	for k := range s.Dismissed {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Seen reports whether the owner has closed the view for good.
func (s State) Seen() bool { return s.SeenAt != nil }

// AutoOpen reports whether the dashboard should open the first-run view by
// itself: only on a fresh install that has not been marked seen.
func AutoOpen(s State) bool { return s.Install == InstallFresh && !s.Seen() }

// Path returns the state file beside dbPath ("" when dbPath is empty).
func Path(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), Filename)
}

// Store serializes this process's reads and writes of one state file.
type Store struct {
	path string
	mu   sync.Mutex
}

// New returns the store for path. An empty path keeps nothing: Load returns
// the zero State and every write is a no-op, which is what a dashboard with
// no database path (tests, demo) wants.
func New(path string) *Store { return &Store{path: path} }

// Load returns the persisted state. A missing, oversized or unreadable file
// is "nothing recorded yet", never an error.
func (s *Store) Load() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

// RecordInstall records the install kind once. fresh reports whether the
// database held no sessions; it is only consulted when nothing is recorded
// yet, so a later start never turns an existing install fresh or back.
func (s *Store) RecordInstall(fresh bool, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if st.Install != InstallUnknown || s.path == "" {
		return st, nil
	}
	st.Install = InstallExisting
	if fresh {
		st.Install = InstallFresh
	}
	at := now.UTC()
	st.RecordedAt = &at
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.RecordInstall: %w", err)
	}
	return st, nil
}

// SetSeen marks the view seen (true) or clears the mark (false).
func (s *Store) SetSeen(seen bool, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" {
		return st, nil
	}
	if seen {
		at := now.UTC()
		st.SeenAt = &at
	} else {
		st.SeenAt = nil
	}
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.SetSeen: %w", err)
	}
	return st, nil
}

// Dismiss records key as dismissed for good. Dismissing a key twice keeps
// the first time.
func (s *Store) Dismiss(key string, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" || key == "" {
		return st, nil
	}
	if _, ok := st.Dismissed[key]; ok {
		return st, nil
	}
	if st.Dismissed == nil {
		st.Dismissed = map[string]time.Time{}
	}
	st.Dismissed[key] = now.UTC()
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.Dismiss: %w", err)
	}
	return st, nil
}

// ArmReceipt arms the first-prompt receipt at now, once: an already-armed
// (or fired) receipt is left as it is.
func (s *Store) ArmReceipt(now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" || st.Receipt != nil {
		return st, nil
	}
	st.Receipt = &Receipt{ArmedAt: now.UTC()}
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.ArmReceipt: %w", err)
	}
	return st, nil
}

// FireReceipt records the receipt as fired for sessionID with its summary
// body, once: an unarmed or already-fired receipt is left as it is, and an
// oversized body is refused.
func (s *Store) FireReceipt(sessionID string, body []byte, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" || st.Receipt == nil || st.Receipt.FiredAt != nil || sessionID == "" {
		return st, nil
	}
	if len(body) > maxReceiptBody || !json.Valid(body) {
		return st, fmt.Errorf("firstrunstate.FireReceipt: body is not a JSON object under %d bytes", maxReceiptBody)
	}
	at := now.UTC()
	r := *st.Receipt
	r.FiredAt = &at
	r.SessionID = sessionID
	r.Body = append(json.RawMessage(nil), body...)
	st.Receipt = &r
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.FireReceipt: %w", err)
	}
	return st, nil
}

// Snooze records key as put away at now, replacing any earlier snooze of
// the same key (each dismissal starts the return interval again).
func (s *Store) Snooze(key string, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" || key == "" {
		return st, nil
	}
	if st.Snoozed == nil {
		st.Snoozed = map[string]time.Time{}
	}
	st.Snoozed[key] = now.UTC()
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.Snooze: %w", err)
	}
	return st, nil
}

// SetFocus stores the owner's choice; ChoiceNone clears it (back to the
// inferred track). A value outside the closed table is refused.
func (s *Store) SetFocus(c planechoice.Choice) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if c != planechoice.ChoiceNone {
		if _, ok := planechoice.ParseChoice(string(c)); !ok {
			return st, fmt.Errorf("firstrunstate.SetFocus: %q is not a choice", c)
		}
	}
	if s.path == "" || st.Focus == c {
		return st, nil
	}
	st.Focus = c
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.SetFocus: %w", err)
	}
	return st, nil
}

// RecordIntent stores the arrival intent the first time one is seen; a
// later intent leaves the first in place (recorded reports which). Values
// outside the closed tables are refused.
func (s *Store) RecordIntent(c planechoice.Choice, src planechoice.IntentSource, now time.Time) (st State, recorded bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st = s.read()
	if _, ok := planechoice.ParseChoice(string(c)); !ok {
		return st, false, fmt.Errorf("firstrunstate.RecordIntent: %q is not a choice", c)
	}
	if _, ok := planechoice.ParseIntentSource(string(src)); !ok {
		return st, false, fmt.Errorf("firstrunstate.RecordIntent: %q is not an intent source", src)
	}
	if s.path == "" || st.Intent != nil {
		return st, false, nil
	}
	st.Intent = &Intent{Choice: c, Source: src, At: now.UTC()}
	if err := s.write(st); err != nil {
		return st, false, fmt.Errorf("firstrunstate.RecordIntent: %w", err)
	}
	return st, true, nil
}

func (s *Store) read() State {
	out := State{Schema: Schema}
	if s.path == "" {
		return out
	}
	fh, err := os.Open(s.path)
	if err != nil {
		return out
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return out
	}
	var st State
	if json.Unmarshal(data, &st) != nil || st.Schema != Schema {
		return out
	}
	switch st.Install {
	case InstallUnknown, InstallFresh, InstallExisting:
	default:
		st.Install = InstallUnknown
	}
	// A hand-edited or future value outside the closed tables reads as
	// nothing recorded, never as a choice.
	if st.Focus != planechoice.ChoiceNone {
		if _, ok := planechoice.ParseChoice(string(st.Focus)); !ok {
			st.Focus = planechoice.ChoiceNone
		}
	}
	if st.Intent != nil {
		_, okC := planechoice.ParseChoice(string(st.Intent.Choice))
		_, okS := planechoice.ParseIntentSource(string(st.Intent.Source))
		if !okC || !okS {
			st.Intent = nil
		}
	}
	return st
}

func (s *Store) write(st State) error {
	st.Schema = Schema
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(s.path, data, fsatomic.Options{TempPattern: ".firstrun-*.tmp"})
}
