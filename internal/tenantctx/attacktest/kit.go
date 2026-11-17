package attacktest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// Session is one dedicated database session, logged in as the adopter's
// runtime login (never a superuser or a role that bypasses row-level
// security). The kit sends it plain transaction-control statements (BEGIN,
// COMMIT, ROLLBACK, SAVEPOINT) through Exec, so every call must use the same
// connection, and a session must survive DISCARD ALL (with pgx, use a
// statement mode that does not depend on server-side prepared statements).
type Session interface {
	// Exec runs one statement with bind arguments.
	Exec(ctx context.Context, query string, args ...any) error
	// Visible returns the subjects of the probe rows the session can read
	// now, sorted and without repeats.
	Visible(ctx context.Context) ([]string, error)
	// Current returns what the database's current-subject function returns
	// now (sbo_current_org(), sbci_current_account()), "" for NULL.
	Current(ctx context.Context) (string, error)
	// Insert writes one probe row owned by subject and returns the
	// database's error (nil when the row was written).
	Insert(ctx context.Context, subject string) error
	// Close releases the session.
	Close() error
}

// Harness is what an adopter tells the kit about itself.
type Harness struct {
	// Kind is the adopter's token kind.
	Kind tenantctx.Kind
	// Key is a key the database verifies tokens against.
	Key []byte
	// A and B are two distinct subjects, each owning at least one probe
	// row before every case and after it (the kit never commits a write).
	A, B string
	// Begin is the statements that open one of the adopter's tenant
	// transactions, first "BEGIN" (then, for example, SET LOCAL ROLE).
	Begin []string
	// Open returns a fresh session; the kit closes it.
	Open func(ctx context.Context) (Session, error)
	// Now is the clock tokens are minted with (nil means time.Now). The
	// database compares expiries with its own clock, so a live harness
	// leaves it nil.
	Now func() time.Time
}

// Case is one attack: Run returns nil when the session resisted it.
type Case struct {
	Name string
	Run  func(ctx context.Context, h Harness, s Session) error
}

// Result is one case's outcome from [Check].
type Result struct {
	Case string
	Err  error
}

// Cases returns the attack table, in order. See the package documentation.
func Cases() []Case {
	return []Case{
		{Name: "valid context sees only its own subject", Run: caseValid},
		{Name: "missing context sees nothing", Run: caseMissing},
		{Name: "forged token", Run: caseForged},
		{Name: "expired token", Run: caseExpired},
		{Name: "wrong-scope token", Run: caseWrongScope},
		{Name: "token reuse across transactions", Run: caseReuse},
		{Name: "raw set_config by the runtime login", Run: caseRawSetConfig},
		{Name: "RESET", Run: caseReset},
		{Name: "DISCARD", Run: caseDiscard},
	}
}

// Run runs every case as a parallel subtest of t, each on its own session.
func Run(t *testing.T, h Harness) {
	t.Helper()
	if err := h.validate(); err != nil {
		t.Fatalf("attacktest.Run: %v", err)
	}
	for _, c := range Cases() {
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			if err := runCase(t.Context(), h, c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Check runs every case in order and returns one result per case (or one
// "harness" result when h is incomplete).
func Check(ctx context.Context, h Harness) []Result {
	if err := h.validate(); err != nil {
		return []Result{{Case: "harness", Err: err}}
	}
	cases := Cases()
	out := make([]Result, 0, len(cases))
	for _, c := range cases {
		out = append(out, Result{Case: c.Name, Err: runCase(ctx, h, c)})
	}
	return out
}

func runCase(ctx context.Context, h Harness, c Case) (err error) {
	s, err := h.Open(ctx)
	if err != nil {
		return fmt.Errorf("open a session: %w", err)
	}
	defer func() {
		if cerr := s.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close the session: %w", cerr)
		}
	}()
	return c.Run(ctx, h, s)
}

func (h Harness) validate() error {
	switch {
	case !h.Kind.Valid():
		return fmt.Errorf("unknown kind %d", uint8(h.Kind))
	case h.Open == nil:
		return errors.New("no Open")
	case len(h.Begin) == 0 || h.Begin[0] != "BEGIN":
		return errors.New(`Begin must start with "BEGIN"`)
	case h.A == h.B:
		return errors.New("A and B must differ")
	}
	if err := tenantctx.CheckKey(h.Key); err != nil {
		return err
	}
	for _, subject := range []string{h.A, h.B} {
		if err := h.Kind.CheckSubject(subject); err != nil {
			return err
		}
	}
	return nil
}

func (h Harness) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h Harness) token(subject string) (string, error) {
	s, err := tenantctx.NewSigner(h.Kind, h.Key, 0, h.Now)
	if err != nil {
		return "", err
	}
	return s.Token(subject)
}

// The statements the cases send, besides Begin and the kind's SetLocalSQL.
// The model in model_test.go understands exactly these.

func setSessionSQL(k tenantctx.Kind) string {
	return "SELECT set_config('" + k.Setting() + "', $1, false)"
}

func setPlainSQL(k tenantctx.Kind, value string) string {
	return "SET " + k.Setting() + " = '" + strings.ReplaceAll(value, "'", "''") + "'"
}

func resetSQL(k tenantctx.Kind) string { return "RESET " + k.Setting() }

func toDefaultSQL(k tenantctx.Kind) string { return "SET LOCAL " + k.Setting() + " TO DEFAULT" }

const (
	discardSQL    = "DISCARD ALL"
	savepointSQL  = "SAVEPOINT attacktest"
	rollbackToSQL = "ROLLBACK TO SAVEPOINT attacktest"
)

// inTx opens a tenant transaction, runs body and ends it with COMMIT
// (commit) or ROLLBACK.
func inTx(ctx context.Context, h Harness, s Session, commit bool, body func() error) error {
	for _, stmt := range h.Begin {
		if err := s.Exec(ctx, stmt); err != nil {
			_ = s.Exec(ctx, "ROLLBACK")
			return fmt.Errorf("open the transaction (%s): %w", stmt, err)
		}
	}
	if err := body(); err != nil {
		_ = s.Exec(ctx, "ROLLBACK")
		return err
	}
	end := "ROLLBACK"
	if commit {
		end = "COMMIT"
	}
	if err := s.Exec(ctx, end); err != nil {
		return fmt.Errorf("%s: %w", end, err)
	}
	return nil
}

// tryInsert attempts a probe write for subject under a savepoint it always
// rolls back to, so the kit never leaves a row behind.
func tryInsert(ctx context.Context, s Session, subject string) (bool, error) {
	if err := s.Exec(ctx, savepointSQL); err != nil {
		return false, fmt.Errorf("savepoint: %w", err)
	}
	ierr := s.Insert(ctx, subject)
	if err := s.Exec(ctx, rollbackToSQL); err != nil {
		return false, fmt.Errorf("rollback to savepoint: %w", err)
	}
	return ierr == nil, nil
}

// seesNothing, inside a transaction: no probe row is visible, the current
// subject is NULL and neither subject's row can be written.
func seesNothing(ctx context.Context, h Harness, s Session) error {
	if err := readsNothing(ctx, s); err != nil {
		return err
	}
	for _, subject := range []string{h.A, h.B} {
		wrote, err := tryInsert(ctx, s, subject)
		if err != nil {
			return err
		}
		if wrote {
			return fmt.Errorf("wrote a row for %s with no valid context", subject)
		}
	}
	return nil
}

// readsNothing: no probe row is visible and the current subject is NULL.
// Outside a transaction it is the whole check (a write would commit).
func readsNothing(ctx context.Context, s Session) error {
	visible, err := s.Visible(ctx)
	if err != nil {
		return fmt.Errorf("read the probe: %w", err)
	}
	if len(visible) != 0 {
		return fmt.Errorf("sees the rows of %v", visible)
	}
	current, err := s.Current(ctx)
	if err != nil {
		return fmt.Errorf("read the current subject: %w", err)
	}
	if current != "" {
		return fmt.Errorf("the current subject is %q", current)
	}
	return nil
}

// seesOnly, inside a transaction: exactly subject's rows are visible, the
// current subject is subject, and only subject's row can be written.
func seesOnly(ctx context.Context, h Harness, s Session, subject string) error {
	visible, err := s.Visible(ctx)
	if err != nil {
		return fmt.Errorf("read the probe: %w", err)
	}
	if !slices.Equal(visible, []string{subject}) {
		return fmt.Errorf("%s's context sees the rows of %v, want only %s", subject, visible, subject)
	}
	current, err := s.Current(ctx)
	if err != nil {
		return fmt.Errorf("read the current subject: %w", err)
	}
	if current != subject {
		return fmt.Errorf("%s's context: the current subject is %q", subject, current)
	}
	for _, other := range []string{h.A, h.B} {
		wrote, err := tryInsert(ctx, s, other)
		if err != nil {
			return err
		}
		if wrote != (other == subject) {
			return fmt.Errorf("%s's context: writing a row for %s succeeded=%v", subject, other, wrote)
		}
	}
	return nil
}

func caseValid(ctx context.Context, h Harness, s Session) error {
	for _, subject := range []string{h.A, h.B} {
		token, err := h.token(subject)
		if err != nil {
			return err
		}
		if err := inTx(ctx, h, s, false, func() error {
			if err := s.Exec(ctx, h.Kind.SetLocalSQL(), token); err != nil {
				return fmt.Errorf("set the context: %w", err)
			}
			return seesOnly(ctx, h, s, subject)
		}); err != nil {
			return err
		}
	}
	return nil
}

func caseMissing(ctx context.Context, h Harness, s Session) error {
	if err := readsNothing(ctx, s); err != nil {
		return fmt.Errorf("outside a transaction: %w", err)
	}
	return inTx(ctx, h, s, false, func() error { return seesNothing(ctx, h, s) })
}

// withToken sets token in a fresh transaction and expects nothing visible.
func withToken(ctx context.Context, h Harness, s Session, label, token string) error {
	err := inTx(ctx, h, s, false, func() error {
		if err := s.Exec(ctx, h.Kind.SetLocalSQL(), token); err != nil {
			return fmt.Errorf("set the context: %w", err)
		}
		return seesNothing(ctx, h, s)
	})
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func caseForged(ctx context.Context, h Harness, s Session) error {
	forgeries, err := Forgeries(h.Kind, h.Key, h.A, h.B, h.now())
	if err != nil {
		return err
	}
	for _, f := range forgeries {
		if err := withToken(ctx, h, s, f.Name, f.Token); err != nil {
			return err
		}
	}
	return nil
}

func caseExpired(ctx context.Context, h Harness, s Session) error {
	// Ten minutes back, so a database clock a little behind the minting
	// clock still sees it expired.
	token, err := tenantctx.Encode(h.Kind, h.A, h.now().Add(-10*time.Minute), h.Key)
	if err != nil {
		return err
	}
	return withToken(ctx, h, s, "expired ten minutes ago", token)
}

func caseWrongScope(ctx context.Context, h Harness, s Session) error {
	others := 0
	for _, other := range tenantctx.Kinds() {
		if other == h.Kind {
			continue
		}
		others++
		token := CrossKindToken(other, h.A, h.now().Add(tenantctx.DefaultTTL), h.Key)
		if err := withToken(ctx, h, s, "a "+other.String()+" token for "+h.A, token); err != nil {
			return err
		}
	}
	if others == 0 {
		return errors.New("no other kind to forge a wrong-scope token with")
	}
	return nil
}

func caseReuse(ctx context.Context, h Harness, s Session) error {
	token, err := h.token(h.A)
	if err != nil {
		return err
	}
	set := func() error { return s.Exec(ctx, h.Kind.SetLocalSQL(), token) }
	for _, commit := range []bool{true, false} {
		end := map[bool]string{true: "commit", false: "rollback"}[commit]
		if err := inTx(ctx, h, s, commit, func() error {
			if err := set(); err != nil {
				return err
			}
			return seesOnly(ctx, h, s, h.A)
		}); err != nil {
			return fmt.Errorf("the transaction that set the context (%s): %w", end, err)
		}
		if err := readsNothing(ctx, s); err != nil {
			return fmt.Errorf("after %s, outside a transaction: %w", end, err)
		}
		if err := inTx(ctx, h, s, false, func() error { return seesNothing(ctx, h, s) }); err != nil {
			return fmt.Errorf("the next transaction after %s: %w", end, err)
		}
	}
	return nil
}

func caseRawSetConfig(ctx context.Context, h Harness, s Session) error {
	clear := func() error { return s.Exec(ctx, setSessionSQL(h.Kind), "") }
	attempts := []struct {
		name string
		run  func() error
	}{
		{name: "session-level set_config of a bare subject", run: func() error {
			if err := s.Exec(ctx, setSessionSQL(h.Kind), h.A); err != nil {
				return err
			}
			if err := readsNothing(ctx, s); err != nil {
				return fmt.Errorf("outside a transaction: %w", err)
			}
			return inTx(ctx, h, s, false, func() error { return seesNothing(ctx, h, s) })
		}},
		{name: "SET of a bare subject", run: func() error {
			if err := s.Exec(ctx, setPlainSQL(h.Kind, h.A)); err != nil {
				return err
			}
			if err := readsNothing(ctx, s); err != nil {
				return fmt.Errorf("outside a transaction: %w", err)
			}
			return inTx(ctx, h, s, false, func() error { return seesNothing(ctx, h, s) })
		}},
		{name: "transaction-level set_config of a bare subject", run: func() error {
			return inTx(ctx, h, s, false, func() error {
				if err := s.Exec(ctx, h.Kind.SetLocalSQL(), h.A); err != nil {
					return err
				}
				return seesNothing(ctx, h, s)
			})
		}},
		{name: "session-level set_config of a bare subject inside a transaction", run: func() error {
			return inTx(ctx, h, s, false, func() error {
				if err := s.Exec(ctx, setSessionSQL(h.Kind), h.A); err != nil {
					return err
				}
				return seesNothing(ctx, h, s)
			})
		}},
	}
	for _, a := range attempts {
		if err := a.run(); err != nil {
			return fmt.Errorf("%s: %w", a.name, err)
		}
		if err := clear(); err != nil {
			return fmt.Errorf("%s: clear the setting: %w", a.name, err)
		}
	}
	return nil
}

func caseReset(ctx context.Context, h Harness, s Session) error {
	token, err := h.token(h.A)
	if err != nil {
		return err
	}
	for _, stmt := range []string{resetSQL(h.Kind), toDefaultSQL(h.Kind)} {
		if err := inTx(ctx, h, s, false, func() error {
			if err := s.Exec(ctx, h.Kind.SetLocalSQL(), token); err != nil {
				return err
			}
			if err := s.Exec(ctx, stmt); err != nil {
				return fmt.Errorf("%s: %w", stmt, err)
			}
			return seesNothing(ctx, h, s)
		}); err != nil {
			return fmt.Errorf("after %s: %w", stmt, err)
		}
	}
	return nil
}

func caseDiscard(ctx context.Context, h Harness, s Session) error {
	token, err := h.token(h.A)
	if err != nil {
		return err
	}
	// A session-level context, as a connection leaked from a buggy caller
	// would carry. The precondition shows it is live, so the DISCARD that
	// follows is what removes it.
	if err := s.Exec(ctx, setSessionSQL(h.Kind), token); err != nil {
		return err
	}
	if err := inTx(ctx, h, s, false, func() error { return seesOnly(ctx, h, s, h.A) }); err != nil {
		return fmt.Errorf("precondition, a session-level context: %w", err)
	}
	if err := s.Exec(ctx, discardSQL); err != nil {
		return fmt.Errorf("DISCARD ALL: %w", err)
	}
	if err := readsNothing(ctx, s); err != nil {
		return fmt.Errorf("after DISCARD ALL, outside a transaction: %w", err)
	}
	if err := inTx(ctx, h, s, false, func() error { return seesNothing(ctx, h, s) }); err != nil {
		return fmt.Errorf("after DISCARD ALL: %w", err)
	}
	// Inside a transaction DISCARD ALL is refused; whatever it did, the
	// next transaction carries nothing.
	for _, stmt := range h.Begin {
		if err := s.Exec(ctx, stmt); err != nil {
			_ = s.Exec(ctx, "ROLLBACK")
			return err
		}
	}
	if err := s.Exec(ctx, h.Kind.SetLocalSQL(), token); err != nil {
		_ = s.Exec(ctx, "ROLLBACK")
		return err
	}
	_ = s.Exec(ctx, discardSQL) // refused inside a transaction block; either outcome is checked below
	if err := s.Exec(ctx, "ROLLBACK"); err != nil {
		return fmt.Errorf("ROLLBACK after an in-transaction DISCARD ALL: %w", err)
	}
	if err := inTx(ctx, h, s, false, func() error { return seesNothing(ctx, h, s) }); err != nil {
		return fmt.Errorf("after an in-transaction DISCARD ALL: %w", err)
	}
	return nil
}

// Forgery is a token a session without the key could send.
type Forgery struct {
	Name  string
	Token string
}

// Forgeries returns the forged and malformed tokens of kind k, built around
// a valid token for a under key that expires a minute after now; b is a
// second subject. Each must verify as nothing.
func Forgeries(k tenantctx.Kind, key []byte, a, b string, now time.Time) ([]Forgery, error) {
	valid, err := tenantctx.Encode(k, a, now.Add(time.Minute), key)
	if err != nil {
		return nil, fmt.Errorf("attacktest.Forgeries: %w", err)
	}
	subject, exp, mac, err := tenantctx.Parse(k, valid)
	if err != nil {
		return nil, fmt.Errorf("attacktest.Forgeries: %w", err)
	}
	macHex := hex.EncodeToString(mac)
	flipped := append([]byte(nil), mac...)
	flipped[len(flipped)-1] ^= 1
	otherKey := sha256.Sum256(append([]byte("attacktest-other-key\n"), key...))
	underOther, err := tenantctx.Encode(k, b, now.Add(time.Minute), otherKey[:])
	if err != nil {
		return nil, fmt.Errorf("attacktest.Forgeries: %w", err)
	}
	expText := func(v int64) string { return strconv.FormatInt(v, 10) }
	return []Forgery{
		{Name: "empty", Token: ""},
		{Name: "bare subject", Token: b},
		{Name: "garbage", Token: "not a token at all"}, //nolint:gosec // G101: a forged test token, not a credential
		{Name: "subject swapped, MAC kept", Token: b + "." + expText(exp) + "." + macHex},
		{Name: "expiry extended, MAC kept", Token: subject + "." + expText(exp+86400) + "." + macHex},
		{Name: "one MAC bit flipped", Token: subject + "." + expText(exp) + "." + hex.EncodeToString(flipped)},
		{Name: "upper-case MAC", Token: subject + "." + expText(exp) + "." + strings.ToUpper(macHex)},
		{Name: "MAC under another key", Token: underOther},
		{Name: "extra segment after the MAC", Token: valid + ".x"},
		{Name: "truncated MAC", Token: valid[:len(valid)-2]},
		{Name: "no expiry", Token: subject + "." + macHex},
		{Name: "overlong", Token: strings.Repeat("a", tenantctx.MaxTokenBytes) + "." + expText(exp) + "." + macHex},
		{Name: "whitespace in the subject", Token: "x " + subject + "." + expText(exp) + "." + macHex},
	}, nil
}

// CrossKindToken returns a token for subject that carries other's MAC under
// key: what a holder of the key would mint for kind other. The subject
// rules of other are deliberately not applied, so the wrong-scope case can
// present an account-shaped subject with the org kind's MAC and the reverse.
func CrossKindToken(other tenantctx.Kind, subject string, expiry time.Time, key []byte) string {
	expText := strconv.FormatInt(expiry.Unix(), 10)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(other.Domain() + subject + "." + expText)) //nolint:errcheck // hash.Hash.Write never fails.
	return subject + "." + expText + "." + hex.EncodeToString(m.Sum(nil))
}
