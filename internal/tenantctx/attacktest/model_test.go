package attacktest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// The kit tests itself here: an in-memory model of a PostgreSQL session
// (transaction-local and session-level settings, RESET, DISCARD ALL,
// savepoints, an aborted transaction, a row-level-security probe table)
// whose current-subject function is tenantctx.Verify. The sound model must
// pass every case; each broken model must fail the case it is named for.
// The model understands exactly the statements kit.go sends.

// mutation is one way a database could get the context wrong.
type mutation int

const (
	sound          mutation = iota
	rejectValid             // no token ever verifies
	defaultSubject          // a missing context falls back to subject A
	ignoreMAC               // any well-formed, unexpired token verifies
	ignoreExpiry            // an expired token verifies
	anyDomain               // a MAC under any kind's domain verifies
	keepLocal               // a transaction's context outlives it
	acceptBare              // a bare subject in the setting is taken as the context
	ignoreReset             // RESET and SET ... TO DEFAULT do nothing
	ignoreDiscard           // DISCARD ALL keeps the setting
)

func modelKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

func modelClock() time.Time { return time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC) }

func modelSubjects(k tenantctx.Kind) (string, string) {
	if k == tenantctx.KindAccount {
		return "0f3a9c1e-1111-4222-8333-444455556666", "0f3a9c1e-aaaa-4bbb-8ccc-ddddeeeeffff"
	}
	return "org-a", "org-b"
}

// modelSession is one session over a shared table that holds one committed
// row for each of the two subjects.
type modelSession struct {
	kind    tenantctx.Kind
	mut     mutation
	a, b    string
	session string
	inTx    bool
	aborted bool
	local   *string
	pending *string
	txRows  []string
	saved   *modelSnapshot
}

type modelSnapshot struct {
	local, pending *string
	txRows         []string
}

func newModelHarness(k tenantctx.Kind, mut mutation) Harness {
	a, b := modelSubjects(k)
	return Harness{
		Kind:  k,
		Key:   modelKey(),
		A:     a,
		B:     b,
		Begin: []string{"BEGIN", "SET LOCAL ROLE sbci_app"},
		Now:   modelClock,
		Open: func(context.Context) (Session, error) {
			return &modelSession{kind: k, mut: mut, a: a, b: b}, nil
		},
	}
}

func (m *modelSession) value() string {
	switch {
	case m.local != nil:
		return *m.local
	case m.pending != nil:
		return *m.pending
	default:
		return m.session
	}
}

// current is the model's current-subject function.
func (m *modelSession) current() string {
	v := m.value()
	switch m.mut {
	case rejectValid:
		return ""
	case defaultSubject:
		if v == "" {
			return m.a
		}
	case acceptBare:
		if v == m.a || v == m.b {
			return v
		}
	case ignoreMAC, ignoreExpiry, anyDomain:
		return m.brokenVerify(v)
	}
	subject, err := tenantctx.Verify(m.kind, v, [][]byte{modelKey()}, modelClock())
	if err != nil {
		return ""
	}
	return subject
}

func (m *modelSession) brokenVerify(v string) string {
	subject, expiry, mac, err := tenantctx.Parse(m.kind, v)
	if err != nil {
		return ""
	}
	if m.mut != ignoreExpiry && expiry <= modelClock().Unix() {
		return ""
	}
	if m.mut == ignoreMAC {
		return subject
	}
	domains := []string{m.kind.Domain()}
	if m.mut == anyDomain {
		domains = nil
		for _, k := range tenantctx.Kinds() {
			domains = append(domains, k.Domain())
		}
	}
	for _, d := range domains {
		h := hmac.New(sha256.New, modelKey())
		h.Write([]byte(d + subject + "." + strconv.FormatInt(expiry, 10)))
		if hmac.Equal(h.Sum(nil), mac) {
			return subject
		}
	}
	return ""
}

func (m *modelSession) endTx(commit bool) {
	if commit && !m.aborted && m.pending != nil {
		m.session = *m.pending
	}
	if m.mut == keepLocal && m.local != nil {
		m.session = *m.local
	}
	m.inTx, m.aborted, m.local, m.pending, m.txRows, m.saved = false, false, nil, nil, nil, nil
}

func strArg(args []any) (string, error) {
	if len(args) != 1 {
		return "", fmt.Errorf("want one argument, got %d", len(args))
	}
	s, ok := args[0].(string)
	if !ok {
		return "", fmt.Errorf("argument is %T", args[0])
	}
	return s, nil
}

// setSession is a session-level SET: inside a transaction it overrides the
// local value at once and becomes the session value at commit.
func (m *modelSession) setSession(v string) {
	if m.inTx {
		m.local, m.pending = nil, &v
		return
	}
	m.session = v
}

func (m *modelSession) Exec(_ context.Context, query string, args ...any) error {
	k := m.kind
	switch {
	case query == "ROLLBACK":
		m.endTx(false)
		return nil
	case query == rollbackToSQL:
		if !m.inTx || m.saved == nil {
			return errors.New("no savepoint")
		}
		m.local, m.pending = m.saved.local, m.saved.pending
		m.txRows = slices.Clone(m.saved.txRows)
		m.aborted = false
		return nil
	case m.aborted:
		return errors.New("current transaction is aborted")
	case query == "BEGIN":
		if m.inTx {
			return errors.New("already in a transaction")
		}
		m.inTx = true
		return nil
	case query == "COMMIT":
		m.endTx(true)
		return nil
	case strings.HasPrefix(query, "SET LOCAL ROLE "):
		return nil
	case query == savepointSQL:
		m.saved = &modelSnapshot{local: m.local, pending: m.pending, txRows: slices.Clone(m.txRows)}
		return nil
	case query == k.SetLocalSQL():
		v, err := strArg(args)
		if err != nil {
			return err
		}
		if m.inTx {
			m.local = &v
		}
		return nil
	case query == setSessionSQL(k):
		v, err := strArg(args)
		if err != nil {
			return err
		}
		m.setSession(v)
		return nil
	case strings.HasPrefix(query, "SET "+k.Setting()+" = '") && strings.HasSuffix(query, "'"):
		inner := strings.TrimSuffix(strings.TrimPrefix(query, "SET "+k.Setting()+" = '"), "'")
		m.setSession(strings.ReplaceAll(inner, "''", "'"))
		return nil
	case query == resetSQL(k):
		if m.mut != ignoreReset {
			m.setSession("")
		}
		return nil
	case query == toDefaultSQL(k):
		if m.mut != ignoreReset && m.inTx {
			empty := ""
			m.local = &empty
		}
		return nil
	case query == discardSQL:
		if m.inTx {
			m.aborted = true
			return errors.New("DISCARD ALL cannot run inside a transaction block")
		}
		if m.mut != ignoreDiscard {
			m.session = ""
		}
		return nil
	default:
		return fmt.Errorf("the model does not understand %q", query)
	}
}

func (m *modelSession) Visible(context.Context) ([]string, error) {
	if m.aborted {
		return nil, errors.New("current transaction is aborted")
	}
	cur := m.current()
	if cur == m.a || cur == m.b || slices.Contains(m.txRows, cur) {
		return []string{cur}, nil
	}
	return nil, nil
}

func (m *modelSession) Current(context.Context) (string, error) {
	if m.aborted {
		return "", errors.New("current transaction is aborted")
	}
	return m.current(), nil
}

func (m *modelSession) Insert(_ context.Context, subject string) error {
	switch {
	case !m.inTx:
		return errors.New("the model only writes inside a transaction")
	case m.aborted:
		return errors.New("current transaction is aborted")
	case m.current() != subject:
		m.aborted = true
		return errors.New("new row violates row-level security policy")
	}
	m.txRows = append(m.txRows, subject)
	return nil
}

func (m *modelSession) Close() error { return nil }

// TestSoundModelPassesEveryCase: the sound model resists every attack, for
// every kind.
func TestSoundModelPassesEveryCase(t *testing.T) {
	t.Parallel()
	for _, k := range tenantctx.Kinds() {
		results := Check(t.Context(), newModelHarness(k, sound))
		if len(results) != len(Cases()) {
			t.Fatalf("%s: %d results for %d cases", k, len(results), len(Cases()))
		}
		for _, r := range results {
			if r.Err != nil {
				t.Errorf("%s / %s: %v", k, r.Case, r.Err)
			}
		}
	}
}

// TestKitCatchesBrokenModels has one case per row of the attack table, in
// table order: a database broken in the row's way must fail that row, for
// every kind.
func TestKitCatchesBrokenModels(t *testing.T) {
	t.Parallel()
	cases := []struct {
		row string
		mut mutation
	}{
		{row: "valid context sees only its own subject", mut: rejectValid},
		{row: "missing context sees nothing", mut: defaultSubject},
		{row: "forged token", mut: ignoreMAC},
		{row: "expired token", mut: ignoreExpiry},
		{row: "wrong-scope token", mut: anyDomain},
		{row: "token reuse across transactions", mut: keepLocal},
		{row: "raw set_config by the runtime login", mut: acceptBare},
		{row: "RESET", mut: ignoreReset},
		{row: "DISCARD", mut: ignoreDiscard},
	}
	rows := Cases()
	if len(cases) != len(rows) {
		t.Fatalf("%d cases for %d rows", len(cases), len(rows))
	}
	for i, c := range cases {
		if rows[i].Name != c.row {
			t.Fatalf("case %d is %q, row %d is %q", i, c.row, i, rows[i].Name)
		}
		for _, k := range tenantctx.Kinds() {
			t.Run(c.row+"/"+k.String(), func(t *testing.T) {
				t.Parallel()
				for _, r := range Check(t.Context(), newModelHarness(k, c.mut)) {
					if r.Case == c.row {
						if r.Err == nil {
							t.Fatalf("the broken model passed %q", c.row)
						}
						return
					}
				}
				t.Fatalf("no result for %q", c.row)
			})
		}
	}
}

// TestHarnessValidation: an incomplete harness is one "harness" result, and
// Run refuses it before any case.
func TestHarnessValidation(t *testing.T) {
	t.Parallel()
	good := newModelHarness(tenantctx.KindOrg, sound)
	for _, c := range []struct {
		name   string
		mutate func(h *Harness)
	}{
		{name: "unknown kind", mutate: func(h *Harness) { h.Kind = 0 }},
		{name: "no Open", mutate: func(h *Harness) { h.Open = nil }},
		{name: "no Begin", mutate: func(h *Harness) { h.Begin = nil }},
		{name: "Begin without BEGIN", mutate: func(h *Harness) { h.Begin = []string{"SET LOCAL ROLE x"} }},
		{name: "same subjects", mutate: func(h *Harness) { h.B = h.A }},
		{name: "short key", mutate: func(h *Harness) { h.Key = h.Key[:31] }},
		{name: "subject of the wrong kind", mutate: func(h *Harness) { h.Kind = tenantctx.KindAccount }},
	} {
		h := good
		c.mutate(&h)
		results := Check(t.Context(), h)
		if len(results) != 1 || results[0].Case != "harness" || results[0].Err == nil {
			t.Errorf("%s: Check = %v", c.name, results)
		}
	}
}

// TestForgeriesAreRefused: every forgery of each kind fails tenantctx.Verify
// and the cross-kind token verifies only as the kind it was made for.
func TestForgeriesAreRefused(t *testing.T) {
	t.Parallel()
	now := modelClock()
	for _, k := range tenantctx.Kinds() {
		a, b := modelSubjects(k)
		forgeries, err := Forgeries(k, modelKey(), a, b, now)
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, f := range forgeries {
			if names[f.Name] {
				t.Errorf("%s: duplicate forgery %q", k, f.Name)
			}
			names[f.Name] = true
			if got, err := tenantctx.Verify(k, f.Token, [][]byte{modelKey()}, now); err == nil {
				t.Errorf("%s / %s: verified as %q", k, f.Name, got)
			}
		}
		for _, other := range tenantctx.Kinds() {
			if other == k {
				continue
			}
			token := CrossKindToken(other, a, now.Add(time.Minute), modelKey())
			if got, err := tenantctx.Verify(k, token, [][]byte{modelKey()}, now); err == nil {
				t.Errorf("a %s-domain token verified as %s: %q", other, k, got)
			}
		}
		// The cross-kind token is a real token of its own kind when the
		// subject fits that kind: the helper builds the MAC correctly.
		self := CrossKindToken(k, a, now.Add(time.Minute), modelKey())
		if got, err := tenantctx.Verify(k, self, [][]byte{modelKey()}, now); err != nil || got != a {
			t.Errorf("%s: CrossKindToken of its own kind = %q, %v", k, got, err)
		}
		want, err := tenantctx.Encode(k, a, now.Add(time.Minute), modelKey())
		if err != nil || self != want {
			t.Errorf("%s: CrossKindToken %q, Encode %q (%v)", k, self, want, err)
		}
	}
}
