//go:build !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestMXCBoxUIOutcomeFailsClosed (WINFIX4 audit finding 4): box detection's
// UI step starts nothing unless the job reads every limit back and, for the
// process that entered the job, the report to the host helper went through.
// Before, a box process logged the class and went on; nothing told the
// helper.
func TestMXCBoxUIOutcomeFailsClosed(t *testing.T) {
	all := sandboxmxc.JobUIRestrictions
	cases := []struct {
		name      string
		class     uint32
		entered   bool
		enterErr  error
		reportErr error
		refused   bool
		reported  bool
		lineHas   string
	}{
		{"entered and reported", all, true, nil, nil, false, true, "and reported to the host helper"},
		{"already in the job (a hook)", all, false, nil, nil, false, false, "already in place"},
		{"enter failed", 0, true, errors.New("access denied"), nil, true, false, "not set: access denied"},
		{"a limit missing", 0x7F, true, nil, nil, true, false, "not 0xFF"},
		{"report failed", all, true, nil, errors.New("port closed"), true, true, "report to the host helper failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reported := false
			refusal, line := mxcBoxUIOutcome(tc.class, tc.entered, tc.enterErr, func(c uint32) error {
				reported = true
				if c != tc.class {
					t.Errorf("reported 0x%X, want 0x%X", c, tc.class)
				}
				return tc.reportErr
			})
			if (refusal != "") != tc.refused {
				t.Fatalf("refusal %q, want refused=%v", refusal, tc.refused)
			}
			if reported != tc.reported {
				t.Fatalf("reported = %v, want %v", reported, tc.reported)
			}
			if !strings.Contains(line, tc.lineHas) {
				t.Fatalf("line %q lacks %q", line, tc.lineHas)
			}
			if !tc.refused && !strings.Contains(line, "read back") {
				t.Fatalf("a line that says the limits hold does not say they were read back: %q", line)
			}
		})
	}
	if s := mxcUnrecognisedRefusal("no AppContainer token"); !strings.Contains(s, "no AppContainer token") || !strings.Contains(s, "nothing is started") {
		t.Fatalf("unrecognised refusal %q", s)
	}
}

// TestMXCAwaitUIClassFailsClosed (finding 4): the helper ends a run whose
// box never reports its UI limit class, or reports one missing a limit;
// before, it logged "UI limits set" right after wxc-exec started, having
// read nothing.
func TestMXCAwaitUIClassFailsClosed(t *testing.T) {
	cases := []struct {
		name   string
		report func(l *mxcUIClassLatch)
		cancel bool
		ends   bool
		line   bool
	}{
		{"reported 0xFF", func(l *mxcUIClassLatch) { l.set(0xFF) }, false, false, true},
		{"reported a lower class", func(l *mxcUIClassLatch) { l.set(0x3F) }, false, true, false},
		{"never reported", func(*mxcUIClassLatch) {}, false, true, false},
		{"run ended by itself", func(*mxcUIClassLatch) {}, true, false, false},
		{"first report counts", func(l *mxcUIClassLatch) { l.set(0xFF); l.set(0) }, false, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := newMXCUIClassLatch()
			tc.report(l)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			line, reason := mxcAwaitUIClass(ctx, l.wait, 50*time.Millisecond)
			if (reason != "") != tc.ends {
				t.Fatalf("reason %q, want ends=%v", reason, tc.ends)
			}
			if tc.ends && !strings.HasPrefix(reason, "ui_limits_not_reported: ") {
				t.Fatalf("reason %q is not named", reason)
			}
			if (line != "") != tc.line {
				t.Fatalf("line %q, want a line=%v", line, tc.line)
			}
		})
	}
}

// TestMXCPortUIClassReport (finding 4): the box reports its class with the
// run's token over POST; a wrong token, a GET or a malformed class is
// refused and never reaches the helper; mxcReportUIClass speaks the route.
func TestMXCPortUIClassReport(t *testing.T) {
	tok, _ := sandboxmxc.EncodeToken(make([]byte, 32))
	other, _ := sandboxmxc.EncodeToken([]byte(strings.Repeat("x", 32)))
	l := newMXCUIClassLatch()
	got := make(chan uint32, 4)
	port := startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierNone, UIClass: func(c uint32) { got <- c; l.set(c) }})
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	for _, bad := range []struct{ method, path string }{
		{http.MethodPost, sandboxmxc.UIClassPath(other, 0xFF)},
		{http.MethodGet, sandboxmxc.UIClassPath(tok, 0xFF)},
		{http.MethodPost, "/uiclass/" + tok + "/FF"},
	} {
		req, _ := http.NewRequest(bad.method, base+bad.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNoContent {
			t.Fatalf("%s %s was taken", bad.method, strings.ReplaceAll(bad.path, tok, "<tok>"))
		}
	}
	select {
	case c := <-got:
		t.Fatalf("a refused report reached the helper (0x%X)", c)
	default:
	}
	dir := t.TempDir()
	if err := writeMXCLoopback(dir, mxcLoopback{V: 1, Port: port, Token: tok}); err != nil {
		t.Fatal(err)
	}
	if err := mxcReportUIClass(dir, 0xFF); err != nil {
		t.Fatalf("mxcReportUIClass: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, ok := l.wait(ctx); !ok || c != 0xFF {
		t.Fatalf("the helper latched 0x%X %v", c, ok)
	}
	// A port with no UI class report refuses it.
	bare := startMXCPort(t, &mxcPort{Token: tok, Tier: vocab.TierNone})
	d2 := t.TempDir()
	if err := writeMXCLoopback(d2, mxcLoopback{V: 1, Port: bare, Token: tok}); err != nil {
		t.Fatal(err)
	}
	if err := mxcReportUIClass(d2, 0xFF); err == nil || strings.Contains(err.Error(), tok) {
		t.Fatalf("a port with no UI class report took one, or the error carries the token: %v", err)
	}
}
