package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// TestDaemonPushNow pins `observer org push-now` against a running daemon
// (round 3 bug 2): it drives the daemon's owner-local push-now route with the
// route's double-submit confirm token, so the daemon pushes and wakes its own
// loops; with no daemon (nothing listening, or a dashboard without the
// enrolment routes) the CLI falls back to its in-process push.
func TestDaemonPushNow(t *testing.T) {
	cases := []struct {
		name         string
		manageStatus int
		pushStatus   int
		pushBody     any
		wantAnswered bool
		wantErr      string
		wantRows     int
	}{
		{
			name: "daemon pushes", manageStatus: 200, pushStatus: 200,
			pushBody: dashapi.PushNowReport{RowCount: 7, Message: "Pushed 7 rows (100 bytes): accepted=7 deduped=0"}, wantAnswered: true, wantRows: 7,
		},
		{
			name: "daemon refuses: not enrolled", manageStatus: 200, pushStatus: http.StatusConflict,
			pushBody: map[string]string{"error": "not_enrolled", "message": "this machine is not enrolled"}, wantAnswered: true, wantErr: "this machine is not enrolled",
		},
		{name: "dashboard without the enrolment manager falls back", manageStatus: http.StatusNotImplemented, wantAnswered: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var pushed bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/enrolment/manage":
					if r.Method != http.MethodGet {
						t.Errorf("manage method = %s", r.Method)
					}
					w.WriteHeader(tc.manageStatus)
					_ = json.NewEncoder(w).Encode(map[string]any{"confirm_token": "tok-123"})
				case "/api/enrolment/push-now":
					ck, err := r.Cookie(pushNowConfirmCookie)
					if r.Method != http.MethodPost || err != nil || ck.Value != "tok-123" ||
						r.Header.Get(pushNowConfirmHeader) != "tok-123" ||
						!strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					pushed = true
					w.WriteHeader(tc.pushStatus)
					_ = json.NewEncoder(w).Encode(tc.pushBody)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			got := daemonPushNow(context.Background(), srv.URL, "")
			if got.Answered != tc.wantAnswered {
				t.Fatalf("answered = %v, want %v (%+v)", got.Answered, tc.wantAnswered, got)
			}
			if tc.wantAnswered && !pushed {
				t.Fatal("the daemon's push-now route was never called with a valid confirm token")
			}
			switch {
			case tc.wantErr != "":
				if got.Err == nil || !strings.Contains(got.Err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", got.Err, tc.wantErr)
				}
			case got.Err != nil:
				t.Fatalf("err = %v", got.Err)
			}
			if got.Report.RowCount != tc.wantRows {
				t.Fatalf("rows = %d, want %d", got.Report.RowCount, tc.wantRows)
			}
			if tc.wantRows > 0 {
				var buf bytes.Buffer
				printDaemonPushNowReport(&buf, got.Report)
				if !strings.Contains(buf.String(), "Pushed 7 rows") || !strings.Contains(buf.String(), "running daemon") {
					t.Fatalf("report = %q", buf.String())
				}
			}
		})
	}

	t.Run("nothing listening falls back", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		_ = ln.Close()
		if got := daemonPushNow(context.Background(), "http://"+addr, ""); got.Answered {
			t.Fatalf("a closed port answered: %+v", got)
		}
	})
}
