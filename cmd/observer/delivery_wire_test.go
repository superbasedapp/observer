package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/deliverynet"
	"github.com/marmutapp/superbased-observer/internal/deliverysvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestDeliveryScheduleMinimumMatchesService pins the dashboard's copy of
// the mirror schedule minimum to the service's (dashapi cannot import the
// egress service, so the two constants are tied here).
func TestDeliveryScheduleMinimumMatchesService(t *testing.T) {
	if dashapi.DeliveryMinScheduleMinutes != deliverysvc.MinScheduleMinutes {
		t.Fatalf("dashapi minimum %d != deliverysvc minimum %d", dashapi.DeliveryMinScheduleMinutes, deliverysvc.MinScheduleMinutes)
	}
	cases := []struct {
		minutes int
		ok      bool
	}{{0, true}, {29, false}, {30, true}, {60, true}, {7 * 24 * 60, true}, {7*24*60 + 1, false}, {-1, false}}
	for _, tc := range cases {
		if got := dashapi.ValidDeliverySchedule(tc.minutes); got != tc.ok {
			t.Errorf("ValidDeliverySchedule(%d) = %v, want %v", tc.minutes, got, tc.ok)
		}
	}
}

// TestDeliveryDashErr is the error table, one case per row: each service
// error becomes the status, closed kind and plain message the page shows.
func TestDeliveryDashErr(t *testing.T) {
	cases := []struct {
		err        error
		wantStatus int
		wantKind   string
	}{
		{deliverysvc.ErrNoKeychain, http.StatusConflict, "no_keychain"},
		{deliverysvc.ErrUnsupported, http.StatusBadRequest, "unsupported"},
		{fmt.Errorf("%w: host", deliverysvc.ErrInvalid), http.StatusBadRequest, "invalid"},
		{deliverysvc.ErrNotFound, http.StatusNotFound, "not_found"},
		{deliverysvc.ErrOverCap, http.StatusConflict, "over_cap"},
		{&deliverynet.Error{Kind: deliverynet.KindAuthFailed, HTTPStatus: 401}, http.StatusUnprocessableEntity, "auth_failed"},
		{&deliverynet.Error{Kind: deliverynet.KindRateLimited}, http.StatusTooManyRequests, "rate_limited"},
		{&deliverynet.Error{Kind: deliverynet.KindUnavailable}, http.StatusUnprocessableEntity, "unavailable"},
		{&deliverynet.Error{Kind: deliverynet.KindHostNotAllowed}, http.StatusBadRequest, "host_not_allowed"},
		{&deliverynet.Error{Kind: deliverynet.KindNeedsNonInteractive}, http.StatusUnprocessableEntity, "needs_noninteractive_credentials"},
		{&deliverynet.Error{Kind: deliverynet.KindRepoMoved}, http.StatusBadGateway, "repo_moved"},
		{&deliverynet.Error{Kind: deliverynet.KindWrongShape}, http.StatusBadGateway, "wrong_shape"},
		{&deliverynet.Error{Kind: deliverynet.KindUnreachable}, http.StatusBadGateway, "unreachable"},
	}
	for _, tc := range cases {
		var de *dashapi.DeliveryError
		if !errors.As(deliveryDashErr(tc.err), &de) {
			t.Fatalf("%v: not mapped", tc.err)
		}
		if de.Status != tc.wantStatus || de.Kind != tc.wantKind || de.Message == "" || strings.ContainsAny(de.Message, "\u2013\u2014") {
			t.Errorf("%v -> %+v, want %d %s", tc.err, de, tc.wantStatus, tc.wantKind)
		}
	}
	if deliveryDashErr(nil) != nil {
		t.Fatal("nil error mapped to non-nil")
	}
	plain := errors.New("disk full")
	if got := deliveryDashErr(plain); !errors.Is(got, plain) {
		t.Fatalf("unmatched error rewritten: %v", got)
	}
}

// TestDeliveryReevaluateGatedOnLocal: with [delivery].local off the service
// gets no reevaluation hook and "Rescan now" is the plain commit scan.
func TestDeliveryReevaluateGatedOnLocal(t *testing.T) {
	st := store.New(openDeliveryTestDB(t))
	if f := deliveryReevaluateFunc(st, config.Config{}, nil); f != nil {
		t.Fatal("reevaluate wired with [delivery].local off")
	}
	cfg := config.Config{Delivery: config.DeliveryConfig{Local: true}}
	f := deliveryReevaluateFunc(st, cfg, nil)
	if f == nil {
		t.Fatal("reevaluate not wired with [delivery].local on")
	}
	if err := f(context.Background(), 99999); err == nil || !strings.Contains(err.Error(), "no project") {
		t.Fatalf("unknown project: %v", err)
	}
}

func openDeliveryTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "delivery.db")})
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

// runDeliveryCmd runs one `observer delivery ...` verb against a config
// whose database lives in a temp dir.
func runDeliveryCmd(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dbPath := filepath.Join(dir, "observer.db")
	writeDeliveryTestConfig(t, cfgPath, dbPath)
	root := &cobra.Command{Use: "observer"}
	root.AddCommand(newDeliveryCmd())
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"delivery", "--config", cfgPath}, args...))
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// TestDeliveryCLI covers the verbs that need no network: status on an
// empty node, connect's argument rules, and the project settings rules.
func TestDeliveryCLI(t *testing.T) {
	out, err := runDeliveryCmd(t, "", "status")
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	for _, want := range []string{"none connected", "connect --token-stdin", "Mirrors", "cap"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output lacks %q:\n%s", want, out)
		}
	}
	cases := []struct {
		name    string
		stdin   string
		args    []string
		wantErr string
	}{
		{"connect needs a mode", "", []string{"connect"}, "pick one"},
		{"connect takes one mode", "", []string{"connect", "--gh", "--token-stdin"}, "pick one"},
		{"connect refuses an empty token", "  \n", []string{"connect", "--token-stdin"}, "no token"},
		{"test needs an id", "", []string{"test", "abc"}, "not an id"},
		{"project must exist", "", []string{"project", "4242"}, "no project"},
		{"mirror delete unknown", "", []string{"mirrors", "delete", "7"}, "No such"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runDeliveryCmd(t, tc.stdin, tc.args...)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q\n%s", err, tc.wantErr, out)
			}
		})
	}
}

// TestDeliveryProjectSettingsCLI pins the mirror opt-in and schedule rules
// through the real store.
func TestDeliveryProjectSettingsCLI(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	dbPath := filepath.Join(dir, "observer.db")
	writeDeliveryTestConfig(t, cfgPath, dbPath)
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatal(err)
	}
	pid, err := store.New(database).UpsertProject(context.Background(), "/tmp/deliv-proj", "")
	_ = database.Close()
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		root := &cobra.Command{Use: "observer"}
		root.AddCommand(newDeliveryCmd())
		var out bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs(append([]string{"delivery", "--config", cfgPath, "project", fmt.Sprint(pid)}, args...))
		err := root.ExecuteContext(context.Background())
		return out.String(), err
	}
	cases := []struct {
		args    []string
		wantOut string
		wantErr string
	}{
		{nil, "mirror off", ""},
		{[]string{"--schedule", "60"}, "", "needs the mirror on"},
		{[]string{"--mirror", "on", "--schedule", "10"}, "", "between 30 minutes"},
		{[]string{"--mirror", "on", "--schedule", "60"}, "refreshed every 60 minutes", ""},
		{[]string{"--mirror", "maybe"}, "", "on or off"},
		{[]string{"--mirror", "off"}, "mirror off", ""},
	}
	for _, tc := range cases {
		out, err := run(tc.args...)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("%v: err = %v, want %q", tc.args, err, tc.wantErr)
			}
			continue
		}
		if err != nil || !strings.Contains(out, tc.wantOut) {
			t.Fatalf("%v: out = %q err = %v, want %q", tc.args, out, err, tc.wantOut)
		}
	}
}

func writeDeliveryTestConfig(t *testing.T, cfgPath, dbPath string) {
	t.Helper()
	body := "[observer]\ndb_path = " + fmt.Sprintf("%q", dbPath) + "\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAgoText pins the CLI's relative-time text.
func TestAgoText(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		at   string
		want string
	}{
		{"", "never"},
		{"garbage", "never"},
		{now.Add(-30 * time.Second).Format(time.RFC3339Nano), "just now"},
		{now.Add(-4 * time.Minute).Format(time.RFC3339Nano), "4m ago"},
		{now.Add(-3 * time.Hour).Format(time.RFC3339Nano), "3h ago"},
		{now.Add(-9 * 24 * time.Hour).Format(time.RFC3339Nano), "9d ago"},
	}
	for _, tc := range cases {
		if got := agoText(tc.at, now); got != tc.want {
			t.Errorf("agoText(%q) = %q, want %q", tc.at, got, tc.want)
		}
	}
}
