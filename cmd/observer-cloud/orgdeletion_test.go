package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/seatbilling/paddleapi"
)

const delSubID = "sub_01jc0000000000000000000000"

// fakeCancelAPI answers GET from a queue of statuses (the last repeats) and
// the cancel with cancelErr, recording the calls.
type fakeCancelAPI struct {
	getStatuses []string
	getErr      error
	cancelErr   error
	gets        int
	cancels     int
}

func (f *fakeCancelAPI) GetSubscription(_ context.Context, id string) (seatbilling.Subscription, error) {
	f.gets++
	if f.getErr != nil {
		return seatbilling.Subscription{}, f.getErr
	}
	i := f.gets - 1
	if i >= len(f.getStatuses) {
		i = len(f.getStatuses) - 1
	}
	return seatbilling.Subscription{ID: id, Status: f.getStatuses[i]}, nil
}

func (f *fakeCancelAPI) CancelSubscription(_ context.Context, id string) (seatbilling.Subscription, error) {
	f.cancels++
	if f.cancelErr != nil {
		return seatbilling.Subscription{}, f.cancelErr
	}
	return seatbilling.Subscription{ID: id, Status: paddleapi.StatusCanceled}, nil
}

// TestDeletionBillingCancel (FR-1): one row per path of the billing seam.
// Already canceled is done without a cancel; a refused cancel is read again
// and is done when the subscription turned out canceled; a refusal a retry
// cannot fix wraps ErrBillingRefused (the step blocks); a rate limit, a
// server error and a transport failure are retried.
func TestDeletionBillingCancel(t *testing.T) {
	t.Parallel()
	refused := &paddleapi.APIError{HTTPStatus: 400, Code: "subscription_update_when_canceled"}
	forbidden := &paddleapi.APIError{HTTPStatus: 403, Code: "forbidden"}
	limited := &paddleapi.APIError{HTTPStatus: 429, Code: "too_many_requests"}
	for _, tc := range []struct {
		name        string
		id          string
		api         *fakeCancelAPI
		wantGets    int
		wantCancels int
		wantRefused bool
		wantErr     bool
		wantClass   string
	}{
		{name: "active: canceled now", api: &fakeCancelAPI{getStatuses: []string{"active"}}, wantGets: 1, wantCancels: 1},
		{name: "past due: canceled now", api: &fakeCancelAPI{getStatuses: []string{"past_due"}}, wantGets: 1, wantCancels: 1},
		{name: "already canceled: done, no cancel sent", api: &fakeCancelAPI{getStatuses: []string{"canceled"}}, wantGets: 1},
		{name: "cancel refused but canceled meanwhile: done", api: &fakeCancelAPI{getStatuses: []string{"active", "canceled"}, cancelErr: refused}, wantGets: 2, wantCancels: 1},
		{name: "cancel refused for good: blocks", api: &fakeCancelAPI{getStatuses: []string{"active"}, cancelErr: forbidden}, wantGets: 2, wantCancels: 1, wantErr: true, wantRefused: true, wantClass: "billing:cancel:http_403:forbidden"},
		{name: "cancel rate limited: retried", api: &fakeCancelAPI{getStatuses: []string{"active"}, cancelErr: limited}, wantGets: 1, wantCancels: 1, wantErr: true, wantClass: "billing:cancel:http_429:too_many_requests"},
		{name: "read not found: blocks", api: &fakeCancelAPI{getErr: &paddleapi.APIError{HTTPStatus: 404, Code: "not_found"}}, wantGets: 1, wantErr: true, wantRefused: true, wantClass: "billing:get:http_404:not_found"},
		{name: "read transport failure: retried", api: &fakeCancelAPI{getErr: errors.New("dial tcp: timeout")}, wantGets: 1, wantErr: true, wantClass: "billing:get:transport"},
		{name: "a stored id that is not Paddle's: blocks, nothing sent", id: "sub_live_1", api: &fakeCancelAPI{getStatuses: []string{"active"}}, wantErr: true, wantRefused: true, wantClass: "billing:bad_subscription_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id := tc.id
			if id == "" {
				id = delSubID
			}
			err := deletionBilling{api: tc.api}.CancelOrgSubscription(context.Background(), orgdeletion.CancelRequest{
				OrgID: "org", SubscriptionID: id, IdempotencyKey: "orgdel:r",
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if got := errors.Is(err, orgdeletion.ErrBillingRefused); got != tc.wantRefused {
				t.Fatalf("refused = %v, want %v (%v)", got, tc.wantRefused, err)
			}
			if tc.wantErr && orgdeletion.ClassOf(err) != tc.wantClass {
				t.Fatalf("class = %q, want %q", orgdeletion.ClassOf(err), tc.wantClass)
			}
			if tc.api.gets != tc.wantGets || tc.api.cancels != tc.wantCancels {
				t.Fatalf("gets %d cancels %d, want %d %d", tc.api.gets, tc.api.cancels, tc.wantGets, tc.wantCancels)
			}
		})
	}
}

// TestDeletionBillingFromEnv: no key leaves the seam unwired; a key builds it;
// a plain key in the environment is refused as for every other reader.
func TestDeletionBillingFromEnv(t *testing.T) {
	t.Parallel()
	log := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	files := filesMap(map[string]string{"/s/key": fakeLiveKey + "\n"})

	b, err := deletionBillingFromEnv(log, env(nil), files)
	if err != nil || b != nil {
		t.Fatalf("no key: %v %v", b, err)
	}
	b, err = deletionBillingFromEnv(log, env(map[string]string{"SBCI_PADDLE_ENV": "live", "SBCI_PADDLE_API_KEY_FILE": "/s/key"}), files)
	if err != nil || b == nil {
		t.Fatalf("a live key: %v %v", b, err)
	}
	if _, err := deletionBillingFromEnv(log, env(map[string]string{"SBCI_PADDLE_API_KEY_FILE": "/s/key"}), files); err == nil {
		t.Fatal("a live key against the sandbox default was accepted")
	}
	if _, err := deletionBillingFromEnv(log, env(map[string]string{"SBCI_PADDLE_API_KEY": fakeLiveKey}), files); err == nil {
		t.Fatal("a plain key in the environment was accepted")
	} else if strings.Contains(err.Error(), fakeLiveKey) {
		t.Fatal("the error carries the key")
	}
}

type countsOf struct {
	orgs, fus int
	err       error
}

func (c countsOf) BlockedDeletions(context.Context) (int, int, error) { return c.orgs, c.fus, c.err }

// TestDeletionAlertLines (FR-1): one alert line per block with the alert key
// and enum words, and the standing alert only while something is blocked.
// The same calls feed the worker's metrics (sbci_deletion_blocked_total and
// the sbci_deletion_blocked_open gauges); the log keys stay.
func TestDeletionAlertLines(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, nil))
	reg := cloudmetrics.New(cloudmetrics.ProcessWorker)
	logDeletionBlocks(log, reg, orgdeletion.PassReport{Blocks: []orgdeletion.BlockEvent{{
		Kind: "org", RequestID: "r1", OrgID: "o1", Step: orgdeletion.StepCancelBilling,
		Reason: orgdeletion.ReasonBillingSeamUnwired,
	}}})
	line := buf.String()
	for _, want := range []string{"level=ERROR", "alert=" + alertDeletionBlocked, "request_id=r1", "reason=billing_seam_unwired", "step=cancel_billing"} {
		if !strings.Contains(line, want) {
			t.Fatalf("alert line %q lacks %q", line, want)
		}
	}
	if got := reg.Value(cloudmetrics.MetricDeletionBlocked, "kind", "org", "reason", orgdeletion.ReasonBillingSeamUnwired); got != 1 {
		t.Fatalf("sbci_deletion_blocked_total = %v, want 1", got)
	}
	buf.Reset()
	logStillBlocked(context.Background(), log, reg, countsOf{})
	if buf.Len() != 0 {
		t.Fatalf("nothing blocked, yet: %q", buf.String())
	}
	logStillBlocked(context.Background(), log, reg, countsOf{orgs: 1, fus: 2})
	if l := buf.String(); !strings.Contains(l, "alert="+alertDeletionBlockedOpen) || !strings.Contains(l, "org_requests=1") || !strings.Contains(l, "account_followups=2") {
		t.Fatalf("standing alert = %q", l)
	}
	if reg.Value(cloudmetrics.MetricDeletionBlockedOpen, "kind", "org") != 1 || reg.Value(cloudmetrics.MetricDeletionBlockedOpen, "kind", "account") != 2 ||
		reg.Value(cloudmetrics.MetricDeletionOpenReadOK) != 1 {
		t.Fatal("the blocked gauges were not set")
	}
	// A failed read keeps the gauges and says so; nil registry is inert.
	buf.Reset()
	readBlockedOpen(context.Background(), log, reg, countsOf{err: errors.New("db down")})
	if reg.Value(cloudmetrics.MetricDeletionOpenReadOK) != 0 || reg.Value(cloudmetrics.MetricDeletionBlockedOpen, "kind", "org") != 1 {
		t.Fatal("a failed read must keep the counts and report read_ok 0")
	}
	logDeletionBlocks(log, nil, orgdeletion.PassReport{Blocks: []orgdeletion.BlockEvent{{Kind: "org"}}})
	logStillBlocked(context.Background(), log, nil, countsOf{orgs: 1})
}

// TestDeletionBlockReasonsAreListed keeps cloudmetrics' block reason table
// in step with every block reason the driver can raise: the Reason*
// constants and the driver's own block("...") words.
func TestDeletionBlockReasonsAreListed(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("..", "..", "internal", "cloudserver", "orgdeletion", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("orgdeletion sources: %v", err)
	}
	reConst := regexp.MustCompile(`\bReason[A-Za-z]+\s*=\s*"([a-z_]+)"`)
	reBlock := regexp.MustCompile(`\bblock(?:Why)?\("([a-z_]+)"`)
	listed := cloudmetrics.DeletionBlockReasons()
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, re := range []*regexp.Regexp{reConst, reBlock} {
			for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
				n++
				if !slices.Contains(listed, m[1]) {
					t.Errorf("%s: deletion block reason %q is not listed in cloudmetrics", filepath.Base(f), m[1])
				}
			}
		}
	}
	if n < 8 {
		t.Fatalf("found %d block reasons; the scan is broken", n)
	}
}
