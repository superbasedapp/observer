package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

// B-G8 (plan docs/plans/dashboard-cli-parity-plan-2026-11-06.md): the audit
// chain repair on the Coverage tab. Each repair's dry run is a read; each
// apply rewrites guard_events rows, so it needs the confirm token, and its
// argv is the CLI verb with --apply, nothing typed.
func TestGuardChainJobRoute(t *testing.T) {
	var calls atomic.Int32
	var lastArgs atomic.Value
	fake := func(_ context.Context, args []string, _ func([]byte)) (int, error) {
		calls.Add(1)
		lastArgs.Store(strings.Join(args, " "))
		return 0, nil
	}
	s, _ := newEvidenceServer(t, fake)
	view, ck := guardJobsInfo(t, s, "/api/guard/jobs/chain")
	if view.ConfirmToken == "" || len(view.Kinds) != 6 {
		t.Fatalf("chain jobs view = %+v", view)
	}
	for _, k := range view.Kinds {
		if strings.HasSuffix(k.Kind, "-apply") != k.Writes {
			t.Errorf("kind %s writes=%v: every apply writes and no dry run does", k.Kind, k.Writes)
		}
	}

	cases := []struct {
		name     string
		body     string
		token    bool
		want     int
		wantArgs string
	}{
		{"repair-anchors dry run needs no token", `{"kind":"repair-anchors"}`, false, 200, "guard repair-anchors"},
		{"dedup-events dry run needs no token", `{"kind":"dedup-events"}`, false, 200, "guard dedup-events"},
		{"relink-gaps dry run needs no token", `{"kind":"relink-gaps"}`, false, 200, "guard relink-gaps"},
		{"repair-anchors apply without the token", `{"kind":"repair-anchors-apply"}`, false, 403, ""},
		{"dedup-events apply without the token", `{"kind":"dedup-events-apply"}`, false, 403, ""},
		{"relink-gaps apply without the token", `{"kind":"relink-gaps-apply"}`, false, 403, ""},
		{"repair-anchors apply", `{"kind":"repair-anchors-apply"}`, true, 200, "guard repair-anchors --apply"},
		{"dedup-events apply", `{"kind":"dedup-events-apply"}`, true, 200, "guard dedup-events --apply"},
		{"relink-gaps apply", `{"kind":"relink-gaps-apply"}`, true, 200, "guard relink-gaps --apply"},
		{"a policy kind on the chain route", `{"kind":"rescan"}`, true, 400, ""},
		{"keep-hashes is not offered", `{"kind":"dedup-events --keep-hashes"}`, true, 400, ""},
	}
	for _, tc := range cases {
		before := calls.Load()
		token, cookie := "", (*http.Cookie)(nil)
		if tc.token {
			token, cookie = view.ConfirmToken, ck
		}
		rr := guardToolPost(s, "/api/guard/jobs/chain", tc.body, token, cookie)
		if rr.Code != tc.want {
			t.Errorf("%s: status = %d %s, want %d", tc.name, rr.Code, rr.Body.String(), tc.want)
			continue
		}
		if tc.want != http.StatusOK {
			if calls.Load() != before {
				t.Errorf("%s: a refused request started a job", tc.name)
			}
			continue
		}
		var resp struct {
			JobID string `json:"job_id"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		job := waitEvidenceJob(t, s, resp.JobID)
		if job.Status != "done" || calls.Load() != before+1 {
			t.Errorf("%s: job = %+v", tc.name, job)
		}
		if got, _ := lastArgs.Load().(string); !strings.HasPrefix(got, tc.wantArgs+" --config ") {
			t.Errorf("%s: argv = %q, want %q --config ...", tc.name, got, tc.wantArgs)
		}
	}
}

// TestGuardChainJobsCoverEveryRepair: every repair store.GuardChainRepairHint
// can name has its dry run and its apply on the route.
func TestGuardChainJobsCoverEveryRepair(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"repair-anchors", "dedup-events", "relink-gaps"} {
		if _, ok := guardChainJobs[kind]; !ok {
			t.Errorf("the chain route lacks the %s dry run", kind)
		}
		if _, ok := guardChainJobs[kind+"-apply"]; !ok {
			t.Errorf("the chain route lacks the %s apply", kind)
		}
	}
}
