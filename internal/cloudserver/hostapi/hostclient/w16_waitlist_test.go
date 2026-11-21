package hostclient_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi/hostclient"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// TestDispatchWaitlistUsesTheConfiguredFloor is W16-D5's retry floor as
// configuration (SBCI_WAITLIST_RETRY_FLOOR): a waitlisted create is due
// again after exactly the configured floor on an early attempt (zero
// jitter), not the 15-minute default; the default holds when nothing is
// configured; a floor outside [1m, 1h] refuses to build the dispatcher.
func TestDispatchWaitlistUsesTheConfiguredFloor(t *testing.T) {
	t.Parallel()
	waitlisted := func(t *testing.T) *scripted {
		t.Helper()
		return &scripted{answer: func(hostclient.Host, hostapi.Request) hostapi.Answer {
			return answerJSON(t, pc.ErrorResponse{Code: pc.CodeCapacityWaitlist})
		}}
	}
	for _, c := range []struct {
		name  string
		floor time.Duration
		want  time.Duration
	}{
		{"default", 0, hostapi.WaitlistMinDelay},
		{"five minutes", 5 * time.Minute, 5 * time.Minute},
		{"forty minutes", 40 * time.Minute, 40 * time.Minute},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ms := newMemStore()
			ms.addOrg(provisioning(orgA))
			ms.enqueue(must(t)(hostapi.CreateTenantIntent(orgA, "Acme")))
			d, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{
				Store: ms, Transport: waitlisted(t), Hosts: directory(t, hostAt("https://10.0.0.1:8443")),
				Resolver: resolver{}, Now: fixedNow, Jitter: zeroJitter, WaitlistRetryFloor: c.floor,
			})
			if err != nil {
				t.Fatal(err)
			}
			if st, err := d.DispatchOnce(context.Background()); err != nil || st.Retried != 1 {
				t.Fatalf("pass = %+v, %v", st, err)
			}
			if got := ms.row(orgA).nextAt.Sub(testNow); got != c.want {
				t.Fatalf("due again after %s, want %s", got, c.want)
			}
		})
	}
	for _, bad := range []time.Duration{-time.Minute, 30 * time.Second, 2 * time.Hour} {
		if _, err := hostclient.NewDispatcher(hostclient.DispatcherConfig{
			Store: newMemStore(), Transport: waitlisted(t), Hosts: directory(t, hostAt("https://10.0.0.1:8443")),
			Resolver: resolver{}, WaitlistRetryFloor: bad,
		}); err == nil {
			t.Errorf("floor %s accepted", bad)
		}
	}
}
