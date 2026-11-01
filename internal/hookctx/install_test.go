package hookctx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

func TestCheckInstall(t *testing.T) {
	ev := &policy.Event{Kind: policy.KindShellExec, Target: "npm i x"}
	none := Host(context.Background(), Request{}, Source{}, HostProviders{})
	none.CheckInstall(context.Background(), InstallRequest{Event: ev})
	if none.Security != nil {
		t.Error("a nil provider must do nothing")
	}

	ok := Host(context.Background(), Request{}, Source{}, HostProviders{Install: func(context.Context, InstallRequest) (InstallResult, error) {
		return InstallResult{CustomRegistry: true, Checks: []policy.InstallCheck{
			{Name: "a", Verdict: policy.InstallKnownGood, Source: policy.InstallSourceOffline},
			{Name: "b", Verdict: policy.InstallNearMiss, Source: policy.InstallSourceOffline},
		}}, nil
	}})
	ok.CheckInstall(context.Background(), InstallRequest{Event: ev})
	if s := ok.Security; s == nil || s.Install != policy.InstallNearMiss || !s.InstallCustomRegistry || len(s.Installs) != 2 {
		t.Fatalf("merged %+v", ok.Security)
	}

	for name, fn := range map[string]InstallChecker{
		"error": func(context.Context, InstallRequest) (InstallResult, error) { return InstallResult{}, errors.New("x") },
		"panic": func(context.Context, InstallRequest) (InstallResult, error) { panic("boom") },
		"overrun": func(ctx context.Context, _ InstallRequest) (InstallResult, error) {
			<-time.After(time.Second)
			return InstallResult{Checks: []policy.InstallCheck{{Verdict: policy.InstallKnownGood}}}, nil
		},
	} {
		c := Host(context.Background(), Request{}, Source{}, HostProviders{Install: fn, Limits: Limits{Install: 20 * time.Millisecond}})
		c.CheckInstall(context.Background(), InstallRequest{Event: ev})
		if c.Security == nil || c.Security.Install != policy.InstallUnknownName || len(c.Issues) != 1 || c.Issues[0].Step != StepInstall {
			t.Errorf("%s: must record unknown, never clean: %+v %+v", name, c.Security, c.Issues)
		}
	}
}
