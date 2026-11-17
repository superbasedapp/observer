package dashboard

import (
	"context"
	"time"

	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/predictsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// PredictProjection is the run-out projection half of the predict response
// (additive: older consumers ignore it). The assembly is
// internal/predictsvc.Build, shared with `observer predict`; this file only
// fills its inputs from the handler's options.
type PredictProjection = predictsvc.Projection

// predictNow is the handler clock (the Server's override in tests).
func (s *Server) predictNow() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now().UTC()
}

// buildPredictProjection is the handler's adapter onto predictsvc.Build.
func (s *Server) buildPredictProjection(ctx context.Context, st *store.Store, tool, sessionID string, gauge LimitGauge, est predict.EstimateResult) PredictProjection {
	d := predictsvc.Deps{Store: st, Now: s.predictNow()}
	if cfg, err := loadConfigForDashboard(s.opts.ConfigPath); err == nil {
		d.Config = &cfg
	}
	if s.opts.Plans != nil {
		d.Plans = s.opts.Plans
	}
	return predictsvc.Build(ctx, d, tool, sessionID, gauge, est)
}
