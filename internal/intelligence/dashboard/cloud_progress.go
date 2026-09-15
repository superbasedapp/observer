package dashboard

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudEnrichmentProgress keeps list and detail progress on the same read seam.
// Unknown state disables submission in the UI until a successful refresh.
func (s *Server) cloudEnrichmentProgress(ctx context.Context, st *store.Store, ids []string) map[string]*store.CloudEnrichmentProgress {
	progress, err := st.LoadCloudEnrichmentProgress(ctx, ids)
	if err != nil {
		s.opts.Logger.Warn("cloud: request progress unavailable", "err", err)
		progress = make(map[string]*store.CloudEnrichmentProgress, len(ids))
	}
	for _, id := range ids {
		if progress[id] == nil {
			progress[id] = &store.CloudEnrichmentProgress{State: "unknown"}
		}
	}
	return progress
}

// cloudListEnrichmentProgress preserves the existing response for sessions that
// have never used enrichment. Opening their row still reads full detail status.
func (s *Server) cloudListEnrichmentProgress(ctx context.Context, st *store.Store, ids []string) map[string]*store.CloudEnrichmentProgress {
	progress := s.cloudEnrichmentProgress(ctx, st, ids)
	for id, p := range progress {
		if p.State == "idle" {
			delete(progress, id)
		}
	}
	return progress
}
