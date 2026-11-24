package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// startWorkerHostAPIFn starts the worker's host-API client and entitlements
// issuer. hostapiworker.go sets it to startWorkerHostAPI at init. The public
// tree has no hostapiworker.go (it imports the private org server's
// availability package, so release.sh's import sweep drops it), and there
// this default answers: an unset SBCI_HOSTAPI_HOSTS_FILE is a no-op, a set one
// is refused rather than silently ignored.
var startWorkerHostAPIFn = func(_ context.Context, _ *slog.Logger, _ *store.Store) error {
	if strings.TrimSpace(os.Getenv("SBCI_HOSTAPI_HOSTS_FILE")) != "" {
		return fmt.Errorf("observer-cloud: SBCI_HOSTAPI_HOSTS_FILE is set, but this build does not include the host-API client")
	}
	return nil
}
