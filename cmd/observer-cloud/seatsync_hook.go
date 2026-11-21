package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// startWorkerSeatSyncFn starts the worker's scheduled seat sync. seatsync.go
// sets it to startWorkerSeatSync at init. The public tree has no seatsync.go
// (it imports the private org server's usage package, so release.sh's import
// sweep drops it), and there this default answers: off is a no-op, any other
// SBCI_PADDLE_SEAT_SYNC value is refused rather than silently ignored.
var startWorkerSeatSyncFn = func(_ context.Context, _ *slog.Logger, _ *store.Store, getenv func(string) string, _ func(string) ([]byte, error)) error {
	if m := getenv("SBCI_PADDLE_SEAT_SYNC"); m != "" && m != seatSyncOff {
		return fmt.Errorf("observer-cloud: SBCI_PADDLE_SEAT_SYNC=%s needs the seat sync, which this build does not include", m)
	}
	return nil
}
