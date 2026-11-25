package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// runHTTPServer serves handler on listen until ctx is cancelled (then shuts
// down gracefully within 15s) or the listener fails. `serve` and
// `staff serve` share it; servingMsg is the line each logs when it starts.
func runHTTPServer(ctx context.Context, log *slog.Logger, servingMsg, listen string, handler http.Handler) error {
	srv := &http.Server{
		Addr:    listen,
		Handler: handler,
		// Slowloris + idle-connection bounds (F9). ReadHeaderTimeout alone
		// caps the header phase only: a client that sends complete headers
		// and then dribbles a body one byte at a time holds a connection (and
		// a goroutine) indefinitely. ReadTimeout bounds the WHOLE request
		// read, and IdleTimeout bounds a kept-alive connection between
		// requests.
		//
		// No WriteTimeout: every response here is small and synchronous, and
		// a write deadline would have to be re-derived if a streaming
		// endpoint is ever added — the two read-side bounds are what close
		// the actual exhaustion path.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info(servingMsg, "addr", listen)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}
