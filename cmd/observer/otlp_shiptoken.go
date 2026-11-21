package main

import (
	"context"
	"database/sql"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// otlpShipTokenAcceptor is the node OTLP receiver's second credential
// (CLOUDTEL-1, cloud-agents decision CA-D18): a cloud environment's exporter
// may carry a per-environment cloud-session ship token minted on this node
// (Settings > Cloud sessions, POST /api/cloud-session/tokens) in the receiver
// token header instead of the node's one shared receiver token. The ship
// token is short-lived, labelled with its environment and revocable on its
// own, so one leaked environment no longer exposes the shared token. The
// check is the store's: a well-formed secret whose digest is an ACTIVE row of
// cloud_session_ship_tokens. A store error refuses (fail closed).
//
// The receiver calls this per request before decode; the store lookup is one
// indexed read. Nothing here logs the presented value.
func otlpShipTokenAcceptor(ctx context.Context, db *sql.DB, now func() time.Time) func(string) bool {
	if db == nil {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	st := store.New(db)
	return func(token string) bool {
		_, ok, err := st.ActiveCloudSessionShipToken(ctx, token, now().UTC())
		return err == nil && ok
	}
}
