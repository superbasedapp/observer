package main

import (
	"context"
	"crypto/rand"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestOTLPShipTokenAcceptor pins CLOUDTEL-1's node wiring: the receiver's
// second credential admits exactly an active node ship token.
func TestOTLPShipTokenAcceptor(t *testing.T) {
	ctx := context.Background()
	database, err := db.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "observer.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	m, err := shiptoken.Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	st := store.New(database)
	if err := st.InsertCloudSessionShipToken(ctx, store.CloudSessionShipToken{
		TokenID: m.ID, TokenHash: m.Hash, Label: "web env", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	clock := now
	accept := otlpShipTokenAcceptor(ctx, database, func() time.Time { return clock })
	if !accept(m.Token) {
		t.Fatal("the active ship token was refused")
	}
	if accept("sbocs_not-a-real-token") || accept("") {
		t.Fatal("a malformed or empty token was accepted")
	}
	clock = now.Add(2 * time.Hour)
	if accept(m.Token) {
		t.Fatal("an expired ship token was accepted")
	}
	if otlpShipTokenAcceptor(ctx, nil, nil) != nil {
		t.Fatal("no database must mean no second credential")
	}
}
