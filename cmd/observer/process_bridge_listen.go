//go:build !sbo_omit_processobs

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/processbridge/setup"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/processobs/bridge"
)

// processBridgeTokenFileName is the shared-token basename. The literal is
// OWNED by internal/processbridge/setup (setup.TokenFileName) — the elevated
// Scheduled-Task planner has to name the same file — and aliased here so the
// daemon-side call sites keep reading in cmd's own vocabulary.
const processBridgeTokenFileName = setup.TokenFileName

// newProcessBridgeListener builds the daemon-side accept listener for the
// cross-OS ETW feed, or returns an error the caller FAILS OPEN on (the rest of
// process capture is unaffected).
//
// It resolves the shared token first, because the listener has no
// unauthenticated mode: WSL2's localhostForwarding makes a WSL-side loopback
// listener reachable from ANY process on the Windows host, so an unauthenticated
// one would let any local process inject fabricated process rows.
func newProcessBridgeListener(pc config.ProcessConfig, observerDir string, logger *slog.Logger, netStatus *processobs.NetworkAccounting) (*bridge.Listener, error) {
	token, err := resolveProcessBridgeListenToken(pc, observerDir)
	if err != nil {
		return nil, err
	}
	return bridge.NewListener(bridge.ListenerOptions{
		Addr:              pc.ETW.ListenAddr,
		AllowNonLoopback:  pc.ETW.AllowNonLoopback,
		Token:             token,
		HandshakeTimeout:  time.Duration(pc.ETW.HandshakeTimeoutMS) * time.Millisecond,
		Logger:            logger,
		NetworkAccounting: netStatus,
	})
}

// resolveProcessBridgeListenToken returns the shared token: the configured
// value if the operator set one, else a 256-bit random token persisted 0600 at
// the token path so the capturer can read it with --token-file. Mirrors
// resolveBrowserIngestToken.
//
// An explicitly-configured token is NOT written to disk — the operator who set
// it owns its distribution, and persisting someone's secret unasked is not the
// daemon's call.
func resolveProcessBridgeListenToken(pc config.ProcessConfig, observerDir string) (string, error) {
	if t := pc.ETW.Token; t != "" {
		return t, nil
	}
	path := setup.TokenPath(pc, observerDir)
	if path == "" {
		return "", fmt.Errorf("no token path (set [observer.process.etw].token or .token_path)")
	}
	if raw, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path derived from the daemon's own config dir.
		if tok := string(bytes.TrimSpace(raw)); tok != "" {
			return tok, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	tok := hex.EncodeToString(buf)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}
	// Owner-only on every OS (on Windows a protected DACL, R-160), and a
	// rename over any empty file left at path, whatever its access was.
	if err := fsatomic.WriteFile(path, []byte(tok+"\n"), fsatomic.Options{TempPattern: ".process-bridge-token-*", OwnerOnly: true}); err != nil {
		return "", fmt.Errorf("persist token: %w", err)
	}
	return tok, nil
}
