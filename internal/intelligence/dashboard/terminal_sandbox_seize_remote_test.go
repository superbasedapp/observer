//go:build !sbo_omit_remote

package dashboard

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTerminalSandboxSeizeRefusedOffLoopback: the strace switch is
// owner-local; a paired remote device (view or execute) gets 403 on both
// methods and the key stays off.
func TestTerminalSandboxSeizeRefusedOffLoopback(t *testing.T) {
	rc, enc := newReadyRemoteController(t)
	s := newRemoteTestServer(t, Options{Remote: rc})
	remoteH := s.remoteGuardedHandler(rc)
	cookie, csrf := pairSession(t, remoteH, enc)
	mc := rc.(*remoteController)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, withCap := range []bool{false, true} {
			req := httptest.NewRequest(method, terminalSandboxSeizePath, strings.NewReader(`{"enabled":true}`))
			req.Host = testRemoteHost
			req.Header.Set("Origin", "https://"+testRemoteHost)
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			req.Header.Set(remoteCSRFHeader, csrf)
			if withCap {
				tok, err := mc.MintExecute(cookie.Value, method+" "+terminalSandboxSeizePath)
				if err != nil {
					t.Fatalf("MintExecute: %v", err)
				}
				req.Header.Set(remoteExecuteHeader, tok)
			}
			rec := httptest.NewRecorder()
			remoteH.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s from a remote device (execute=%v) = %d, want 403", method, withCap, rec.Code)
			}
		}
	}
	if _, capMap, _ := s.registerRoutes(nil); capMap[terminalSandboxSeizePath] != CapabilityLocal {
		t.Fatalf("%s is %v, want Local", terminalSandboxSeizePath, capMap[terminalSandboxSeizePath])
	}
}
