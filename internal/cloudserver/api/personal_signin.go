package api

import (
	"context"
	"time"
)

// personal_signin.go creates the personal dashboard at sign-in (Getting
// started v2: "personal dashboard auto-created on first sign-in"). The
// console no longer asks the person to click "Create my personal
// organization"; the account home shows "Setting up your personal
// dashboard..." while the org provisions.
//
// It runs after the session cookie is minted, in the background, so a slow
// or failing provision never fails or delays a sign-in, and it is idempotent
// (store.EnsurePersonalOrg answers the existing org, and the one-per-account
// index resolves two concurrent ensures to one org). A failure is logged and
// retried at the next sign-in, at the approval page (connectChoices) or by
// `observer connect` (POST /v1/orgs/personal:ensure).

// personalOnSignInTimeout bounds one background ensure.
const personalOnSignInTimeout = 30 * time.Second

// ensurePersonalAfterSignIn starts the background ensure for accountID when
// Options.EnsurePersonalOnSignIn is on.
func (s *Server) ensurePersonalAfterSignIn(accountID string) {
	if !s.ensurePersonalOnSignIn || accountID == "" || s.store == nil {
		return
	}
	s.background.Add(1)
	go func() {
		defer s.background.Done()
		ctx, cancel := context.WithTimeout(context.Background(), personalOnSignInTimeout)
		defer cancel()
		_, created, err := s.store.EnsurePersonalOrg(ctx, accountID, s.tenantDomain)
		if err != nil {
			s.log.Error("cloudserver/api: ensure personal org at sign-in", "err", err)
			return
		}
		if created {
			s.audit(ctx, accountID, "signin_personal_org_ensured")
		}
	}()
}

// WaitBackground waits for every background task a request started (tests,
// and a graceful shutdown after the listener has stopped).
func (s *Server) WaitBackground() { s.background.Wait() }
