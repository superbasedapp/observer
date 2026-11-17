package store

// AccountContextTokenForTest mints a tenant-context token for accountID with
// the store's own key, for the external tests that poison a session with a
// valid token (a session-level context left on a pooled connection) rather
// than through a transaction helper. Test builds only.
func (s *Store) AccountContextTokenForTest(accountID string) (string, error) {
	return s.tenant.signer.Token(accountID)
}
