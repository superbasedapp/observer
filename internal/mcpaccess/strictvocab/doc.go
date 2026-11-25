// Package strictvocab is the closed audit strict-class VOCABULARY of
// agent_access_settings.audit_strict_classes (doc3 R9.6 / §9.1): the accepted
// values, the retirement table and the one normalization every reader
// applies. It is pure (stdlib only) and core in every image, so the org
// server's config validator can check the field without linking Agent Access
// (modular packaging lane MP-L1G). What each value MATCHES stays in
// internal/mcpaccess (MatchStrictClass, the gateway PDP's one predicate
// table), which re-exports this vocabulary under its historical names; this
// package is the one owner of the values themselves (security ledger AA-69:
// an accepted value can never be a value the gateway does not act on, pinned
// by mcpaccess's TestStrictClassTableCoversVocabulary).
package strictvocab
