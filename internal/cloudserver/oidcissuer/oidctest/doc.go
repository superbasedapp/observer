// Package oidctest is TEST SUPPORT for the OIDC issuer (managed-SaaS M6.2):
// an in-memory oidcissuer.Store with the database's single-use code
// semantics, a settable clock and RSA key helpers, so issuer and handler
// tests run without Postgres. The Postgres-backed proofs (RLS, grants, two
// replicas on one database) live in internal/cloudserver/store. No
// production package imports it (imports_test.go in each production
// package of the issuer forbids it).
package oidctest
