// Package proxyauth is the pure core of the node proxy's client
// authentication (OSH-R-009, design note
// docs/plans/proxy-client-auth-2026-10-30.md).
//
// A client Observer routed carries a per-install token as the first path
// segment of its base URL: http://127.0.0.1:<port>/t/<token>/v1. The proxy
// checks the token in constant time and strips the prefix before any other
// part of the request path sees it, so the token never reaches an upstream,
// a log line or the database.
//
// This package holds only data and decisions: the token shape (ValidToken),
// the path split (SplitPath), the per-request decision table (Decide), the
// start-time enforcement table (Enforce) and the base-URL helpers
// (WithToken, StripToken). It imports no net/http, os, database/sql or
// fsnotify (imports_test.go): the token file lives in cmd/observer, the
// check in internal/proxy, the route writers in internal/proxyroute.
package proxyauth
