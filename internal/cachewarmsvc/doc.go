// Package cachewarmsvc is the boundary that turns node-local cache_entries
// rows into classified cache-expiry warnings + keep-warm recommendations.
// It is the SINGLE seam every surface (dashboard API, CLI, MCP, VS Code
// endpoint) calls, so the store→cachewarm mapping and the capability
// resolution live in exactly one place.
//
// It imports internal/store (the row type + read), internal/intelligence/cost
// (rate lookup for value-at-risk), and internal/cachewarm (the pure
// classifier + recommender). The pure cachewarm package stays free of all
// three — the impurity is concentrated here.
package cachewarmsvc
