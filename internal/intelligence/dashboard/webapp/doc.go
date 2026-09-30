// Package webapp embeds the redesigned React/Vite dashboard
// produced by the web/ directory at the repo root.
//
// During the multi-phase frontend migration the new dashboard
// mounts at /v2/ while the legacy vanilla SPA at
// internal/intelligence/dashboard/static stays at /. Once /v2/
// reaches parity the cutover collapses to a single root mount
// and the static/ tree is retired.
//
// The dist/ subtree is the committed output of `make web-build`
// (npm ci + vite build + scripts/sync-web-embed.sh, which copies
// web/dist minus its source maps). It is regenerated from source
// rather than authored by hand; do not edit by hand. It stays
// committed so `go install` and Node-less builds still compile.
package webapp
