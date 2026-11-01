// Package sarif is the security pillar's one SARIF 2.1.0 syntax decoder
// and writer (security pillar plan section 4.5.3). The decoder reads only
// a field allowlist into neutral types, under strict size, depth and count
// caps; it never decodes region.snippet (SARIF snippets and messages are
// content-bearing). Mapping a decoded run onto findings is each driver's
// semantic adapter (internal/secscan), never this package.
//
// The package is pure: no file or network access.
package sarif
