// Package sdkcatalog is the Go reader of the one SDK catalog
// (shared/lib/sdkCatalog.json; review P-11, first-run plan revision 2
// section 3.9). The apps read the same file through sdkCatalog.ts and the
// marketing generator through website/docs-tools/pagegen; this package is
// how the CLI (`observer apps on`) prints the same rows, embedded so the
// binary needs no file at run time. It is pure: no I/O beyond the embed.
//
// The package lives beside the JSON because go:embed cannot reach a parent
// directory; the rest of shared/lib is TypeScript and ignores this file.
package sdkcatalog
