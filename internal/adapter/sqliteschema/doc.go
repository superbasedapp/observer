// Package sqliteschema holds the schema probes the adapters that read a
// vendor's SQLite store share. A vendor store's schema varies across the
// vendor's releases (and an empty or foreign-mount file has none), so an
// adapter gates every optional read on a probe here and degrades to
// "nothing to read" instead of failing the parse.
//
// It reads only the store's own catalogue (sqlite_master) through a
// *sql.DB the caller opened; it opens nothing, does no file, network or
// fsnotify I/O itself (imports_test.go pins it).
package sqliteschema
