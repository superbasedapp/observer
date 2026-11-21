// Package secdepdetail builds the view-time detail of one dependency
// finding (category vulnerable_dependency) for the node dashboard's Code
// security finding drawer: which package and version the finding names,
// where the lockfile holds it (a line window), whether the lockfile says
// it is a direct or a transitive, a runtime or a dev dependency, the
// advisories the node's LOCAL OSV database holds for it, and the smallest
// fixed version an upgrade can move to.
//
// It is PURE (CLAUDE.md "Module Boundaries" rule 1): no database/sql, no
// net/http, no os, no fsnotify (imports_test.go). Every read is injected
// through Input: ReadFile reads the lockfile under the project root (the
// caller owns containment, the size cap and the scrubbing of what is
// shown), LookupRecord reads one OSV record from the local database.
//
// The rule it exists to keep: advisory prose (an OSV record's summary and
// details) is third-party text. It is read at VIEW time from the local
// database into this one local response only, and never into a
// sec_findings row, an MCP tool result, the Explain judge prompt or the
// org push wire. There is no network path: a record the local database
// does not hold is reported as such (AdvisorySource), never fetched.
//
// Decision logic is table-driven (rule 5): the lockfile locators are one
// table keyed by file name (locatorRows), the version comparators one
// table keyed by ecosystem (comparatorRows), the package-name
// normalisation one table (nameNormalizers). Nothing is guessed: an
// unknown lockfile format is "unsupported_format", a version the
// comparator cannot parse yields no suggestion, and a relationship the
// file does not state stays empty.
package secdepdetail
