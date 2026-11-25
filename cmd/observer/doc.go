// Command observer is the CLI entry point for the SuperBased Observer.
//
// All capture/query/manage subcommands (scan, watch, init, uninstall, serve,
// doctor, status, tail, prune, cost, score, discover, patterns, learn,
// suggest, dashboard, metrics, summarize, export) are wired directly under
// the root. The legacy `observer observer ...` nesting is preserved as a
// hidden alias group so installed hooks and MCP registrations from earlier
// versions keep working without re-init.
package main
