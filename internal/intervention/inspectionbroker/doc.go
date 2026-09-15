// Package inspectionbroker provides a bounded Linux Unix-socket service that
// supplements process inventory with a privileged, nonsensitive process
// identity read.
//
// The broker returns only intervention.Identity. It cannot signal or execute a
// process, inspect arguments, environment, working directories or path
// contents, access the Observer database, or call a model API. Callers must
// still perform ordinary unprivileged binding and process-control checks.
package inspectionbroker
