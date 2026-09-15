// Package intervention discovers and controls exactly identified adapter
// processes through registry-declared installation and injected org policy.
//
// Installation declarations come from integration. Manifest construction and
// process scanning bind native files or explicit interpreted entrypoints;
// shared editor/browser hosts are never classified as isolated adapter work.
// Device/inode evidence identifies local installed files, not vendor/package
// signatures. Database and organization authority remain at the caller, whose
// injected decision is rechecked before each policy signal. Acquire binds a
// kernel process handle to the exact identity and revalidates it before every
// operation. Executable/argv checks are point-in-time, not atomic with exec.
//
// Linux uses pidfds and never falls back to kill(2). Terminate and Kill are
// explicit, separate operations. The supervisor escalates a graceful timeout
// only after a fresh authority/stop decision and reports success only after
// observed exit. It controls individual processes, not descendant trees. It
// does not admit launches or requests or preserve control across controller
// failure. Other operating systems need an equivalent identity-safe backend.
package intervention
