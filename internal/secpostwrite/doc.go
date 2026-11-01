// Package secpostwrite is the security pillar's post-write seam consumer
// (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md
// section 5.3, "The post-write seam"; security Phase C, S-722).
//
// The store reports each ingested write (session, action id, project root,
// project-relative path; internal/store.SetPostWriteSink). This package
// queues it (bounded, deduplicated per path, one worker), later re-opens
// the file itself and scans it in memory with the secret rows under the
// post-write cap (64 or 256 KiB, internal/secdetect), then discards it:
// only the result reaches the injected sink, never the content.
//
// The read is defensive because the path is repository-controlled: Lstat
// first; refuse a symlink, a non-regular file, anything outside the
// project root (the root and the file's directory are resolved through
// symlinks and compared); open with no-follow where the OS offers it;
// refuse a file whose opened handle is not the file Lstat saw (a
// replacement between the two is retried once); refuse a file over the
// cap; read through a bounded reader. A file that changed again before the
// scan runs is scanned as it is then; the commit gate and the commit scan
// are the durable fallback. A copy workspace whose tree is not visible on
// the host is reported not_scanned: copy_workspace, never clean.
package secpostwrite
