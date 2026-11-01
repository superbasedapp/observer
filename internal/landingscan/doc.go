// Package landingscan is the local half of commit to PR to merge tracking
// (docs/plans/commit-pr-merge-tracking-plan-2026-10-15.md 2.1, 4 and 12,
// operator decision D-689): the second after-scan step of the commit
// scanner (next to internal/skillscan). For one project root that the
// commit scan just read successfully it:
//
//   - reads the project's remotes, each remote's default branch and the
//     user's own remote-tracking tip of it, and the age of .git/FETCH_HEAD
//     (a stat, not a read);
//   - computes the patch fingerprint of AI-touched commits still pending
//     (bounded per pass), and of default-branch commits since the oldest
//     commit that has not landed (bounded, cached by sha);
//   - records local branch tips holding an unlanded AI commit with the
//     fingerprint of their cumulative diff (the squash rules);
//   - checks ancestry against the default ref and reachability from any
//     remote-tracking ref;
//   - runs internal/delivery.Evaluate over that evidence plus the PRs the
//     provider service already stored, and persists the landings.
//
// READ-ONLY. Every git call goes through the injected Exec, which production
// wires to internal/gitview's read-only envelope with lazy fetching refused
// (RunReadOnlyNoLazyFetch): no fetch, no merge-tree, no config write, no
// object write, no network. When the project's remote has an Observer mirror
// (internal/deliverynet keeps it fresh), default-branch evidence is read from
// the MIRROR directory instead, with the user's commit ids passed as plain
// arguments; neither repository is ever made an alternate of the other.
//
// PURE-ISH: no database/sql, net/http, os/exec or fsnotify, and no
// internal/store import (imports_test.go). Every store read and write and
// the filesystem stat arrive as injected funcs, the internal/skillscan
// precedent.
package landingscan
