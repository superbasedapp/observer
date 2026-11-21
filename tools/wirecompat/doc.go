// Command wirecompat records golden org push envelopes for one node version
// (managed-SaaS plan 07 row M1.5, plan 06 section 18.2.7, decision D-30).
//
// It seeds a throwaway node database with a fixed, synthetic fixture (one
// project, two sessions, actions, token usage, an API turn and a guard
// event; every value invented, no real path, host name, user or
// environment), enrols it into a fake org server (an in-process
// httptest listener on the loopback), and drives the node's REAL push path,
// orgclient.Client.PushOnce, once per share mode that changes the wire
// shape. The fake server keeps each decoded (post-gunzip) push body and
// answers 200, so what is recorded is exactly what that version of the node
// puts on the wire, written indented for review.
//
// Output, under -out (testdata/wirecompat/<version>/ in the repository):
//
//	meta.json                   version, agent version, release date, commit, modes
//	metadata-only.push-01.json  [org_client.share] zero value (hashes only)
//	full-content.push-01.json   [org_client.share].full_content = true
//
// A mode that needs more than one push writes push-02 and so on, in order.
//
// The recorder must also build and run inside a checkout of an OLDER release
// tag, because tools/wirecompat/record.sh copies this directory's non-test
// files into a temporary worktree of each tag. It therefore uses only node
// APIs that already existed at v1.31.0, the oldest version D-30's window held
// when the recorder was written (db.Open, store.New and its UpsertSession,
// InsertActions, InsertTokenEvents, InsertAPITurn, InsertGuardEvents and
// WriteEnrolment, config.OrgClientConfig, orgclient.New and PushOnce), and
// only the fields those types had then. imports_test.go pins the import set.
//
//	go run ./tools/wirecompat -out testdata/wirecompat/main -version main \
//	    -agent-version dev -released 2026-11-12 -commit <sha>
//
// Run it through tools/wirecompat/record.sh, which isolates HOME and the
// other per-user directories and passes the host's own name, user and home
// as -forbid values: the recorder fails, writing nothing, when an envelope
// contains any of them.
//
// Exit status: 0 on success, 1 on any failure (nothing is written to -out
// unless every mode recorded and passed the -forbid check).
package main
