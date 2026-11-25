// Package deletionjournal is the append-only account-deletion journal that
// lives OUTSIDE the Postgres restore domain (divergence remediation plan §3
// W6d, rev-4 F8).
//
// Why it exists: replaying a restored database's own deletion_requests to
// re-apply tombstones is circular — a point-in-time restore to a moment BEFORE
// a deletion request contains no request to replay, so the restored service
// would reopen with the deleted account's data resurrected. The journal is a
// SEPARATE durable record, on a different lifecycle from DB backups, that the
// restore runbook ingests to re-apply every completed/accepted deletion BEFORE
// the restored service reopens.
//
// The interface is injected into the store (an I/O boundary, like the blob
// store). Two implementations ship: FileJournal (an append-only JSONL file on a
// durable volume — the local/default impl, and what the tests use) and the
// production target, an Azure append blob in the storage account, bound at
// deploy time (a documented operator-owed infra item; the FileJournal contract
// is the same shape). The journal is a HARD dependency of the deletion path:
// the store refuses to run a deletion with no journal configured, so a deletion
// can never reach 'done' without a durable, restore-surviving record of it.
package deletionjournal
