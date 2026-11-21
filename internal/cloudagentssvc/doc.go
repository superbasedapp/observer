// Package cloudagentssvc is the service of the node cloud-agent pull
// connectors (docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 5.1, decision CA-D5; operator reference docs/cloud-agents.md): the
// account lifecycle (test, connect, disconnect), the sync of one account
// (discovery pages, per-session refresh, ingest, execution stamp, checkpoint
// commit) and the daemon's poll loop.
//
// It owns no I/O of its own. The vendor egress arrives as the Egress
// interface (internal/cloudagentsnet, composed in cmd/observer), the
// keychain as keystore.Store under service sbo-cloudagents-v1, and the
// database as the Store interface (internal/store's A1 seams:
// cloud_connector_accounts, cloud_sync_checkpoints, cloud_usage_ledger,
// ResolveRemoteProject, SetSessionExecution, plus Ingest).
//
// Off by default: with no linked account, Status reads the database only,
// SyncAll returns without a vendor call, and the poll loop sleeps.
package cloudagentssvc
