package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/updatespec"
)

// Identity-bound org documents (T-393, the review M3-01 class).
//
// The org signs a number of documents for ONE enrolment identity: one org, and
// for most of them one member. The node caches each verified document so a
// restart does not wait for the next poll. Every such cache must end with the
// identity that received it, on BOTH paths that end an identity:
//
//   - `observer unenroll` (DeleteEnrolment), and
//   - a re-enrolment into a different org, or as a different member, without an
//     unenrol in between (orgclient.Enroll).
//
// Before this table the two paths kept separate lists and drifted: Enroll
// cleared only the budget and the org AI tool policy, so a node that re-enrolled
// into a second org kept the first org's display policy, routing policy,
// announcement banner, access grants, intel terms, prices and update manifest.
// Several of those caches also pin the first org's signing key or hold its
// highest version, so the second org's documents were then refused as a "key
// CHANGED" attack or as a downgrade until the operator unenrolled by hand.
//
// identityBoundDocs is the ONE list both paths walk. Each row names the cache
// and how it is cleared; TestIdentityBoundDocsCoverEveryOrgTable fails when a
// new org_* table appears without a row here or a recorded reason to keep it.

// IdentityBoundDoc names one node-local cache of an org-signed, identity-bound
// document.
type IdentityBoundDoc string

// The identity-bound documents, in clearing order.
const (
	IdentityDocAnnouncements  IdentityBoundDoc = "announcements"
	IdentityDocDisplayPolicy  IdentityBoundDoc = "display_policy"
	IdentityDocAgentConfig    IdentityBoundDoc = "agent_config_policy"
	IdentityDocRoutingPolicy  IdentityBoundDoc = "routing_policy"
	IdentityDocAccessGrants   IdentityBoundDoc = "access_grants"
	IdentityDocIntel          IdentityBoundDoc = "intel"
	IdentityDocPricing        IdentityBoundDoc = "pricing"
	IdentityDocBudget         IdentityBoundDoc = "budget"
	IdentityDocGuardETag      IdentityBoundDoc = "guard_bundle_etag"
	IdentityDocUpdateManifest IdentityBoundDoc = "update_manifest"
	IdentityDocMessages       IdentityBoundDoc = "org_messages"
	// IdentityDocProjectAudience is the index of the org-signed project
	// mapping (agent migration 190, lane sec-p).
	IdentityDocProjectAudience IdentityBoundDoc = "project_audience"
	// IdentityDocSecurityPurpose is the org's stated purpose for its Code
	// security views and what they show (schema_meta, lane SEC-E3 and ruling
	// P-089): a departed org's purpose and settings must not keep describing
	// it in the affected-worker notice.
	IdentityDocSecurityPurpose IdentityBoundDoc = "security_purpose"
)

// identityBoundDoc is one row of the clearing table.
type identityBoundDoc struct {
	doc IdentityBoundDoc
	// tables are the agent tables (or schema_meta keys, as "schema_meta:<key>")
	// the clear empties or resets. The coverage test reads this column.
	tables []string
	clear  func(ctx context.Context, s *Store, leaving *Enrolment) error
}

func execClear(stmts ...string) func(ctx context.Context, s *Store, _ *Enrolment) error {
	return func(ctx context.Context, s *Store, _ *Enrolment) error {
		for _, q := range stmts {
			if _, err := s.db.ExecContext(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}
}

var identityBoundDocs = []identityBoundDoc{
	// Rail R3: a departed org's banner must not keep rendering, and its
	// TOFU-pinned key must not refuse the next org's banner.
	{IdentityDocAnnouncements, []string{"org_announcements"}, execClear(`DELETE FROM org_announcements`)},
	// The org's developer cost-display choice (migration 148) is the org's: a
	// node that left it shows dollars again, like any solo install.
	{IdentityDocDisplayPolicy, []string{"org_display_policy"}, execClear(`DELETE FROM org_display_policy`)},
	// The org AI tool policy (agent migration 157) and its applied state: a
	// departed org's policy must not keep locking the developer's settings.
	{IdentityDocAgentConfig, []string{"org_agent_config_policy", "agent_config_org_state"}, func(ctx context.Context, s *Store, _ *Enrolment) error {
		return s.ClearOrgAgentConfig(ctx)
	}},
	// §R19.1: leaving an org drops its routing layer, and its pin must not
	// poison the next enrolment.
	{IdentityDocRoutingPolicy, []string{"org_routing_policies"}, execClear(`DELETE FROM org_routing_policies`)},
	// The org's access grants and this node's queued requests to it
	// (migration 152): grants are the org speaking for one member.
	{IdentityDocAccessGrants, []string{"org_access_grants", "org_access_grant_state", "access_request_outbox"}, func(ctx context.Context, s *Store, _ *Enrolment) error {
		return s.clearAccessGrants(ctx)
	}},
	// Org-served cloud intelligence (migrations 112/114 and the parity
	// tables): the result cache, the requirement document and the submission
	// outbox go, the departed org's consent ends with a 'leave' event, and the
	// clear is recorded in the local receipts.
	{IdentityDocIntel, []string{"org_intel_cache", "org_intel_requirement", "org_intel_outbox"}, func(ctx context.Context, s *Store, leaving *Enrolment) error {
		cached, err := countOrgIntelCache(ctx, s.db)
		if err != nil {
			return fmt.Errorf("count intel cache: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM org_intel_cache`); err != nil {
			return fmt.Errorf("clear intel cache: %w", err)
		}
		return s.leaveOrgIntel(ctx, leaving, cached)
	}},
	// The org's signed PRICE document (migration 106): cost is stamped at
	// capture with no re-pricing, so a departed org's rates must not price
	// one more turn. The singleton row is RESET, not deleted, so a later
	// enrolment's SaveOrgPricing UPDATE still matches it. pricing_feed_cache
	// is the node's own public feed and is deliberately not listed.
	{IdentityDocPricing, []string{"org_pricing_cache"}, execClear(`
UPDATE org_pricing_cache
   SET version = 0, org_key_fingerprint = '', body_json = '', fetched_at = '', state = ''
 WHERE id = 1`)},
	// The signed budget body is resolved per member and per enrolment epoch.
	{IdentityDocBudget, []string{"org_budget_cache"}, func(ctx context.Context, s *Store, _ *Enrolment) error {
		return s.ClearOrgBudget(ctx)
	}},
	// The guard bundle's ETag: the bundle FILE is the caller's (cmd/observer
	// removes it on unenrol, orgclient on a re-enrolment); its conditional-GET
	// validator must not be offered to the next org's server.
	{IdentityDocGuardETag, []string{"schema_meta:" + orgPolicyETagKey}, execClear(`DELETE FROM schema_meta WHERE key = '` + orgPolicyETagKey + `'`)},
	// The update manifest the org's distribution key signed (agent migration
	// 105): its replay memory (last_manifest_version) would refuse the next
	// org's lower-numbered manifests, and its bytes are not the next org's
	// offer. An apply in flight keeps the row (it owns it until it finishes).
	{IdentityDocUpdateManifest, []string{"update_state"}, func(ctx context.Context, s *Store, _ *Enrolment) error {
		return s.forgetOrgUpdateManifest(ctx)
	}},
	// Admin and developer messaging (agent migrations 173 to 176): the
	// messages were signed for one member of one org, the cursor and version
	// belong to that org's lineage, and the outbox holds words meant for it.
	// The project audience's mapping index (agent migration 190): the
	// departed org's projects must not keep matching this node's directories.
	// The mapping and envelope files beside the bundle cache are the
	// caller's, like the bundle file, and are inert without a v3 bundle.
	// The downgrade fence (the guard_policy_state `#project-audience` rows,
	// audit finding 9) goes with it: a new enrolment identity starts a new
	// fence, so a different org at the same server URL, or a server restored
	// to a lower epoch for a re-enrolled node, is not refused forever.
	{IdentityDocProjectAudience, []string{"org_project_mapping_index", "guard_policy_state"}, func(ctx context.Context, s *Store, _ *Enrolment) error {
		if err := s.ClearOrgProjectMappingIndex(ctx); err != nil {
			return err
		}
		return s.ClearProjectAudienceFence(ctx)
	}},
	{
		IdentityDocSecurityPurpose,
		[]string{"schema_meta:" + securityOrgPurposeKey, "schema_meta:" + securityOrgVisibilityKey},
		execClear(`DELETE FROM schema_meta WHERE key IN ('` + securityOrgPurposeKey + `', '` + securityOrgVisibilityKey + `')`),
	},
	{
		IdentityDocMessages,
		[]string{"org_message_rail", "org_message_threads_local", "org_messages_inbox", "org_message_outbox"},
		func(ctx context.Context, s *Store, _ *Enrolment) error {
			return s.clearOrgMessages(ctx)
		},
	},
}

// IdentityBoundDocs lists every identity-bound document ClearIdentityBoundDocs
// clears, in order. orgclient's enrolment decision table is checked against it.
func IdentityBoundDocs() []IdentityBoundDoc {
	out := make([]IdentityBoundDoc, len(identityBoundDocs))
	for i, d := range identityBoundDocs {
		out[i] = d.doc
	}
	return out
}

// ClearIdentityBoundDocs clears every cached org document bound to the
// enrolment identity `leaving` (nil when unknown). DeleteEnrolment calls it on
// unenrol; orgclient.Enroll calls it when a re-enrolment changes the org or the
// member. It stops at the first failure: the caller fails closed (Enroll does
// not write the new enrolment over a half-cleared cache).
func (s *Store) ClearIdentityBoundDocs(ctx context.Context, leaving *Enrolment) error {
	for _, d := range identityBoundDocs {
		if err := d.clear(ctx, s, leaving); err != nil {
			return fmt.Errorf("store.ClearIdentityBoundDocs: %s: %w", d.doc, err)
		}
	}
	return nil
}

// forgetOrgUpdateManifest drops the update rail's memory of the org's last
// verified manifest (channel, replay version, canonical bytes, target) and
// returns the node to idle. An apply in flight (downloading, verified,
// applying) owns the row, the same rule SaveVerifiedManifest follows, so it is
// left alone; the rollback columns are never touched.
func (s *Store) forgetOrgUpdateManifest(ctx context.Context) error {
	cur, err := s.LoadUpdateState(ctx)
	if err != nil {
		return err
	}
	switch cur.State {
	case updatespec.StateApplying, updatespec.StateDownloading, updatespec.StateVerified:
		return nil
	}
	if cur.LastManifestVersion == 0 && strings.TrimSpace(cur.ManifestJSON) == "" && cur.Channel == "" &&
		cur.TargetVersion == "" && cur.State == updatespec.StateIdle {
		return nil
	}
	mutate := func(row *UpdateStateRow) {
		row.Channel = ""
		row.LastManifestVersion = 0
		row.ManifestJSON = ""
		row.LastManifestSeenAt = ""
		row.TargetVersion = ""
		row.Reason = ""
		row.ErrorClass = ""
	}
	if cur.State == updatespec.StateIdle {
		row := cur
		mutate(&row)
		return s.SaveUpdateState(ctx, row)
	}
	return s.TransitionUpdateState(ctx, updatespec.StateIdle, mutate, UpdateEventRow{
		At:     time.Now().UTC(),
		State:  updatespec.StateIdle,
		Detail: "the org enrolment changed: the previous org's update manifest was forgotten",
	})
}
