package models

// Cloud-agent usage and sync vocabularies (cloud-agents arc, decision CA-D11
// and plan section 4.1). Each is a closed set mirrored by a CHECK constraint
// in agent migration 241; the store validates against these tables before it
// writes and a store test inserts every member, so the two copies cannot
// drift silently.

// Usage measurement sources: who measured a cloud_usage_ledger figure.
const (
	// UsageSourceExporter is a measurement from a telemetry exporter
	// (vendor-native OTLP from the cloud runtime, Rail T).
	UsageSourceExporter = "exporter"
	// UsageSourceProviderRunTotal is the provider's own finalized total for
	// a run or session (Rail P).
	UsageSourceProviderRunTotal = "provider_run_total"
	// UsageSourceOrgReport is an organization-level report (a daily usage
	// report or analytics export).
	UsageSourceOrgReport = "org_report"
	// UsageSourceInvoice is an invoice or billing-ledger line.
	UsageSourceInvoice = "invoice"
)

// Usage value types: how a figure relates to time. A cumulative counter or a
// snapshot is never summed across reports.
const (
	// UsageValueSnapshot is a point-in-time reading of a total.
	UsageValueSnapshot = "snapshot"
	// UsageValueDelta is an increment since the previous report.
	UsageValueDelta = "delta"
	// UsageValueInterval is a total over a stated interval.
	UsageValueInterval = "interval"
	// UsageValueCumulative is a monotonically accumulating counter.
	UsageValueCumulative = "cumulative"
	// UsageValueGauge is a level that can go up or down (a balance, a quota
	// percentage).
	UsageValueGauge = "gauge"
)

// Usage monetary statuses: what kind of money, if any, a figure is.
const (
	// UsageMonetaryNone marks a figure that is not money (ACUs, credits,
	// seconds, quota percentage).
	UsageMonetaryNone = "not_monetary"
	// UsageMonetaryReported is a charge the vendor reported.
	UsageMonetaryReported = "reported_charge"
	// UsageMonetaryEstimated is a charge the vendor or Observer estimated.
	UsageMonetaryEstimated = "estimated_charge"
	// UsageMonetaryQuota is a quota or subscription allocation, not
	// additional cash spent.
	UsageMonetaryQuota = "quota_allocation"
	// UsageMonetaryAPIEquivalent is a hypothetical API-list-price
	// equivalent, never an actual charge.
	UsageMonetaryAPIEquivalent = "api_equivalent"
)

// Cloud sync checkpoint streams: the independently checkpointed streams of
// one connector account.
const (
	// SyncStreamDiscovery is session discovery (list sessions updated since).
	SyncStreamDiscovery = "discovery"
	// SyncStreamSessionHistory is one session's message or event history;
	// its checkpoint scope is the session id.
	SyncStreamSessionHistory = "session_history"
	// SyncStreamUsage is usage reports.
	SyncStreamUsage = "usage"
	// SyncStreamLive is a live stream (SSE or WebSocket).
	SyncStreamLive = "live"
)

var (
	usageSources = []string{
		UsageSourceExporter, UsageSourceProviderRunTotal, UsageSourceOrgReport, UsageSourceInvoice,
	}
	usageValueTypes = []string{
		UsageValueSnapshot, UsageValueDelta, UsageValueInterval, UsageValueCumulative, UsageValueGauge,
	}
	usageMonetaryStatuses = []string{
		UsageMonetaryNone, UsageMonetaryReported, UsageMonetaryEstimated, UsageMonetaryQuota, UsageMonetaryAPIEquivalent,
	}
	syncStreams = []string{
		SyncStreamDiscovery, SyncStreamSessionHistory, SyncStreamUsage, SyncStreamLive,
	}
)

func inVocab(v string, vocab []string) bool {
	for _, k := range vocab {
		if v == k {
			return true
		}
	}
	return false
}

func copyVocab(vocab []string) []string {
	out := make([]string, len(vocab))
	copy(out, vocab)
	return out
}

// KnownUsageSource reports whether s is one of the UsageSource* constants.
func KnownUsageSource(s string) bool { return inVocab(s, usageSources) }

// KnownUsageValueType reports whether s is one of the UsageValue* constants.
func KnownUsageValueType(s string) bool { return inVocab(s, usageValueTypes) }

// KnownUsageMonetaryStatus reports whether s is one of the UsageMonetary*
// constants.
func KnownUsageMonetaryStatus(s string) bool { return inVocab(s, usageMonetaryStatuses) }

// KnownSyncStream reports whether s is one of the SyncStream* constants.
func KnownSyncStream(s string) bool { return inVocab(s, syncStreams) }

// UsageSources returns the measurement-source vocabulary (a copy).
func UsageSources() []string { return copyVocab(usageSources) }

// UsageValueTypes returns the value-type vocabulary (a copy).
func UsageValueTypes() []string { return copyVocab(usageValueTypes) }

// UsageMonetaryStatuses returns the monetary-status vocabulary (a copy).
func UsageMonetaryStatuses() []string { return copyVocab(usageMonetaryStatuses) }

// SyncStreams returns the checkpoint-stream vocabulary (a copy).
func SyncStreams() []string { return copyVocab(syncStreams) }
