package cloudcontract

import "strings"

// datadictionary.go publishes the STRUCTURAL DATA DICTIONARY digest — the
// schema-level thing a STANDING consent grant actually authorizes
// (divergence-remediation plan rev 4.1 §2 R1: the receipt binds "schema version
// + data-dictionary digest").
//
// Why a digest of a dictionary rather than of a payload: a standing grant can
// not bind one byte-string, because it authorizes a rail of future snapshots
// nobody has built yet. What it CAN bind is the exhaustive description of what
// such a snapshot may ever contain — every field name and type, the closed band
// vocabulary, and every bound. If that description changes, the developer
// consented to a different disclosure, and the grant no longer covers it.
//
// The enumeration below is therefore the CONSENT ARTIFACT, not a convenience
// summary. It is:
//
//   - versioned (the dictionary_version line), so a purely presentational
//     change to the enumeration is still a deliberate, visible act;
//   - canonically SORTED ascending, so the digest depends on the SET of
//     declarations and never on the order they happen to be written in;
//   - joined with "\n" and run through the same digest helper (digest.go) the
//     rest of this package uses, so there is one hashing convention here.
//
// TestStructuralDataDictionaryCoversEverySnapshotField walks the actual structs
// with reflection and fails if a field exists that this enumeration does not
// declare (or vice versa), so the dictionary cannot silently go stale — and
// TestStructuralDataDictionaryDigestIsPinned fails loudly on any change, with
// the standing-grant consequence spelled out.

// structuralDataDictionaryVersion versions the ENUMERATION itself (distinct
// from StructuralSnapshotSchemaVersion, which versions the wire schema). Bump
// it when the way the dictionary is expressed changes, not only when the schema
// does.
const structuralDataDictionaryVersion = "structural_data_dictionary.v1"

// structuralDataDictionary is the canonical, sorted, versioned enumeration the
// data-dictionary digest is taken over. Entries are "<category>:<declaration>"
// and the whole slice MUST stay sorted ascending (pinned by
// TestStructuralDataDictionaryIsSorted).
//
// Field entries are "field:<struct>.<json name>:<type>" — the JSON name,
// because that is what actually appears in the bytes a developer previews.
var structuralDataDictionary = []string{
	// The closed coverage-band vocabulary (values, not fields).
	"band:high",
	"band:low",
	"band:medium",
	"band:none",

	"dictionary_version:" + structuralDataDictionaryVersion,

	// StructuralCoverageDenominators.
	"field:structural_coverage_denominators.sessions_with_outcomes:int",
	"field:structural_coverage_denominators.sessions_with_verification:int",

	// StructuralMixEntry.
	"field:structural_mix_entry.count:int",
	"field:structural_mix_entry.key:string",

	// StructuralSnapshot.
	"field:structural_snapshot.action_count:int",
	"field:structural_snapshot.active:bool",
	"field:structural_snapshot.cache_read_tokens:int",
	"field:structural_snapshot.cost_usd:float64",
	"field:structural_snapshot.coverage_denominators:structural_coverage_denominators",
	"field:structural_snapshot.declared_timezone:string",
	"field:structural_snapshot.digest:string_omitempty",
	"field:structural_snapshot.model_family_mix:structural_mix_entry_list",
	"field:structural_snapshot.outcome_evidence_band:coverage_band",
	"field:structural_snapshot.period:string",
	"field:structural_snapshot.period_rule_version:int",
	"field:structural_snapshot.revision:int",
	"field:structural_snapshot.schema_version:string",
	"field:structural_snapshot.session_count:int",
	"field:structural_snapshot.source_watermark:string",
	"field:structural_snapshot.timezone_rule_version:int",
	"field:structural_snapshot.tokens_in:int",
	"field:structural_snapshot.tokens_out:int",
	"field:structural_snapshot.tool_mix:structural_mix_entry_list",
	"field:structural_snapshot.verification_coverage_band:coverage_band",

	// Every bound a snapshot is validated against.
	"limit:max_declared_timezone_bytes:64",
	"limit:max_structural_mix_entries:64",
	"limit:max_structural_mix_key_bytes:64",

	"period_layout:" + StructuralPeriodLayout,
	"schema_version:" + StructuralSnapshotSchemaVersion,
}

// StructuralDataDictionaryPreimage returns the exact bytes the data-dictionary
// digest is computed over: the canonical enumeration joined with "\n". It is
// exported so a consent surface can show a developer precisely what the digest
// on their receipt covers, rather than an opaque hex string.
func StructuralDataDictionaryPreimage() []byte {
	return []byte(strings.Join(structuralDataDictionary, "\n"))
}

// StructuralDataDictionaryDigest returns the "sha256:<hex>" digest over
// StructuralDataDictionaryPreimage(). A STANDING consent receipt binds this
// value; a queued snapshot records the value it was built under, and
// store.PrepareStructuralSend refuses to send when the two have diverged
// (ErrCloudGrantGenerationDrift) rather than uploading under terms the
// developer never saw.
func StructuralDataDictionaryDigest() string {
	return digest(StructuralDataDictionaryPreimage())
}
