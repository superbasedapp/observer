package otelident

// Echo marker: Observer stamps EchoAttr=EchoValue on the telemetry it
// exports itself (internal/exporter/otel); a receiver that sees it never
// reads the resource back in.
const (
	EchoAttr  = "sbo.emitted_by"
	EchoValue = "observer"
)

// TenantKeys are the attributes a hosted application's tenant (the
// CUSTOMER's own tenant, never the Observer org) is read from, in Plane A's
// candidate order (internal/obs/ingest).
var TenantKeys = []string{"sbo.tenant", "tenant.id", "tenant", "traceloop.association.properties.tenant_id"}

// UserKeys are the attributes a hosted application's END USER is read from,
// in Plane A's candidate order (internal/obs/ingest). The end user is PII
// (plan §3 principle 3): a wire row carries its hash always and the raw value
// only under the raw-content predicate.
var UserKeys = []string{
	"sbo.user",
	"enduser.id", // OTel (deprecated in favour of user.id, still emitted)
	"user.id",    // OTel general + OpenInference
	"user",
	"langfuse.user.id",
	"traceloop.association.properties.user_id",
}

// HostedAppKeys returns every hosted-app identity key: TenantKeys then
// UserKeys, as a fresh slice. Any one of them on a resource or record marks
// it a hosted application's (Plane A). Deliberately NOT widened with the
// session/service/environment/release keys below: those also appear on
// telemetry that is not a hosted app's (internal/ownagent reads this set).
func HostedAppKeys() []string {
	out := make([]string, 0, len(TenantKeys)+len(UserKeys))
	out = append(out, TenantKeys...)
	return append(out, UserKeys...)
}

// SessionKeys are the attributes a trace's session (the app's conversation
// or user session, not an Observer coding session) is read from, in
// candidate order. thread.id stays last: it is a session fallback only.
var SessionKeys = []string{
	"sbo.session",
	"session.id", // OTel + OpenInference
	"gen_ai.conversation.id",
	"conversation.id",
	"langfuse.session.id",
	"traceloop.association.properties.session_id",
	"thread.id",
}

// ServiceKeys name the service a trace belongs to. Resource-scoped ONLY
// (plan §3 principle 3: service comes from the resource); a span attribute
// of the same name is ignored.
var ServiceKeys = []string{"service.name"}

// EnvironmentKeys are the attributes the app's deployment environment
// (production / staging / ...) is read from, in candidate order. The Observer
// org's own workspace environment comes from the ingest credential, never
// from these (principle 3).
var EnvironmentKeys = []string{
	"sbo.environment",
	"deployment.environment.name", // OTel semconv >= 1.27
	"deployment.environment",      // OTel semconv < 1.27
	"langfuse.environment",
	"environment",
}

// ReleaseKeys are the attributes the app's release (build / version label)
// is read from, in candidate order. service.version is the resource-level
// fallback; an explicit release attribute beats it.
var ReleaseKeys = []string{
	"sbo.release",
	"langfuse.release",
	"release",
	"service.version",
}

// TagKeys carry a trace's tags: a string array, a JSON-encoded array string,
// or a comma-separated string (ParseTags accepts all three).
var TagKeys = []string{
	"sbo.tags",
	"langfuse.trace.tags",
	"tag.tags", // OpenInference
	"tags",
}

// MetadataKeys carry a trace's metadata as ONE value: a kvlist or a
// JSON-encoded object string (ParseMetadataJSON).
var MetadataKeys = []string{
	"sbo.metadata",
	"langfuse.trace.metadata",
	"metadata", // OpenInference (JSON string)
}

// MetadataPrefixes carry a trace's metadata FLATTENED: every attribute whose
// key starts with one of these contributes one entry, keyed by the remainder
// (e.g. langfuse.trace.metadata.plan=pro -> plan=pro). Identity keys that
// also sit under a prefix (traceloop's user_id/session_id/tenant_id) are
// identity, not metadata: a mapper skips any key already in an identity list.
var MetadataPrefixes = []string{
	"sbo.metadata.",
	"langfuse.trace.metadata.",
	"langfuse.metadata.",
	"traceloop.association.properties.",
}

// Bounds of the identity contract. Every writer (mapper, node store, org
// ingest) clamps with these, so a hostile or chatty app cannot grow a trace
// row without limit.
const (
	MaxValueLen         = 256 // tenant, end user, session, service, environment, release
	MaxTags             = 32
	MaxTagLen           = 128
	MaxMetadataKeys     = 32
	MaxMetadataKeyLen   = 128
	MaxMetadataValueLen = 512
)

// Field is one identity field whose trace-level value may come from either
// the resource or a span. The bit is set in a FieldSet when the value came
// from a span attribute.
type Field uint8

// The span-overridable identity fields. Service is absent on purpose: it is
// resource-only.
const (
	FieldTenant Field = 1 << iota
	FieldUser
	FieldSession
	FieldEnvironment
	FieldRelease
)

// FieldSet records, per identity field, whether the trace's value came from
// a SPAN attribute (bit set) or from the resource (bit clear). It is the
// precedence input of the store merge: a span-level value beats a
// resource-level value; at equal level the first stored value is kept.
type FieldSet uint8

// Has reports whether f is marked span-sourced.
func (s FieldSet) Has(f Field) bool { return s&FieldSet(f) != 0 }

// With returns s with f marked span-sourced.
func (s FieldSet) With(f Field) FieldSet { return s | FieldSet(f) }

// Without returns s with f marked resource-sourced.
func (s FieldSet) Without(f Field) FieldSet { return s &^ FieldSet(f) }
