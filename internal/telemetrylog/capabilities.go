package telemetrylog

// Capabilities describes optional broker guarantees, not the mandatory durable
// publish and at-least-once delivery contract. Natural-key idempotency never
// depends on ContentDedup. Kafka does not offer JetStream's reject-new quota or
// exact stored-record and acknowledgement-state counters.
type Capabilities struct {
	ContentDedup bool
	DiscardNew   bool
	ExactStats   bool
}

// CapabilityProvider exposes optional guarantees independently of engine names.
type CapabilityProvider interface{ Capabilities() Capabilities }

// CapabilitiesOf returns the broker's optional guarantees. Existing adapters
// predate this seam and implement all three; new adapters must declare theirs.
func CapabilitiesOf(log Log) Capabilities {
	if provider, ok := log.(CapabilityProvider); ok {
		return provider.Capabilities()
	}
	return Capabilities{ContentDedup: true, DiscardNew: true, ExactStats: true}
}
