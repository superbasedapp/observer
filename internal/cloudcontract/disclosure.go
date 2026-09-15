package cloudcontract

// ProviderPostureDisclosure is the one-sentence provider-retention disclosure
// every consent surface renders verbatim (operator ruling 2026-09-15, option C
// in docs/modified-abuse-monitoring-filing.md s8): the node dashboard's
// consent screen, `observer cloud enable`, and the hosted portal's served
// consent notice. It applies to EVERY consent level - the structural purpose
// already carries the first prompt - and it is the same posture the privacy
// page's Azure AI Foundry row states and the hosted worker's
// provider_retention_disclosed attestation mode records. Keep the three in
// step: a change here is a privacy-policy change (bump
// ProviderPosturePolicyVersion and the page's effective date together).
const ProviderPostureDisclosure = "Analysis runs on Microsoft Azure AI Foundry in the service's own region: what is sent is processed " +
	"statelessly and is never used to train or improve models, but samples that Microsoft's automated abuse " +
	"classifiers flag may be stored there for review by authorized Microsoft staff, as described in our Privacy Policy."

// ProviderPosturePolicyVersion is the privacy-policy version under which
// ProviderPostureDisclosure was published ("1" = the 15 September 2026
// policy). A node records it on the consent it stores; the hosted worker's
// disclosed attestation mode names the same version
// (SBCI_PROVIDER_RETENTION_POLICY_VERSION), so a receipt and the attestation
// that authorized its job point at the same published text.
const ProviderPosturePolicyVersion = "1"
