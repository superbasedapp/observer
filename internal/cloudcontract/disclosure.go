package cloudcontract

// ProviderPostureDisclosure is the one-sentence provider-retention disclosure
// every consent surface renders verbatim (operator ruling 2026-09-15, option C
// in docs/modified-abuse-monitoring-filing.md s8, carried to the Anthropic
// provider by the 2026-10-20 ruling that moved Cloud Intelligence off Azure):
// the node dashboard's consent screen, `observer cloud enable`, and the hosted
// portal's served consent notice. It applies to EVERY consent level - the
// structural purpose already carries the first prompt - and it is the same
// posture the hosted worker's provider_retention_disclosed attestation mode
// records (attest.DisclosedReason: provider-side retention NOT verified, only
// disclosed). Keep them in step: a change here is a privacy-policy change (bump
// ProviderPosturePolicyVersion, and update the website privacy page's
// subprocessor row and effective date together - see docs/cloud-intelligence.md
// "Provider and disclosed attestation").
//
// What it says, and why each clause is there:
//   - which provider and model receive the evidence (Anthropic, Claude Haiku 5.5);
//   - that Anthropic does not train on API traffic (its commercial terms);
//   - that Anthropic DOES keep API inputs and outputs for a limited period under
//     its own terms, and longer for content its safety systems flag;
//   - that there is no zero-data-retention agreement, and that this service
//     cannot verify the provider's retention (nothing machine-readable exists
//     to check, which is exactly why the worker attests in disclosed mode).
const ProviderPostureDisclosure = "Analysis runs on Anthropic's Claude API (model Claude Haiku 5.5): Anthropic does not " +
	"train its models on what is sent, but keeps API inputs and outputs for a limited period under its own retention " +
	"terms, and longer for content its safety systems flag; we have no zero-data-retention agreement with Anthropic " +
	"and cannot verify its retention ourselves."

// ProviderPosturePolicyVersion is the privacy-policy version under which
// ProviderPostureDisclosure was published ("1" = the 15 September 2026 Azure AI
// Foundry policy; "2" = the Anthropic provider). A node records it on the
// consent it stores; the hosted worker's disclosed attestation mode names the
// same version (SBCI_PROVIDER_RETENTION_POLICY_VERSION), so a receipt and the
// attestation that authorized its job point at the same published text.
const ProviderPosturePolicyVersion = "2"
