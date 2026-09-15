// Package pricingfeed is the SHARED CONTRACT for the Tokenomics -> SuperBased
// pricing feed (docs/plans/pricing-sync-tokenomics-to-platform-plan-2026-09-11.md,
// Wave 0). It is the one place the publisher (model-pricing/, Wave T), the org
// importer (internal/orgserver/pricingfeed, Wave O) and the standalone node
// feed client (Wave N) all derive the SAME signing bytes and verify against the
// SAME compiled-in vendor key.
//
// WHY A PURE PACKAGE. Like internal/orgcontract (the org price-policy rail this
// feed deliberately mirrors), this package is a contract, not a consumer: it
// owns wire types, the canonical-body rule, the domain tag, the compiled vendor
// key and offline verification, and it touches NO database/sql, net/http,
// fsnotify or os/exec — imports_test.go pins that. The network lane (the node's
// opt-in fetch, §C.3) and the SQL (the node cache, the org bookkeeping table)
// live in the Wave N / Wave O packages that import this one; they never leak
// back in.
//
// THE SHAPE. The feed row EMBEDS orgcontract.PricingPolicyRow verbatim (§A) so
// no consumer does a code-level rate translation: the platform already speaks
// exactly one price vocabulary, and the feed speaks it too. The only addition
// per row is the Tokenomics quality Grade, carried out of band of the rate
// vocabulary so the org importer can gate auto-apply vs park on grade.
//
// OFFLINE VERIFY, FAIL CLOSED. A feed body is signed by the operator-held
// private half of PricingFeedPublicKeyV1 (the internal/update/vendorkey.go
// rotation-slot pattern). Every consumer verifies offline against the compiled
// key set and REFUSES an unsigned or mis-signed body rather than applying it
// (§E). The domain tag is DISTINCT per rail (the ROUTING-SIG-1 lesson) so a
// signature minted for the org policy rail can never verify here and vice
// versa.
package pricingfeed
