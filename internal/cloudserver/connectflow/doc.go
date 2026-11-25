// Package connectflow is the pure core of the Getting started v2 connect
// flow (docs/plans/onboarding-v2-connect-flow.md; docs/security.md
// CONNECT-1): one machine asks to be signed in and connected, and a
// signed-in person approves it in the browser.
//
// It holds the decisions as data tables walked top down, and the pieces that
// need no I/O:
//
//   - the create request's field rules (ValidateCreate);
//   - the user code: minting from an unambiguous alphabet, normalising what a
//     person typed (NewUserCode, NormalizeUserCode);
//   - the status machine (Transition, EffectiveStatus);
//   - when an approved request may still hand its sign-in to the machine
//     (DeliveryDecision);
//   - the share level a dashboard kind implies (ShareLevelFor) and the
//     disclosure text shown for it, with its version and digest (Disclosure);
//   - the masked network prefix shown to the approver (NetworkPrefix);
//   - the request's purpose (purpose.go: a machine, or the AI Apps SDK
//     setup's device sign-in for the member's own SDK key) and the
//     capabilities each purpose's row carries: how its poll proves itself
//     (a device key proof, or a bearer device code minted and compared
//     here), which browser answers it takes, what an approved poll hands
//     over (a sign-in, or a key grant, KeyGrantDecision) and its disclosure
//     (SDKKeyDisclosure for an SDK key; docs/security.md SDKQS-1).
//
// SQL lives in internal/cloudserver/store and HTTP in internal/cloudserver/api;
// imports_test.go pins that this package reaches neither.
package connectflow
