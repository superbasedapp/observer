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
//   - the masked network prefix shown to the approver (NetworkPrefix).
//
// SQL lives in internal/cloudserver/store and HTTP in internal/cloudserver/api;
// imports_test.go pins that this package reaches neither.
package connectflow
