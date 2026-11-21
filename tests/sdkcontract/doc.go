// Package sdkcontract pins the SDK wire contracts that span two owners (the
// org SDK control API and the node), so a renamed header or field on one side
// fails here instead of silently disabling the other side's reader (review
// finding R-A03). The SDKs' own tests read the same recorded fixtures under
// sdk/contract. Test-only: it has no production code.
package sdkcontract
