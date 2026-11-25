// Package api is the ONLY HTTP owner for the hosted cloud-intelligence service
// (plan §6 CI-P3). It maps the /v1 device surface, the /portal browser BFF
// (with its webhooks) and, on the staff listener only (StaffHandler), the
// staff console to the store. Auth is applied once per route in the mux table
// (server.go): every device endpoint enforces device-bound authentication +
// per-request proof-of-possession + jti replay defense. Account scope ALWAYS
// comes from the verified auth context, never a request-body field.
package api
