// Package routingconfig is the boundary adapter between the [routing]
// config section and the pure routing package (model-routing spec
// §R21): config cannot import routing (config is a leaf package) and
// routing cannot import config (purity-pinned by imports_test), so the
// field-by-field mirror copy lives here — ONE seam shared by every
// consumer (cmd/observer proxy wiring, the dashboard routing page),
// never duplicated.
package routingconfig
