// Package schema embeds the generated config-schema artifact
// (schema.gen.json) that GET /api/config/schema serves.
//
// The file is written by `make config-schema-build` (web/cfgschema), which
// serializes internal/configschema — the one owner of structure +
// classification — plus each field's Go doc comment harvested with go/ast.
// It is embedded rather than imported into the SPA bundle so the schema
// always describes THIS daemon's build (plan §1.2): a dashboard talking to
// an older or newer daemon degrades honestly instead of rendering keys that
// do not exist. `make verify-config-schema` is the drift gate.
package schema
