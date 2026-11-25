package schema

import _ "embed"

// JSON is the raw generated schema document (a configschema.Descriptor
// with doc text). Never edit by hand.
//
//go:embed schema.gen.json
var JSON []byte
