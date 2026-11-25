package kilo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

// The reviewed tRPC request encoder and response unwrapper (lane ENTAPI-L16C,
// T-710). Kilo's admin reads are tRPC queries over HTTP GET: the procedure is
// the last path segment (/api/trpc/<procedure>) and the input is a JSON
// object, URL-encoded in the single query parameter "input" (OpenAPI: "URL-
// encoded JSON tRPC input payload"). Each procedure's input schema declares
// additionalProperties false.
//
// The encoder is the ONLY way a Kilo driver builds a request: it takes one of
// the package's closed input types (the trpcInput interface is sealed by an
// unexported method, so no caller outside this file's types can satisfy it),
// marshals it with encoding/json and returns the path and the query. No
// caller text, filter list or free-form field ever reaches the input: every
// field is a fixed enum value of the driver or a connection parameter that
// passed its own validation first.
//
// The unwrapper reads the documented success envelope {"result": {"data":
// <procedure output>}} and returns the data member raw for the driver's own
// closed DTO; a missing result or data member is schema drift. tRPC batching
// (?batch=1, an array envelope) is never used.

// trpcInput is a closed tRPC query input.
type trpcInput interface {
	procedure() string
}

// uuidRE is the organizationId format the input schemas declare (a UUID; the
// schemas also admit the nil and max UUIDs, which never name an organization
// and are refused here).
var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// procedureRE is a tRPC procedure path (dotted identifiers).
var procedureRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(\.[A-Za-z][A-Za-z0-9]*)+$`)

// encodeTRPC builds the GET request of one closed input.
func encodeTRPC(in trpcInput) (vendorapi.Request, error) {
	p := in.procedure()
	if !procedureRE.MatchString(p) {
		return vendorapi.Request{}, fmt.Errorf("kilo: procedure %q is not a tRPC procedure path", p)
	}
	b, err := json.Marshal(in)
	if err != nil {
		return vendorapi.Request{}, fmt.Errorf("kilo: encode %s input: %w", p, err)
	}
	return vendorapi.Request{Method: "GET", Path: "/api/trpc/" + p, Query: map[string][]string{"input": {string(b)}}}, nil
}

// trpcEnvelope is the documented success envelope.
type trpcEnvelope struct {
	Result *struct {
		Data json.RawMessage `json:"data"`
	} `json:"result"`
}

// unwrapTRPC returns the data member of a 200 tRPC answer.
func unwrapTRPC(s vs.SurfaceID, r vendorapi.Response) (json.RawMessage, error) {
	if r.Status != 200 {
		return nil, vendorapi.Drift(s, "status %d is not the documented 200", r.Status)
	}
	var env trpcEnvelope
	dec := json.NewDecoder(bytes.NewReader(r.Body))
	dec.UseNumber()
	if err := dec.Decode(&env); err != nil {
		return nil, vendorapi.Drift(s, "body is not the documented tRPC envelope")
	}
	if env.Result == nil || len(env.Result.Data) == 0 || string(env.Result.Data) == "null" {
		return nil, vendorapi.Drift(s, "required field result.data is missing")
	}
	return env.Result.Data, nil
}

func decodeData(s vs.SurfaceID, raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return vendorapi.Drift(s, "result.data does not decode as the documented output")
	}
	return nil
}
