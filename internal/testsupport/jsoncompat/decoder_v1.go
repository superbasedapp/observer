//go:build !goexperiment.jsonv2

package jsoncompat

// V1Decoder reports whether this build backs encoding/json with the v1
// implementation (GOEXPERIMENT=nojsonv2 on Go 1.27, or any earlier Go).
const V1Decoder = true
