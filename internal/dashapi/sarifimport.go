package dashapi

import (
	"context"
	"errors"
)

// SARIFImportTool is one row of the SARIF upload's producer picker.
type SARIFImportTool struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// ErrSARIFImportInput marks an import the file itself refused (not SARIF,
// an unsupported version, a malformed result): the upload route answers
// 400 with the error's text. Any other error is the node's and answers 500.
var ErrSARIFImportInput = errors.New("sarif import: the file was refused")

// SARIFImport is the dashboard seam of the SARIF upload (component
// security.scan.sarif-import, lane SEC-P4 decision 13), wired from
// cmd/observer/security_sarifimport_dash.go. Tools is the producer picker
// and MaxBytes the file cap, both the CLI's own; Import records one file
// on the project at root through the same function `observer security
// import-sarif` calls and returns its report. A nil SARIFImport (a build
// without the component, a test) makes the upload route answer 404.
type SARIFImport struct {
	Tools    []SARIFImportTool
	MaxBytes int
	Import   func(ctx context.Context, root, tool string, data []byte) (any, error)
}
