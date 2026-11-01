package main

import (
	"context"
	"encoding/json"
)

// securityMCPTool is the shape of one module-composed MCP tool (the method
// set of internal/mcp.Tool, restated so security_mcp.go never imports
// internal/mcp: an MCP-server-less build must not link it). serve.go adds
// each to the server's ExtraTools.
type securityMCPTool interface {
	Name() string
	Description() string
	InputSchema() map[string]any
	Invoke(ctx context.Context, args json.RawMessage) (any, error)
}
