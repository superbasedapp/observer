package devcontainer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// MaxBytes caps the file the reader accepts.
const MaxBytes = 256 << 10

// ignoredFields are the fields that would run something on the host or
// raise a container's privilege. Observer's container sandbox ignores every
// one (it never honours them), and the repository trust check reports them
// (agentconfig's devcontainerFields table says which, under which
// condition).
var ignoredFields = []string{
	"initializeCommand", "onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand",
	"runArgs", "privileged", "capAdd", "securityOpt", "mounts", "build", "dockerFile", "dockerfile", "context",
	"dockerComposeFile", "service", "runServices", "workspaceMount", "workspaceFolder", "features", "overrideFeatureInstallOrder",
	"remoteEnv", "remoteUser", "containerUser", "updateRemoteUserUID", "userEnvProbe", "init", "forwardPorts", "appPort",
	"portsAttributes", "otherPortsAttributes", "hostRequirements", "overrideCommand", "shutdownAction", "customizations",
}

// IgnoredFields returns the ignored field names (a copy).
func IgnoredFields() []string { return append([]string(nil), ignoredFields...) }

// File is what the reader takes from a devcontainer.json.
type File struct {
	// Image is the raw `image` value; nil when the file has none.
	Image json.RawMessage
	// ContainerEnv is the `containerEnv` string map; nil when the file has
	// none.
	ContainerEnv map[string]string
	// Ignored are the host-executing or privilege fields present, sorted.
	Ignored []string
	// IgnoredRaw holds each ignored field's value as compact JSON.
	IgnoredRaw map[string]string
}

// ParseDevcontainer reads devcontainer.json (JSON with comments and
// trailing commas). It is the one reader of the file: the container
// sandbox driver adopts from its result and the repository trust check
// reports from it, so the two can never disagree about which fields are
// present or whether the file parses.
func ParseDevcontainer(raw []byte) (File, error) {
	if len(raw) > MaxBytes {
		return File{}, fmt.Errorf("devcontainer.json is over %d bytes", MaxBytes)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(StripJSONC(raw), &m); err != nil {
		return File{}, fmt.Errorf("devcontainer.json: %w", err)
	}
	var f File
	if img, ok := m["image"]; ok {
		f.Image = img
	}
	if env, ok := m["containerEnv"]; ok {
		var e map[string]string
		if json.Unmarshal(env, &e) != nil {
			return File{}, fmt.Errorf("devcontainer.json: containerEnv is not a string map")
		}
		if e == nil {
			e = map[string]string{}
		}
		f.ContainerEnv = e
	}
	for _, name := range ignoredFields {
		if v, ok := m[name]; ok {
			f.Ignored = append(f.Ignored, name)
			if f.IgnoredRaw == nil {
				f.IgnoredRaw = map[string]string{}
			}
			var buf bytes.Buffer
			if json.Compact(&buf, v) != nil {
				buf.Reset()
				buf.Write(v)
			}
			f.IgnoredRaw[name] = buf.String()
		}
	}
	sort.Strings(f.Ignored)
	return f, nil
}

// StripJSONC removes // and /* */ comments outside strings and trailing
// commas before a closing brace or bracket, leaving plain JSON.
func StripJSONC(in []byte) []byte {
	out := make([]byte, 0, len(in))
	inStr, esc := false, false
	for i := 0; i < len(in); i++ {
		c := in[i]
		if inStr {
			out = append(out, c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(in) && in[i+1] == '/':
			for i < len(in) && in[i] != '\n' {
				i++
			}
			if i < len(in) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(in) && in[i+1] == '*':
			i += 2
			for i+1 < len(in) && (in[i] != '*' || in[i+1] != '/') {
				i++
			}
			i++
		case c == ',':
			j := i + 1
			for j < len(in) && (in[j] == ' ' || in[j] == '\t' || in[j] == '\n' || in[j] == '\r') {
				j++
			}
			if j < len(in) && (in[j] == '}' || in[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}
