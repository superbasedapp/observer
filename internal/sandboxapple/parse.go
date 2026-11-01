package sandboxapple

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// parse.go reads the JSON the container CLI prints for `container ls
// --format json` and `container inspect` (an array of container snapshots,
// each a "configuration" with the id, image, labels, resources, mounts,
// read-only paths and published sockets, plus the run "status" and the
// attached networks) and for `container image list --format json`. The
// decoder is tolerant of fields it does not know and strict about the ones
// it needs: an entry with no id, or a status of no shape it knows, is
// refused, never guessed. Where the CLI changed a shape between releases
// (the 1.6.0 status object, the 1.6.0 image list), each shape it has
// printed is one row of a table, tried in order. The samples under testdata
// are the reconstructed pre-1.6 shapes and the live 1.6.0 captures of
// 2026-10-23 (the *_live files, anonymized).

// Container is the part of a snapshot the driver uses.
type Container struct {
	ID          string
	Status      string
	Image       string
	Labels      map[string]string
	CPUs        int
	MemoryBytes int64
	Networks    []string
	Mounts      []Mount
	// ReadOnlyPaths are the configuration's read-only paths (the runtime's
	// own defaults, such as /proc/sys, included).
	ReadOnlyPaths []string
	// PublishedSockets are the configuration's published sockets.
	PublishedSockets []PublishSocket
}

type rawSnapshot struct {
	Status        json.RawMessage `json:"status"`
	Configuration struct {
		ID    string `json:"id"`
		Image struct {
			Reference string `json:"reference"`
		} `json:"image"`
		Labels    map[string]string `json:"labels"`
		Resources struct {
			CPUs          int   `json:"cpus"`
			MemoryInBytes int64 `json:"memoryInBytes"`
		} `json:"resources"`
		Mounts []struct {
			Source      string   `json:"source"`
			Destination string   `json:"destination"`
			Options     []string `json:"options"`
		} `json:"mounts"`
		Networks         []json.RawMessage `json:"networks"`
		ReadonlyPaths    []string          `json:"readonlyPaths"`
		PublishedSockets []struct {
			HostPath      string `json:"hostPath"`
			ContainerPath string `json:"containerPath"`
		} `json:"publishedSockets"`
	} `json:"configuration"`
	Networks []struct {
		Network string `json:"network"`
		Address string `json:"address"`
	} `json:"networks"`
}

// runStatus is what one status shape established.
type runStatus struct {
	State    string
	Networks []string
}

// statusShapes are the run-status shapes the CLI has printed, tried in
// order; the first that decodes wins. An absent or null status is no
// status (an empty state), never a refusal.
var statusShapes = []struct {
	name   string
	decode func(json.RawMessage) (runStatus, bool)
}{
	// Before 1.6.0 (the reconstructed reference): a bare string.
	{"string", func(raw json.RawMessage) (runStatus, bool) {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return runStatus{}, false
		}
		return runStatus{State: s}, true
	}},
	// 1.6.0 (live 2026-10-23): {"state": "running", "networks": [{"network":
	// "default", ...}], "startedDate": ...}.
	{"object", func(raw json.RawMessage) (runStatus, bool) {
		var o struct {
			State    *string `json:"state"`
			Networks []struct {
				Network string `json:"network"`
			} `json:"networks"`
		}
		if json.Unmarshal(raw, &o) != nil || o.State == nil {
			return runStatus{}, false
		}
		st := runStatus{State: *o.State}
		for _, n := range o.Networks {
			if n.Network != "" {
				st.Networks = append(st.Networks, n.Network)
			}
		}
		return st, true
	}},
}

// decodeStatus walks statusShapes.
func decodeStatus(raw json.RawMessage) (runStatus, error) {
	if t := strings.TrimSpace(string(raw)); t == "" || t == "null" {
		return runStatus{}, nil
	}
	for _, sh := range statusShapes {
		if st, ok := sh.decode(raw); ok {
			return st, nil
		}
	}
	return runStatus{}, fmt.Errorf("a status of no shape this build reads")
}

// maxListBytes caps what the parser reads (the CLI's output is captured
// with the same cap by the cmd layer).
const maxListBytes = 8 << 20

// ParseList reads `container ls --format json` or `container inspect`
// output.
func ParseList(b []byte) ([]Container, error) {
	if len(b) > maxListBytes {
		return nil, fmt.Errorf("sandboxapple.ParseList: %d bytes is over the %d cap", len(b), maxListBytes)
	}
	var raw []rawSnapshot
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("sandboxapple.ParseList: %w", err)
	}
	out := make([]Container, 0, len(raw))
	for i, r := range raw {
		c := r.Configuration
		if c.ID == "" {
			return nil, fmt.Errorf("sandboxapple.ParseList: entry %d has no id", i)
		}
		st, err := decodeStatus(r.Status)
		if err != nil {
			return nil, fmt.Errorf("sandboxapple.ParseList: entry %d: %w", i, err)
		}
		ct := Container{
			ID: c.ID, Status: strings.ToLower(st.State), Image: c.Image.Reference, Labels: c.Labels,
			CPUs: c.Resources.CPUs, MemoryBytes: c.Resources.MemoryInBytes,
			ReadOnlyPaths: append([]string(nil), c.ReadonlyPaths...),
		}
		addNet := func(name string) {
			if name != "" && !contains(ct.Networks, name) {
				ct.Networks = append(ct.Networks, name)
			}
		}
		for _, n := range r.Networks {
			addNet(n.Network)
		}
		for _, n := range st.Networks {
			addNet(n)
		}
		for _, n := range c.Networks {
			addNet(networkName(n))
		}
		for _, m := range c.Mounts {
			ro := false
			for _, o := range m.Options {
				ro = ro || o == "ro" || o == "readonly"
			}
			ct.Mounts = append(ct.Mounts, Mount{Source: m.Source, Target: m.Destination, ReadOnly: ro})
		}
		for _, s := range c.PublishedSockets {
			ct.PublishedSockets = append(ct.PublishedSockets, PublishSocket{Host: s.HostPath, Guest: s.ContainerPath})
		}
		sort.Strings(ct.Networks)
		out = append(out, ct)
	}
	return out, nil
}

// networkName reads a configured network, a bare name or {"network": name}.
func networkName(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Network string `json:"network"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.Network
	}
	return ""
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// imageShapes are the image-list entry shapes the CLI has printed, tried in
// order: each yields the entry's name and its descriptor digest, or ok=false
// when the entry is not of that shape.
var imageShapes = []struct {
	name   string
	decode func(json.RawMessage) (name, digest string, ok bool)
}{
	// Before 1.6.0 (the reconstructed reference): {"reference": ...,
	// "descriptor": {"digest": ...}} at the top of the entry.
	{"reference", func(raw json.RawMessage) (string, string, bool) {
		var e struct {
			Reference  string `json:"reference"`
			Descriptor struct {
				Digest string `json:"digest"`
			} `json:"descriptor"`
		}
		if json.Unmarshal(raw, &e) != nil || (e.Reference == "" && e.Descriptor.Digest == "") {
			return "", "", false
		}
		return e.Reference, e.Descriptor.Digest, true
	}},
	// 1.6.0 (live 2026-10-23): {"configuration": {"name": ..., "descriptor":
	// {"digest": ...}}, "id": ..., "variants": [...]}.
	{"configuration", func(raw json.RawMessage) (string, string, bool) {
		var e struct {
			Configuration struct {
				Name       string `json:"name"`
				Descriptor struct {
					Digest string `json:"digest"`
				} `json:"descriptor"`
			} `json:"configuration"`
		}
		if json.Unmarshal(raw, &e) != nil || (e.Configuration.Name == "" && e.Configuration.Descriptor.Digest == "") {
			return "", "", false
		}
		return e.Configuration.Name, e.Configuration.Descriptor.Digest, true
	}},
}

// ImagePresent reports whether `container image list --format json` output
// holds the digest ref names (name@sha256:<hex>): an image whose descriptor
// digest equals it, or whose name is pinned by it, in any shape of
// imageShapes. A tag alone never matches.
func ImagePresent(b []byte, ref string) (bool, error) {
	if len(b) > maxListBytes {
		return false, fmt.Errorf("sandboxapple.ImagePresent: output over the cap")
	}
	_, digest, ok := strings.Cut(ref, "@")
	if !ok || !strings.HasPrefix(digest, "sha256:") {
		return false, fmt.Errorf("sandboxapple.ImagePresent: %q is not pinned by digest", ref)
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return false, fmt.Errorf("sandboxapple.ImagePresent: %w", err)
	}
	for _, entry := range raw {
		for _, sh := range imageShapes {
			name, d, ok := sh.decode(entry)
			if !ok {
				continue
			}
			if d == digest || strings.HasSuffix(name, "@"+digest) {
				return true, nil
			}
			break
		}
	}
	return false, nil
}

// SameImage reports whether two image references name the same image: equal
// strings, or both pinned by the same digest (the CLI prints a configured
// "local/x@sha256:..." back as "docker.io/local/x@sha256:...").
func SameImage(a, b string) bool {
	if a == b {
		return true
	}
	_, da, okA := strings.Cut(a, "@sha256:")
	_, db, okB := strings.Cut(b, "@sha256:")
	return okA && okB && da != "" && da == db
}
