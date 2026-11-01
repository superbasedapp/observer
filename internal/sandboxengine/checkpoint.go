package sandboxengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// checkpoint.go holds the Engine API calls of local re-adoption and of the
// Podman checkpoint and restore (sandbox plan v2 section 4.8, the control
// table's libpod row; gap G50; lane GATES-SBX): the engine's own word on
// whether it keeps a container whose attached process went away, and
// libpod's checkpoint with export and restore with import. Nothing here
// decides; internal/sandboxadopt does.

// RestartFacts are the engine facts the re-adoption table reads.
type RestartFacts struct {
	// LiveRestore is Docker's /info LiveRestoreEnabled.
	LiveRestore bool
	// ConmonPath is Podman's /libpod/info host.conmon.path ("" when the
	// engine sent none, or on Docker).
	ConmonPath string
}

// RestartFacts reads the engine's restart facts: /info on Docker, libpod
// info on Podman.
func (c *Client) RestartFacts(ctx context.Context, engine sandboxoci.Engine) (RestartFacts, error) {
	if engine == sandboxoci.EnginePodman {
		var lp struct {
			Host struct {
				Conmon struct {
					Path string `json:"path"`
				} `json:"conmon"`
			} `json:"host"`
		}
		if err := c.getJSON(ctx, "libpod info", libpodPrefix+"/info", nil, &lp); err != nil {
			return RestartFacts{}, err
		}
		return RestartFacts{ConmonPath: lp.Host.Conmon.Path}, nil
	}
	p, err := c.versioned("/info")
	if err != nil {
		return RestartFacts{}, err
	}
	var w struct {
		LiveRestoreEnabled bool `json:"LiveRestoreEnabled"`
	}
	if err := c.getJSON(ctx, "info", p, nil, &w); err != nil {
		return RestartFacts{}, err
	}
	return RestartFacts{LiveRestore: w.LiveRestoreEnabled}, nil
}

// ContainerOCIRuntime reads the OCI runtime name from a libpod container
// inspect answer (its "OCIRuntime" field); "" when absent.
func ContainerOCIRuntime(libpodInspect []byte) string {
	var w struct {
		OCIRuntime string `json:"OCIRuntime"`
	}
	if json.Unmarshal(libpodInspect, &w) != nil {
		return ""
	}
	return strings.TrimSpace(w.OCIRuntime)
}

// ErrExportCap is returned when a checkpoint export is larger than the cap
// the caller set; what was written is the caller's to remove.
var ErrExportCap = errors.New("sandboxengine: the checkpoint export is over its cap")

// ContainerCheckpointExport is libpod's POST
// /libpod/containers/{id}/checkpoint?export=true&leaveRunning=true: the
// engine streams the container's checkpoint as a tar archive, which is
// copied into w up to capBytes, and leaves the container running (so a
// refused export ends nothing; the caller removes the container once the
// export is kept). It returns the bytes written.
func (c *Client) ContainerCheckpointExport(ctx context.Context, id string, w io.Writer, capBytes int64) (int64, error) {
	q := url.Values{"export": {"true"}, "leaveRunning": {"true"}}
	resp, err := c.do(ctx, c.stream, "libpod checkpoint", http.MethodPost, libpodPrefix+"/containers/"+url.PathEscape(id)+"/checkpoint", q, nil, false)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "" && !strings.Contains(ct, "tar") && !strings.Contains(ct, "octet-stream") {
		return 0, fmt.Errorf("sandboxengine: libpod checkpoint: the engine answered %q, not an archive: %s", ct, errorMessage(resp.Body))
	}
	n, err := io.Copy(w, io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return n, fmt.Errorf("sandboxengine: libpod checkpoint: %w", err)
	}
	if n > capBytes {
		return n, ErrExportCap
	}
	return n, nil
}

// ContainerRestoreImport is libpod's POST
// /libpod/containers/{name}/restore?import=true with the export as the
// body: the engine creates the container from the archive and starts it.
// It returns the restored container's id.
func (c *Client) ContainerRestoreImport(ctx context.Context, name string, export io.Reader) (string, error) {
	u := "http://engine" + libpodPrefix + "/containers/" + url.PathEscape(name) + "/restore?" + url.Values{"import": {"true"}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, export)
	if err != nil {
		return "", fmt.Errorf("sandboxengine: libpod restore: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.stream.Do(req)
	if err != nil {
		return "", fmt.Errorf("sandboxengine: libpod restore: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", &APIError{Op: "libpod restore", Status: resp.StatusCode, Message: errorMessage(resp.Body)}
	}
	var out struct {
		ID  string `json:"Id"`
		Err any    `json:"Err"`
	}
	if err := decodeCapped(resp.Body, &out, "libpod restore"); err != nil {
		return "", err
	}
	if out.Err != nil {
		return "", fmt.Errorf("sandboxengine: libpod restore: the engine reported %v", out.Err)
	}
	if strings.TrimSpace(out.ID) == "" {
		return "", errors.New("sandboxengine: libpod restore: no container id in the answer")
	}
	return out.ID, nil
}
