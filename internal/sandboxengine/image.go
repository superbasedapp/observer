package sandboxengine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// image.go is the image half of the container driver's default-image
// handling (sandbox plan v2 section 12.3, lane SBX-P3C): a pull by digest
// whose progress stream is read event by event, the removal of one image
// reference (never forced: an image a container still uses answers 409,
// returned as the error), and the containers made from an image.

// PullEvent is one line of the engine's pull progress stream.
type PullEvent struct {
	// Status is the engine's status ("Downloading", "Pull complete",
	// "Digest: sha256:...", "Status: Downloaded newer image for ...").
	Status string
	// ID is the layer the event is about ("" for the whole pull).
	ID string
	// Current and Total are the layer's progress in bytes (0 when the event
	// carries none).
	Current int64
	Total   int64
	// Error is the engine's error message (the stream's last event).
	Error string
}

// maxPullStream caps the progress stream read.
const maxPullStream = 64 << 20

// ImagePullStream is POST /images/create?fromImage=<ref>: the ENGINE fetches
// the image; each progress event is handed to each (nil for none). An error
// event in the stream comes back as an *APIError carrying its message.
func (c *Client) ImagePullStream(ctx context.Context, ref string, each func(PullEvent)) error {
	p, err := c.versioned("/images/create")
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, c.stream, "image pull", http.MethodPost, p, url.Values{"fromImage": {ref}}, nil, false)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxPullStream))
	for {
		var m struct {
			Status         string `json:"status"`
			ID             string `json:"id"`
			ProgressDetail struct {
				Current int64 `json:"current"`
				Total   int64 `json:"total"`
			} `json:"progressDetail"`
			Error       string `json:"error"`
			ErrorDetail struct {
				Message string `json:"message"`
			} `json:"errorDetail"`
		}
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("sandboxengine: image pull: %w", err)
		}
		msg := m.Error
		if msg == "" {
			msg = m.ErrorDetail.Message
		}
		if each != nil {
			each(PullEvent{Status: m.Status, ID: m.ID, Current: m.ProgressDetail.Current, Total: m.ProgressDetail.Total, Error: msg})
		}
		if msg != "" {
			return &APIError{Op: "image pull", Status: http.StatusOK, Message: msg}
		}
	}
}

// ImageRemove is DELETE /images/{ref} (never forced; the engine keeps the
// layers another image shares). An image already gone is not an error; an
// image a container still uses answers 409, returned as the error.
func (c *Client) ImageRemove(ctx context.Context, ref string) error {
	p, err := c.versioned("/images/" + url.PathEscape(ref))
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, c.hc, "image remove", http.MethodDelete, p, url.Values{"force": {"0"}, "noprune": {"0"}}, nil, false)
	if IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}

// ContainersUsing lists every container (running or not) made from image,
// by id.
func (c *Client) ContainersUsing(ctx context.Context, image string) ([]string, error) {
	list, err := c.ContainerList(ctx, map[string][]string{"ancestor": {image}})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, f := range list {
		out = append(out, f.ID)
	}
	return out, nil
}

// ImagePull is ImagePullStream with no callback: the ENGINE fetches the
// image (`observer sandbox oci pull`); the error carries the engine's own
// message.
func (c *Client) ImagePull(ctx context.Context, ref string) error {
	return c.ImagePullStream(ctx, ref, nil)
}
