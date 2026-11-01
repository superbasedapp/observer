package sandboxengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
)

// volume.go is the per-image tool cache's engine calls (sandbox plan v2
// section 5.4, lane SBX-P3C): create a labelled volume, list this install's
// cache volumes by label, remove one. A volume in use by a container is
// never forced away: the engine's 409 comes back as the error, naming it.

// Volume is one volume the engine lists.
type Volume struct {
	Name       string
	Driver     string
	Mountpoint string
	Labels     map[string]string
	Options    map[string]string
}

// VolumeCreate is POST /volumes/create with the local driver: labels, and
// driverOpts (nil for a plain engine-managed volume; the tool cache passes
// type=none, o=bind and the device of an owner-only host directory, so the
// files the setup container writes belong to the host user on every engine
// mode).
func (c *Client) VolumeCreate(ctx context.Context, name string, labels, driverOpts map[string]string) error {
	p, err := c.versioned("/volumes/create")
	if err != nil {
		return err
	}
	body := map[string]any{"Name": name, "Driver": "local", "Labels": labels}
	if len(driverOpts) > 0 {
		body["DriverOpts"] = driverOpts
	}
	resp, err := c.do(ctx, c.hc, "volume create", http.MethodPost, p, nil, body, false)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return resp.Body.Close()
}

// VolumeList is GET /volumes?filters=<filters>, sorted by name.
func (c *Client) VolumeList(ctx context.Context, filters map[string][]string) ([]Volume, error) {
	p, err := c.versioned("/volumes")
	if err != nil {
		return nil, err
	}
	f, err := json.Marshal(filters)
	if err != nil {
		return nil, err
	}
	var w struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			Labels     map[string]string `json:"Labels"`
			Options    map[string]string `json:"Options"`
		} `json:"Volumes"`
	}
	if err := c.getJSON(ctx, "volume list", p, url.Values{"filters": {string(f)}}, &w); err != nil {
		return nil, err
	}
	out := make([]Volume, 0, len(w.Volumes))
	for _, v := range w.Volumes {
		out = append(out, Volume{Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, Labels: v.Labels, Options: v.Options})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// VolumeRemove is DELETE /volumes/{name} (never forced: a volume a container
// still uses answers 409, returned as the error). A volume already gone is
// not an error.
func (c *Client) VolumeRemove(ctx context.Context, name string) error {
	p, err := c.versioned("/volumes/" + url.PathEscape(name))
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, c.hc, "volume remove", http.MethodDelete, p, nil, nil, false)
	if IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
