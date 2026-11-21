package contentchan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// Source is where FetchInstall reads one kind's files from: a network
// feed, or a directory a user copied in. It is the caller's transport;
// contentchan never opens a connection itself.
type Source interface {
	// FetchManifest returns the kind's envelope and its ETag. A non-empty
	// etag is the accepted envelope's: a source that can tell the copy is
	// current returns ErrNotModified.
	FetchManifest(ctx context.Context, kind content.Kind, etag string) (envelope []byte, newTag string, err error)
	// FetchArtifact writes entry e's bytes to w, refusing more than
	// e.SizeBytes (FetchInstall checks the exact size and digest after).
	FetchArtifact(ctx context.Context, kind content.Kind, e content.Entry, w io.Writer) error
}

// ErrNotModified is a Source's answer for a current copy (an HTTP 304).
var ErrNotModified = errors.New("contentchan: not modified")

// FetchResult is one kind's FetchInstall.
type FetchResult struct {
	// Unchanged: the source's envelope is the accepted one (or a 304).
	Unchanged bool
	// State is the kind's state after the call.
	State content.State
	// Reused counts artifacts staged from the installed copy (same name,
	// platform, size and sha256) instead of being fetched again.
	Reused int
	// Fetched counts artifacts read from the source.
	Fetched int
	// ETag is the envelope's ETag to keep for the next call ("" keeps
	// none); set only when the result is installed or already accepted.
	ETag string
}

// FetchInstall fetches kind from src and installs it under tr, the shared
// shape of every feed fetch: the envelope revalidated with etag (ignored
// while nothing is accepted), verified before any artifact is read, an
// unchanged envelope answered without a byte more, each artifact for this
// store's platform either staged from the installed copy of the same bytes
// (a hard link, a copy where refused; InstalledArtifact) or streamed from
// src to a file under the root, and the whole set handed to InstallFiles,
// which checks every size and digest against the accepted high-water mark
// before anything is installed. Any failure keeps the last-known-good, and
// a refused envelope is recorded in the kind's state.
func (s Store) FetchInstall(ctx context.Context, kind content.Kind, tr Trust, src Source, etag string) (FetchResult, error) {
	res := FetchResult{}
	prev, err := s.State(kind)
	if err != nil {
		return res, err
	}
	res.State = prev
	if prev.Accepted == nil {
		etag = ""
	}
	envelope, newTag, err := src.FetchManifest(ctx, kind, etag)
	if errors.Is(err, ErrNotModified) {
		res.Unchanged, res.ETag = true, etag
		return res, nil
	}
	if err != nil {
		return res, err
	}
	v, err := content.Verify(content.VerifyInput{
		Envelope: envelope, Kind: kind, VendorKeys: tr.VendorKeys, FeedKeys: tr.FeedKeys,
		RequireOrg: tr.RequireOrg, OrgKey: tr.OrgKey, Accepted: prev.Accepted, Now: s.now(),
	})
	if err != nil {
		res.State, _ = s.InstallFiles(kind, envelope, nil, tr) // records the refusal; keeps last-known-good
		return res, err
	}
	if prev.Accepted != nil && v.Hash == prev.Accepted.ManifestHash {
		res.Unchanged, res.ETag = true, newTag
		return res, nil
	}
	if err := os.MkdirAll(s.Root, 0o700); err != nil {
		return res, fmt.Errorf("contentchan.FetchInstall: %w", err)
	}
	files := map[string]string{}
	defer func() {
		for _, p := range files {
			_ = os.Remove(p)
		}
	}()
	goos, goarch := s.platformFor(kind)
	for _, e := range v.Manifest.Entries {
		if !content.EntryApplies(e, goos, goarch) || content.IsRevoked(v.Manifest, e.SHA256) {
			continue
		}
		if e.Name == ManifestFile || e.Name == StateFile {
			continue // InstallFiles refuses the set (structure)
		}
		if p, ok := s.InstalledArtifact(kind, e); ok {
			if staged, err := stageFile(s.Root, p); err == nil {
				files[e.Name] = staged
				res.Reused++
				continue
			}
		}
		f, err := os.CreateTemp(s.Root, ".incoming-*")
		if err != nil {
			return res, fmt.Errorf("contentchan.FetchInstall: %w", err)
		}
		files[e.Name] = f.Name()
		ferr := src.FetchArtifact(ctx, kind, e, f)
		if cerr := f.Close(); ferr == nil {
			ferr = cerr
		}
		if ferr != nil {
			return res, fmt.Errorf("artifact %s: %w", e.Name, ferr)
		}
		res.Fetched++
	}
	next, err := s.InstallFiles(kind, envelope, files, tr)
	res.State = next
	if err != nil {
		return res, err
	}
	res.ETag = newTag
	return res, nil
}

// stageFile stages src under a fresh ".incoming-*" name in root: a hard
// link (no second copy of a large export), or a copy where the filesystem
// refuses the link. The caller removes the staged name.
func stageFile(root, src string) (string, error) {
	f, err := os.CreateTemp(root, ".incoming-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	if err := f.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if err := os.Link(src, name); err == nil {
		return name, nil
	}
	in, err := os.Open(src) //nolint:gosec // G304: a file of the content channel's own kind directory
	if err != nil {
		return "", err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(out, in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}
