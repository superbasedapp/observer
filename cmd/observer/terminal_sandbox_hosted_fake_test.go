//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
)

// fakeBoxClient is an in-memory vendor: boxes with files, labels and
// processes, so the host helper's lifecycle runs end to end without a key.
type fakeBoxClient struct {
	mu    sync.Mutex
	boxes map[string]*fakeBox
	n     int
	calls []string
	execs func(box *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error)
	// loseCreate makes the next create make a box and lose the answer.
	loseCreate bool
	// reattach answers Reattach (nil: not supported).
	reattach func(id, pid string) (sandboxremote.Process, error)
	// createErr makes every create fail with it, making no box.
	createErr error
	// writeFail, when set, fails one file's write with its error.
	writeFail func(path string) error
}

type fakeBox struct {
	id      string
	spec    sandboxremote.BoxSpec
	files   map[string][]byte
	deleted bool
}

func newFakeBoxClient() *fakeBoxClient { return &fakeBoxClient{boxes: map[string]*fakeBox{}} }

func (f *fakeBoxClient) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeBoxClient) Create(_ context.Context, spec sandboxremote.BoxSpec) (sandboxremote.BoxInfo, error) {
	f.record("create")
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return sandboxremote.BoxInfo{}, f.createErr
	}
	f.n++
	b := &fakeBox{id: fmt.Sprintf("box%d", f.n), spec: spec, files: map[string][]byte{}}
	f.boxes[b.id] = b
	if f.loseCreate {
		f.loseCreate = false
		return sandboxremote.BoxInfo{}, sandboxremote.ErrCreateUnknown
	}
	return sandboxremote.BoxInfo{ID: b.id, Region: spec.Region, Running: true, Labels: spec.Labels, Extra: map[string]string{"vendor_key": "v1"}, Deadline: time.Now().Add(time.Duration(spec.TimeoutSeconds) * time.Second)}, nil
}

func (f *fakeBoxClient) box(id string) (*fakeBox, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.boxes[id]
	if !ok || b.deleted {
		return nil, sandboxremote.ErrNotFound
	}
	return b, nil
}

func (f *fakeBoxClient) Get(_ context.Context, id string) (sandboxremote.BoxInfo, error) {
	f.record("get")
	b, err := f.box(id)
	if err != nil {
		return sandboxremote.BoxInfo{}, err
	}
	return sandboxremote.BoxInfo{ID: b.id, Running: true, Labels: b.spec.Labels}, nil
}

func (f *fakeBoxClient) ListByLabel(_ context.Context, key, value string) ([]sandboxremote.BoxInfo, error) {
	f.record("list")
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []sandboxremote.BoxInfo
	for _, b := range f.boxes {
		if !b.deleted && b.spec.Labels[key] == value {
			out = append(out, sandboxremote.BoxInfo{ID: b.id, Running: true, Labels: b.spec.Labels})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeBoxClient) Delete(_ context.Context, id string) error {
	f.record("delete")
	b, err := f.box(id)
	if err != nil {
		return err
	}
	f.mu.Lock()
	b.deleted = true
	f.mu.Unlock()
	return nil
}

func (f *fakeBoxClient) WriteFiles(_ context.Context, id string, files []sandboxremote.UploadFile) error {
	f.record("write")
	b, err := f.box(id)
	if err != nil {
		return err
	}
	for _, uf := range files {
		if f.writeFail != nil {
			if err := f.writeFail(uf.Path); err != nil {
				return err
			}
		}
		rc, err := uf.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
		f.mu.Lock()
		b.files[uf.Path] = data
		f.mu.Unlock()
	}
	return nil
}

func (f *fakeBoxClient) ReadFile(_ context.Context, id, p string, max int64) ([]byte, error) {
	f.record("read")
	b, err := f.box(id)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	data, ok := b.files[p]
	if !ok {
		return nil, sandboxremote.ErrNotFound
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("over cap")
	}
	return append([]byte(nil), data...), nil
}

func (f *fakeBoxClient) Exec(_ context.Context, id string, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	f.record("exec " + strings.Join(spec.Argv, " "))
	b, err := f.box(id)
	if err != nil {
		return nil, err
	}
	if len(spec.Argv) > 0 && spec.Argv[0] == "find" {
		var lines []string
		f.mu.Lock()
		for p, data := range b.files {
			for _, root := range spec.Argv[1:] {
				if strings.HasPrefix(root, "-") {
					break
				}
				if strings.HasPrefix(p, path.Clean(root)+"/") {
					lines = append(lines, fmt.Sprintf("%s\t%d", p, len(data)))
				}
			}
		}
		f.mu.Unlock()
		sort.Strings(lines)
		return newFakeProcess(strings.Join(lines, "\n")+"\n", 0), nil
	}
	if f.execs != nil {
		return f.execs(b, spec)
	}
	return newFakeProcess("", 0), nil
}

func (f *fakeBoxClient) Reattach(_ context.Context, id, pid string) (sandboxremote.Process, error) {
	if f.reattach == nil {
		return nil, sandboxremote.ErrNotSupported
	}
	return f.reattach(id, pid)
}

// fakeProcess is a process whose output is fixed.
type fakeProcess struct {
	r    io.Reader
	code int
}

func newFakeProcess(out string, code int) *fakeProcess {
	return &fakeProcess{r: strings.NewReader(out), code: code}
}

func (p *fakeProcess) Read(b []byte) (int, error)                   { return p.r.Read(b) }
func (p *fakeProcess) Write(b []byte) (int, error)                  { return len(b), nil }
func (p *fakeProcess) PID() string                                  { return "1" }
func (p *fakeProcess) Resize(context.Context, uint16, uint16) error { return nil }
func (p *fakeProcess) Wait(context.Context) (int, error)            { return p.code, nil }
func (p *fakeProcess) Kill(context.Context) error                   { return nil }
func (p *fakeProcess) Close() error                                 { return nil }
