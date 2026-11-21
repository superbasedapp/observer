package customagent

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestAdapterIsProxyOnly(t *testing.T) {
	a := New()
	if a.Name() != models.ToolCustomAgent {
		t.Fatalf("Name = %q", a.Name())
	}
	if len(a.WatchPaths()) != 0 {
		t.Fatal("custom-agent must not watch any path")
	}
	if a.IsSessionFile("/tmp/x.jsonl") {
		t.Fatal("custom-agent claims a session file")
	}
	res, err := a.ParseSessionFile(context.Background(), "/tmp/x", 42)
	if err != nil || res.NewOffset != 42 || len(res.ToolEvents) != 0 {
		t.Fatalf("ParseSessionFile = %+v, %v", res, err)
	}
}
