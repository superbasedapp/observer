package watcher

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

type budgetDropAdapter struct{ *budgetFakeAdapter }

func (a budgetDropAdapter) ParseSessionFile(ctx context.Context, path string, offset int64) (adapter.ParseResult, error) {
	res, err := a.budgetFakeAdapter.ParseSessionFile(ctx, path, offset)
	if strings.HasPrefix(filepath.Base(path), "bad") {
		res.TokenEvents[0].SessionID = ""
	}
	return res, err
}

func TestReconcileBudgetCaptureRejectsDroppedBatchUsage(t *testing.T) {
	t.Parallel()
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprintf("partial=%v", partial), func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "bad.session"), []byte("source"), 0o600); err != nil {
				t.Fatal(err)
			}
			if partial {
				if err := os.WriteFile(filepath.Join(root, "good.session"), []byte("source"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			w, _ := newBudgetCaptureTestWatcher(t, Options{}, budgetDropAdapter{&budgetFakeAdapter{name: "fake", root: root}})
			got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
			if got.Ready || got.Reason != BudgetCaptureReasonParseError || !strings.Contains(got.Detail, "accounting is incomplete") {
				t.Fatalf("dropped usage reported healthy: %+v", got)
			}
		})
	}
}

func TestReconcileBudgetCaptureFlushesLastBatchWithoutDuplicatingUsage(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	count := budgetCaptureBatchFiles + 3
	for i := 0; i < count; i++ {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d.session", i)), []byte("source"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	w, st := newBudgetCaptureTestWatcher(t, Options{}, &budgetFakeAdapter{name: "fake", root: root})
	for pass := 0; pass < 2; pass++ {
		got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
		if !got.Ready || got.FilesProcessed != count {
			t.Fatalf("pass %d: %+v", pass, got)
		}
		start := time.Now().UTC().Add(-time.Hour)
		tokens, err := st.GuardBudgetTokens(context.Background(), "fake-session", start, start, start)
		if err != nil || tokens.DailyTokens != int64(2*count) {
			t.Fatalf("batch usage=%+v err=%v", tokens, err)
		}
	}
}

func BenchmarkReconcileBudgetCaptureHistory(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprintf("files_%d", count), func(b *testing.B) {
			root := b.TempDir()
			for i := 0; i < count; i++ {
				if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%04d.session", i)), []byte("source"), 0o600); err != nil {
					b.Fatal(err)
				}
			}
			w, _ := newBudgetCaptureTestWatcher(b, Options{}, &budgetFakeAdapter{name: "fake", root: root})
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				got := w.ReconcileBudgetCapture(context.Background(), []string{"fake"})["fake"]
				if !got.Ready || got.FilesProcessed != count {
					b.Fatalf("history capture: %+v", got)
				}
			}
		})
	}
}
