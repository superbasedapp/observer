package superbased

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
)

var (
	loggerMu sync.RWMutex
	logger   *slog.Logger
)

// SetLogger sets where the SDK writes its few log lines (warnings: a degraded
// destination, an admit() that got no decision, export failures once a
// minute; info: discovery notes). nil restores slog.Default().
func SetLogger(l *slog.Logger) {
	loggerMu.Lock()
	logger = l
	loggerMu.Unlock()
}

func logf(level slog.Level, format string, args ...any) {
	loggerMu.RLock()
	l := logger
	loggerMu.RUnlock()
	if l == nil {
		l = slog.Default()
	}
	l.Log(context.Background(), level, "superbased: "+fmt.Sprintf(format, args...))
}
