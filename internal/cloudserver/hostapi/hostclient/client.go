package hostclient

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Loop defaults.
const (
	// DefaultDispatchEvery is the outbox poll interval.
	DefaultDispatchEvery = 5 * time.Second
	// DefaultReconcileEvery is the reconciliation interval (design 4.6:
	// hourly).
	DefaultReconcileEvery = time.Hour
)

// NewTickerFunc starts a ticker: its channel and its stop function.
type NewTickerFunc func(d time.Duration) (<-chan time.Time, func())

// realTicker is the default NewTickerFunc.
func realTicker(d time.Duration) (<-chan time.Time, func()) {
	t := time.NewTicker(d)
	return t.C, t.Stop
}

// Config configures a Client. Dispatcher and Reconciler are required.
type Config struct {
	Dispatcher *Dispatcher
	Reconciler *Reconciler
	// DispatchEvery is the outbox poll interval (0: DefaultDispatchEvery).
	DispatchEvery time.Duration
	// ReconcileEvery is the reconciliation interval (0:
	// DefaultReconcileEvery).
	ReconcileEvery time.Duration
	// NewTicker starts a ticker (nil: time.NewTicker).
	NewTicker NewTickerFunc
	// OnError receives every pass error (nil: dropped). It must not block.
	OnError func(error)
}

// Client runs the dispatcher and the reconciler.
type Client struct {
	cfg Config
}

// New builds a Client. It does not start anything; call Run.
func New(cfg Config) (*Client, error) {
	if cfg.Dispatcher == nil || cfg.Reconciler == nil {
		return nil, errors.New("hostclient.New: Dispatcher and Reconciler are required")
	}
	if cfg.DispatchEvery <= 0 {
		cfg.DispatchEvery = DefaultDispatchEvery
	}
	if cfg.ReconcileEvery <= 0 {
		cfg.ReconcileEvery = DefaultReconcileEvery
	}
	if cfg.NewTicker == nil {
		cfg.NewTicker = realTicker
	}
	if cfg.OnError == nil {
		cfg.OnError = func(error) {}
	}
	return &Client{cfg: cfg}, nil
}

// Run dispatches on every dispatch tick and reconciles on every reconcile
// tick, each in its own goroutine (a slow reconciliation never delays the
// outbox), until ctx ends. It returns nil after both loops stopped.
func (c *Client) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	loop := func(every time.Duration, pass func(context.Context) error) {
		defer wg.Done()
		tick, stop := c.cfg.NewTicker(every)
		defer stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick:
				if err := pass(ctx); err != nil && ctx.Err() == nil {
					c.cfg.OnError(err)
				}
			}
		}
	}
	wg.Add(2)
	go loop(c.cfg.DispatchEvery, func(ctx context.Context) error {
		_, err := c.cfg.Dispatcher.DispatchOnce(ctx)
		return err
	})
	go loop(c.cfg.ReconcileEvery, func(ctx context.Context) error {
		_, err := c.cfg.Reconciler.ReconcileOnce(ctx)
		return err
	})
	wg.Wait()
	return nil
}
