package waiter

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sync/errgroup"
)

type WaitFunc func(context.Context) error

type Waiter struct {
	ctx    context.Context
	cancel context.CancelFunc
	fns    []WaitFunc
}

func NewWaiter() *Waiter {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	ctx, cancel = signal.NotifyContext(ctx, os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	return &Waiter{
		ctx:    ctx,
		cancel: cancel,
		fns:    []WaitFunc{},
	}
}

func (w *Waiter) Add(fn WaitFunc) {
	w.fns = append(w.fns, fn)
}

func (w *Waiter) Context() context.Context {
	return w.ctx
}

func (w *Waiter) CancelFunc() context.CancelFunc {
	return w.cancel
}

func (w *Waiter) Wait() error {
	group, gCtx := errgroup.WithContext(w.ctx)

	group.Go(func() error {
		<-w.ctx.Done()
		w.cancel()
		return nil
	})

	for _, fn := range w.fns {
		fn := fn
		group.Go(func() error { return fn(gCtx) })
	}
	return group.Wait()
}
