package waiter

import (
	"context"

	"golang.org/x/sync/errgroup"
)

type waiterFunc func(context.Context) error

type Waiter struct {
	ctx   context.Context
	group *errgroup.Group
	Fns   []waiterFunc
}

func NewWaiter(ctx context.Context) *Waiter {
	wGroup, wCtx := errgroup.WithContext(ctx)
	return &Waiter{
		ctx:   wCtx,
		group: wGroup,
	}
}

func (w *Waiter) Add(fn waiterFunc) {
	w.Fns = append(w.Fns, fn)
}

func (w *Waiter) Context() context.Context {
	return w.ctx
}

func (w *Waiter) Wait() error {
	for _, fn := range(w.Fns) {
		f := func() error {
			return fn(w.ctx)
		}
		w.group.Go(f)
	}
	return w.group.Wait()
}