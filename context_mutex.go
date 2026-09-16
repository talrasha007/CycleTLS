package cycletls

import (
	"context"
	"sync"
)

// contextMutex allows canceled requests to stop waiting behind a slow dial.
// Like sync.Mutex, its zero value is ready to use and it must not be copied.
type contextMutex struct {
	once sync.Once
	gate chan struct{}
}

func (m *contextMutex) LockContext(ctx context.Context) error {
	m.once.Do(func() { m.gate = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *contextMutex) Lock() { _ = m.LockContext(context.Background()) }

func (m *contextMutex) Unlock() { <-m.gate }
