package runner

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func TestWorkerPoolRunsWithConfiguredConcurrency(t *testing.T) {
	pool, err := NewWorkerPool(3)
	if err != nil {
		t.Fatalf("NewWorkerPool() error = %v", err)
	}

	var running int32
	var maxRunning int32
	var completed int32
	jobs := make([]Job, 12)
	for i := range jobs {
		jobs[i] = func(ctx context.Context) error {
			current := atomic.AddInt32(&running, 1)
			for {
				maxSeen := atomic.LoadInt32(&maxRunning)
				if current <= maxSeen || atomic.CompareAndSwapInt32(&maxRunning, maxSeen, current) {
					break
				}
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Millisecond):
			}

			atomic.AddInt32(&running, -1)
			atomic.AddInt32(&completed, 1)
			return nil
		}
	}

	if err := pool.Run(context.Background(), jobs); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if completed != int32(len(jobs)) {
		t.Fatalf("completed = %d, want %d", completed, len(jobs))
	}
	if maxRunning > 3 {
		t.Fatalf("max running = %d, want <= 3", maxRunning)
	}
}

func TestWorkerPoolCancelsOnFirstError(t *testing.T) {
	pool, err := NewWorkerPool(2)
	if err != nil {
		t.Fatalf("NewWorkerPool() error = %v", err)
	}

	wantErr := fmt.Errorf("boom")
	err = pool.Run(context.Background(), []Job{
		func(context.Context) error { return wantErr },
		func(ctx context.Context) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})

	if err != wantErr {
		t.Fatalf("Run() error = %v, want %v", err, wantErr)
	}
}
