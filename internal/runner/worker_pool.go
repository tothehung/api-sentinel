package runner

import (
	"context"
	"fmt"
	"sync"
)

type Job func(context.Context) error

type WorkerPool struct {
	concurrency int
}

func NewWorkerPool(concurrency int) (*WorkerPool, error) {
	if concurrency < 1 {
		return nil, fmt.Errorf("concurrency must be >= 1")
	}

	return &WorkerPool{concurrency: concurrency}, nil
}

func (p *WorkerPool) Concurrency() int {
	return p.concurrency
}

func (p *WorkerPool) Run(ctx context.Context, jobs []Job) error {
	if p == nil {
		return fmt.Errorf("worker pool is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobCh := make(chan Job)
	errCh := make(chan error, 1)
	var wg sync.WaitGroup

	for workerID := 0; workerID < p.concurrency; workerID++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobCh:
					if !ok {
						return
					}
					if job == nil {
						continue
					}
					if err := job(ctx); err != nil {
						select {
						case errCh <- err:
							cancel()
						default:
						}
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobCh)
		for _, job := range jobs {
			select {
			case <-ctx.Done():
				return
			case jobCh <- job:
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		select {
		case err := <-errCh:
			return err
		default:
			return ctx.Err()
		}
	case err := <-errCh:
		cancel()
		<-done
		return err
	case <-ctx.Done():
		<-done
		return ctx.Err()
	}
}
