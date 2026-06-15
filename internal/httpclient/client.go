package httpclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

var ErrBodyNotReplayable = errors.New("request body is not replayable; set GetBody or disable retries")

type Config struct {
	Timeout            time.Duration
	RateLimitPerSecond float64
	MaxRetries         int
	RetryWait          time.Duration
	UserAgent          string
	Transport          http.RoundTripper
}

type Client struct {
	httpClient *http.Client
	limiter    *rate.Limiter
	maxRetries int
	retryWait  time.Duration
	userAgent  string
}

func New(config Config) (*Client, error) {
	if config.RateLimitPerSecond < 0 {
		return nil, fmt.Errorf("rate limit must be >= 0")
	}
	if config.MaxRetries < 0 {
		return nil, fmt.Errorf("max retries must be >= 0")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	retryWait := config.RetryWait
	if retryWait == 0 {
		retryWait = 250 * time.Millisecond
	}

	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	var limiter *rate.Limiter
	if config.RateLimitPerSecond > 0 {
		limiter = rate.NewLimiter(rate.Limit(config.RateLimitPerSecond), 1)
	}

	userAgent := config.UserAgent
	if userAgent == "" {
		userAgent = "api-sentinel/0.1"
	}

	return &Client{
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		limiter:    limiter,
		maxRetries: config.MaxRetries,
		retryWait:  retryWait,
		userAgent:  userAgent,
	}, nil
}

func (c *Client) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if c == nil {
		return nil, fmt.Errorf("client is nil")
	}
	if req == nil {
		return nil, fmt.Errorf("request is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil && c.maxRetries > 0 {
		return nil, ErrBodyNotReplayable
	}

	attempts := c.maxRetries + 1
	var lastErr error

	for attempt := 0; attempt < attempts; attempt++ {
		if c.limiter != nil {
			if err := c.limiter.Wait(ctx); err != nil {
				return nil, fmt.Errorf("wait for rate limiter: %w", err)
			}
		}

		cloned, err := cloneRequest(ctx, req)
		if err != nil {
			return nil, err
		}
		if cloned.Header.Get("User-Agent") == "" {
			cloned.Header.Set("User-Agent", c.userAgent)
		}

		resp, err := c.httpClient.Do(cloned)
		if !shouldRetry(resp, err) || attempt == attempts-1 {
			return resp, err
		}

		lastErr = err
		closeResponse(resp)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.retryWait):
		}
	}

	return nil, lastErr
}

func cloneRequest(ctx context.Context, req *http.Request) (*http.Request, error) {
	cloned := req.Clone(ctx)
	if req.Body == nil || req.Body == http.NoBody {
		return cloned, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, fmt.Errorf("reset request body: %w", err)
	}
	cloned.Body = body

	return cloned, nil
}

func shouldRetry(resp *http.Response, err error) bool {
	if err != nil {
		return true
	}
	if resp == nil {
		return false
	}

	return resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError
}

func closeResponse(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}

	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}
