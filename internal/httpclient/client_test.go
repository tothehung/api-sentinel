package httpclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientRetriesServerErrors(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(Config{MaxRetries: 2, RetryWait: time.Millisecond})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestClientRejectsRetryWithNonReplayableBody(t *testing.T) {
	client, err := New(Config{MaxRetries: 1})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "https://example.test", io.NopCloser(bytes.NewBufferString("payload")))
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	_, err = client.Do(context.Background(), req)
	if !errors.Is(err, ErrBodyNotReplayable) {
		t.Fatalf("Do() error = %v, want ErrBodyNotReplayable", err)
	}
}

func TestClientSetsUserAgent(t *testing.T) {
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.UserAgent()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, err := New(Config{UserAgent: "api-sentinel-test"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	resp, err := client.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if got := <-seen; got != "api-sentinel-test" {
		t.Fatalf("User-Agent = %q", got)
	}
}
