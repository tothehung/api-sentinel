package attack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/tothehung/api-sentinel/internal/httpclient"
	"github.com/tothehung/api-sentinel/internal/spec"
)

func TestBrokenAuthenticationAttackReportsBypass(t *testing.T) {
	var pathSeen atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathSeen.Store(r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	finding := runBrokenAuth(t, server.URL, spec.Endpoint{
		Method: "GET",
		Path:   "/users/{userId}",
		Parameters: []spec.Parameter{
			{Name: "userId", In: spec.ParameterInPath, Required: true, SchemaType: "integer"},
			{Name: "includeDetails", In: spec.ParameterInQuery, Required: true, SchemaType: "boolean"},
		},
		Security: []spec.SecurityRequirement{{SchemeName: "bearerAuth"}},
	})

	if finding == nil {
		t.Fatal("finding = nil, want broken auth finding")
	}
	if finding.ID != BrokenAuthenticationID {
		t.Fatalf("finding ID = %q", finding.ID)
	}
	if got := pathSeen.Load().(string); got != "/users/1?includeDetails=true" {
		t.Fatalf("request URI = %q", got)
	}
}

func TestBrokenAuthenticationAttackIgnores401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	finding := runBrokenAuth(t, server.URL, spec.Endpoint{
		Method:   "GET",
		Path:     "/users",
		Security: []spec.SecurityRequirement{{SchemeName: "bearerAuth"}},
	})
	if finding != nil {
		t.Fatalf("finding = %#v, want nil", finding)
	}
}

func TestBrokenAuthenticationAttackSkipsPublicEndpoint(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	finding := runBrokenAuth(t, server.URL, spec.Endpoint{
		Method: "GET",
		Path:   "/health",
	})
	if finding != nil {
		t.Fatalf("finding = %#v, want nil", finding)
	}
	if atomic.LoadInt32(&requests) != 0 {
		t.Fatalf("requests = %d, want 0", requests)
	}
}

func runBrokenAuth(t *testing.T, target string, endpoint spec.Endpoint) *Finding {
	t.Helper()

	client, err := httpclient.New(httpclient.Config{})
	if err != nil {
		t.Fatalf("httpclient.New() error = %v", err)
	}
	attack, err := NewBrokenAuthenticationAttack(client)
	if err != nil {
		t.Fatalf("NewBrokenAuthenticationAttack() error = %v", err)
	}

	finding, err := attack.Run(context.Background(), target, endpoint)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	return finding
}
