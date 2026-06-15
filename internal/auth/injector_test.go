package auth

import (
	"net/http"
	"testing"
)

func TestInjectorApplyBearerAndAPIKeys(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/users", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	injector := Injector{
		BearerToken: "token-123",
		APIKeys: []APIKeyCredential{
			{Name: "X-API-Key", Value: "header-key", Location: APIKeyInHeader},
			{Name: "api_key", Value: "query-key", Location: APIKeyInQuery},
			{Name: "session", Value: "cookie-key", Location: APIKeyInCookie},
		},
	}

	if err := injector.Apply(req); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer token-123" {
		t.Fatalf("Authorization = %q", got)
	}
	if got := req.Header.Get("X-API-Key"); got != "header-key" {
		t.Fatalf("X-API-Key = %q", got)
	}
	if got := req.URL.Query().Get("api_key"); got != "query-key" {
		t.Fatalf("api_key query = %q", got)
	}
	if got := req.Cookies()[0].Value; got != "cookie-key" {
		t.Fatalf("cookie value = %q", got)
	}
}

func TestInjectorApplyBasicAuth(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "https://example.test/users", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}

	injector := Injector{
		Basic: &BasicCredential{Username: "admin", Password: "secret"},
	}

	if err := injector.Apply(req); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		t.Fatal("BasicAuth() ok = false")
	}
	if username != "admin" || password != "secret" {
		t.Fatalf("BasicAuth() = %q/%q", username, password)
	}
}
