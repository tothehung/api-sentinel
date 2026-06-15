package spec

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOpenAPIParserLoadExtractsEndpoints(t *testing.T) {
	parser := NewOpenAPIParser()

	doc, err := parser.Load(context.Background(), filepath.Join("..", "..", "testdata", "petstore.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if doc.Title != "API Sentinel Test API" {
		t.Fatalf("Title = %q", doc.Title)
	}
	if len(doc.Endpoints) != 3 {
		t.Fatalf("endpoint count = %d, want 3", len(doc.Endpoints))
	}

	pet := findEndpoint(t, doc.Endpoints, "GET", "/pets/{petId}")
	if !pet.RequiresAuth() {
		t.Fatal("pet endpoint should inherit root security")
	}
	if _, ok := pet.SecuritySchemes["bearerAuth"]; !ok {
		t.Fatal("pet endpoint should include bearerAuth scheme")
	}
	if _, ok := pet.ParameterByName("petId", ParameterInPath); !ok {
		t.Fatal("pet endpoint should include path parameter")
	}
	queryParam, ok := pet.ParameterByName("includeDetails", ParameterInQuery)
	if !ok {
		t.Fatal("pet endpoint should include query parameter")
	}
	if queryParam.SchemaType != "boolean" {
		t.Fatalf("query param schema type = %q, want boolean", queryParam.SchemaType)
	}

	admin := findEndpoint(t, doc.Endpoints, "POST", "/admin/users")
	if len(admin.Security) != 1 || admin.Security[0].SchemeName != "apiKeyAuth" {
		t.Fatalf("admin security = %#v, want apiKeyAuth", admin.Security)
	}

	health := findEndpoint(t, doc.Endpoints, "GET", "/health")
	if health.RequiresAuth() {
		t.Fatal("health endpoint should explicitly disable security")
	}
}

func findEndpoint(t *testing.T, endpoints []Endpoint, method, path string) Endpoint {
	t.Helper()

	for _, endpoint := range endpoints {
		if endpoint.Method == method && endpoint.Path == path {
			return endpoint
		}
	}

	t.Fatalf("endpoint %s %s not found", method, path)
	return Endpoint{}
}
