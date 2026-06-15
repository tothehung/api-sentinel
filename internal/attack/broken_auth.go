package attack

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/tothehung/api-sentinel/internal/httpclient"
	"github.com/tothehung/api-sentinel/internal/spec"
)

const BrokenAuthenticationID = "OWASP-API2-BROKEN-AUTHENTICATION"

type BrokenAuthenticationAttack struct {
	client *httpclient.Client
}

func NewBrokenAuthenticationAttack(client *httpclient.Client) (*BrokenAuthenticationAttack, error) {
	if client == nil {
		return nil, fmt.Errorf("http client is required")
	}

	return &BrokenAuthenticationAttack{client: client}, nil
}

func (a *BrokenAuthenticationAttack) Run(ctx context.Context, target string, endpoint spec.Endpoint) (*Finding, error) {
	if !endpoint.RequiresAuth() {
		return nil, nil
	}

	requestURL, err := endpointURL(target, endpoint)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, endpoint.Method, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create unauthenticated request: %w", err)
	}

	resp, err := a.client.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("send unauthenticated request: %w", err)
	}
	defer resp.Body.Close()

	if isAuthBypassed(resp.StatusCode) {
		return &Finding{
			ID:         BrokenAuthenticationID,
			Title:      "Authenticated endpoint accepted an unauthenticated request",
			Severity:   SeverityHigh,
			Method:     endpoint.Method,
			Path:       endpoint.Path,
			StatusCode: resp.StatusCode,
			Evidence: fmt.Sprintf(
				"%s returned HTTP %d without credentials despite declaring security requirements",
				endpoint.DisplayName(),
				resp.StatusCode,
			),
			Remediation: "Require authentication middleware on this route and return 401 or 403 before executing business logic.",
		}, nil
	}

	return nil, nil
}

func isAuthBypassed(statusCode int) bool {
	return statusCode >= 200 && statusCode < 400
}

func endpointURL(target string, endpoint spec.Endpoint) (string, error) {
	base, err := url.Parse(strings.TrimSpace(target))
	if err != nil {
		return "", fmt.Errorf("parse target url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", fmt.Errorf("target must include scheme and host")
	}

	materializedPath := materializePath(endpoint.Path, endpoint.Parameters)
	base.Path = joinURLPath(base.Path, materializedPath)

	query := base.Query()
	for _, param := range endpoint.Parameters {
		if param.In == spec.ParameterInQuery && param.Required {
			query.Set(param.Name, sampleValue(param))
		}
	}
	base.RawQuery = query.Encode()

	return base.String(), nil
}

func materializePath(path string, params []spec.Parameter) string {
	result := path
	for _, param := range params {
		if param.In != spec.ParameterInPath {
			continue
		}
		result = strings.ReplaceAll(result, "{"+param.Name+"}", url.PathEscape(sampleValue(param)))
	}

	return result
}

func joinURLPath(basePath, endpointPath string) string {
	basePath = strings.TrimRight(basePath, "/")
	endpointPath = strings.TrimLeft(endpointPath, "/")
	if basePath == "" {
		return "/" + endpointPath
	}
	if endpointPath == "" {
		return basePath
	}

	return basePath + "/" + endpointPath
}

func sampleValue(param spec.Parameter) string {
	if param.Example != nil {
		return fmt.Sprint(param.Example)
	}

	name := strings.ToLower(param.Name)
	if strings.HasSuffix(name, "id") || strings.Contains(name, "_id") || strings.Contains(name, "-id") {
		return "1"
	}

	switch param.SchemaType {
	case "integer", "number":
		return "1"
	case "boolean":
		return "true"
	default:
		return "sentinel"
	}
}
