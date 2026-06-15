package spec

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

type OpenAPIParser struct {
	loader *openapi3.Loader
}

func NewOpenAPIParser() *OpenAPIParser {
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true

	return &OpenAPIParser{loader: loader}
}

func (p *OpenAPIParser) Load(ctx context.Context, path string) (*Document, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("openapi spec path is required")
	}

	loader := p.loader
	if loader == nil {
		loader = openapi3.NewLoader()
		loader.IsExternalRefsAllowed = true
	}

	raw, err := loader.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("load openapi spec: %w", err)
	}

	if err := raw.Validate(ctx); err != nil {
		return nil, fmt.Errorf("validate openapi spec: %w", err)
	}

	securitySchemes := extractSecuritySchemes(raw)
	endpoints := extractEndpoints(raw, securitySchemes)

	return &Document{
		Title:           raw.Info.Title,
		Version:         raw.Info.Version,
		Endpoints:       endpoints,
		SecuritySchemes: securitySchemes,
	}, nil
}

func extractEndpoints(raw *openapi3.T, securitySchemes map[string]SecurityScheme) []Endpoint {
	if raw.Paths == nil {
		return nil
	}

	endpoints := make([]Endpoint, 0, raw.Paths.Len())
	for _, path := range raw.Paths.InMatchingOrder() {
		pathItem := raw.Paths.Value(path)
		if pathItem == nil {
			continue
		}

		pathParams := convertParameters(pathItem.Parameters)
		for _, method := range orderedHTTPMethods() {
			operation := pathItem.GetOperation(method)
			if operation == nil {
				continue
			}

			params := mergeParameters(pathParams, convertParameters(operation.Parameters))
			security := resolveSecurityRequirements(raw.Security, operation.Security)

			endpoints = append(endpoints, Endpoint{
				Method:          strings.ToUpper(method),
				Path:            path,
				OperationID:     operation.OperationID,
				Summary:         operation.Summary,
				Parameters:      params,
				Security:        security,
				SecuritySchemes: schemesForRequirements(security, securitySchemes),
			})
		}
	}

	return endpoints
}

func orderedHTTPMethods() []string {
	return []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
}

func convertParameters(params openapi3.Parameters) []Parameter {
	converted := make([]Parameter, 0, len(params))
	for _, ref := range params {
		if ref == nil || ref.Value == nil {
			continue
		}

		param := ref.Value
		converted = append(converted, Parameter{
			Name:        param.Name,
			In:          ParameterLocation(param.In),
			Required:    param.Required,
			SchemaType:  schemaType(param.Schema),
			Format:      schemaFormat(param.Schema),
			Description: param.Description,
			Example:     parameterExample(param),
		})
	}

	return converted
}

func mergeParameters(pathParams, operationParams []Parameter) []Parameter {
	merged := make([]Parameter, 0, len(pathParams)+len(operationParams))
	indexByKey := make(map[string]int, len(pathParams)+len(operationParams))

	for _, param := range slices.Concat(pathParams, operationParams) {
		key := string(param.In) + ":" + param.Name
		if existing, ok := indexByKey[key]; ok {
			merged[existing] = param
			continue
		}

		indexByKey[key] = len(merged)
		merged = append(merged, param)
	}

	return merged
}

func schemaType(ref *openapi3.SchemaRef) string {
	if ref == nil || ref.Value == nil || ref.Value.Type == nil || ref.Value.Type.IsEmpty() {
		return ""
	}

	types := ref.Value.Type.Slice()
	if len(types) == 0 {
		return ""
	}

	return types[0]
}

func schemaFormat(ref *openapi3.SchemaRef) string {
	if ref == nil || ref.Value == nil {
		return ""
	}

	return ref.Value.Format
}

func parameterExample(param *openapi3.Parameter) any {
	if param.Example != nil {
		return param.Example
	}

	if param.Schema != nil && param.Schema.Value != nil {
		if param.Schema.Value.Example != nil {
			return param.Schema.Value.Example
		}

		if param.Schema.Value.Default != nil {
			return param.Schema.Value.Default
		}
	}

	return nil
}

func resolveSecurityRequirements(root openapi3.SecurityRequirements, operation *openapi3.SecurityRequirements) []SecurityRequirement {
	requirements := root
	if operation != nil {
		requirements = *operation
	}

	resolved := make([]SecurityRequirement, 0, len(requirements))
	for _, requirement := range requirements {
		if len(requirement) == 0 {
			continue
		}

		for name, scopes := range requirement {
			resolved = append(resolved, SecurityRequirement{
				SchemeName: name,
				Scopes:     slices.Clone(scopes),
			})
		}
	}

	return resolved
}

func extractSecuritySchemes(raw *openapi3.T) map[string]SecurityScheme {
	if raw.Components == nil || raw.Components.SecuritySchemes == nil {
		return nil
	}

	schemes := make(map[string]SecurityScheme, len(raw.Components.SecuritySchemes))
	for name, ref := range raw.Components.SecuritySchemes {
		if ref == nil || ref.Value == nil {
			continue
		}

		value := ref.Value
		schemes[name] = SecurityScheme{
			Name:         name,
			Type:         value.Type,
			In:           value.In,
			Scheme:       value.Scheme,
			BearerFormat: value.BearerFormat,
		}
	}

	return schemes
}

func schemesForRequirements(requirements []SecurityRequirement, schemes map[string]SecurityScheme) map[string]SecurityScheme {
	if len(requirements) == 0 || len(schemes) == 0 {
		return nil
	}

	selected := make(map[string]SecurityScheme, len(requirements))
	for _, requirement := range requirements {
		if scheme, ok := schemes[requirement.SchemeName]; ok {
			selected[requirement.SchemeName] = scheme
		}
	}

	return selected
}
