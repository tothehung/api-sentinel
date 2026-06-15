package spec

import "strings"

type ParameterLocation string

const (
	ParameterInPath   ParameterLocation = "path"
	ParameterInQuery  ParameterLocation = "query"
	ParameterInHeader ParameterLocation = "header"
	ParameterInCookie ParameterLocation = "cookie"
)

type Parameter struct {
	Name        string
	In          ParameterLocation
	Required    bool
	SchemaType  string
	Format      string
	Description string
	Example     any
}

type SecurityRequirement struct {
	SchemeName string
	Scopes     []string
}

type SecurityScheme struct {
	Name         string
	Type         string
	In           string
	Scheme       string
	BearerFormat string
}

type Endpoint struct {
	Method          string
	Path            string
	OperationID     string
	Summary         string
	Parameters      []Parameter
	Security        []SecurityRequirement
	SecuritySchemes map[string]SecurityScheme
}

func (e Endpoint) RequiresAuth() bool {
	return len(e.Security) > 0
}

func (e Endpoint) ParameterByName(name string, in ParameterLocation) (Parameter, bool) {
	for _, param := range e.Parameters {
		if param.Name == name && param.In == in {
			return param, true
		}
	}

	return Parameter{}, false
}

func (e Endpoint) DisplayName() string {
	return strings.ToUpper(e.Method) + " " + e.Path
}

type Document struct {
	Title           string
	Version         string
	Endpoints       []Endpoint
	SecuritySchemes map[string]SecurityScheme
}
