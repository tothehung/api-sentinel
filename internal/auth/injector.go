package auth

import (
	"fmt"
	"net/http"
)

type APIKeyLocation string

const (
	APIKeyInHeader APIKeyLocation = "header"
	APIKeyInQuery  APIKeyLocation = "query"
	APIKeyInCookie APIKeyLocation = "cookie"
)

type APIKeyCredential struct {
	Name     string
	Value    string
	Location APIKeyLocation
}

type BasicCredential struct {
	Username string
	Password string
}

type Injector struct {
	BearerToken string
	APIKeys     []APIKeyCredential
	Basic       *BasicCredential
}

func (i Injector) Apply(req *http.Request) error {
	if req == nil {
		return fmt.Errorf("request is nil")
	}

	if i.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+i.BearerToken)
	}

	if i.Basic != nil {
		req.SetBasicAuth(i.Basic.Username, i.Basic.Password)
	}

	for _, key := range i.APIKeys {
		if err := applyAPIKey(req, key); err != nil {
			return err
		}
	}

	return nil
}

func applyAPIKey(req *http.Request, key APIKeyCredential) error {
	if key.Name == "" {
		return fmt.Errorf("api key name is required")
	}

	switch key.Location {
	case APIKeyInHeader, "":
		req.Header.Set(key.Name, key.Value)
	case APIKeyInQuery:
		query := req.URL.Query()
		query.Set(key.Name, key.Value)
		req.URL.RawQuery = query.Encode()
	case APIKeyInCookie:
		req.AddCookie(&http.Cookie{Name: key.Name, Value: key.Value})
	default:
		return fmt.Errorf("unsupported api key location %q", key.Location)
	}

	return nil
}
