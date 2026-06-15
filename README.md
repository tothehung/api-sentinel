# API Sentinel

API Sentinel is an API security scanner focused on OpenAPI-driven attack generation.

## Current scope

- OpenAPI 3 parser with validation.
- Internal endpoint model with method, path, parameters, and security schemes.
- Configurable worker pool.
- HTTP client with rate limiting, retry handling, timeout, and user agent.
- Auth injector for Bearer, API key, and Basic auth.
- Broken authentication probe that calls secured endpoints without credentials.
- GitHub Actions workflow for test and lint on pull requests.

## Local development

```bash
go test ./...
```

Preview scan command:

```bash
go run ./cmd/sentinel scan --spec testdata/petstore.yaml --target http://localhost:3000
```

To run the local vulnerable demo target first:

```bash
go run ./examples/vulnerable-api
```

The full Cobra CLI, additional attack modules, and HTML reporting are planned for the next milestone.
