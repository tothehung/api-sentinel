package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/yourusername/api-sentinel/internal/attack"
	"github.com/yourusername/api-sentinel/internal/httpclient"
	"github.com/yourusername/api-sentinel/internal/runner"
	"github.com/yourusername/api-sentinel/internal/spec"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "scan":
		os.Exit(runScan(os.Args[2:]))
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func runScan(args []string) int {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	specPath := flags.String("spec", "", "OpenAPI 3 spec path")
	target := flags.String("target", "", "Target base URL")
	concurrency := flags.Int("concurrency", 5, "Concurrent workers")
	rps := flags.Float64("rate", 5, "Maximum requests per second")

	if err := flags.Parse(args); err != nil {
		return 2
	}
	if *specPath == "" || *target == "" {
		fmt.Fprintln(os.Stderr, "--spec and --target are required")
		return 2
	}

	ctx := context.Background()
	parser := spec.NewOpenAPIParser()
	doc, err := parser.Load(ctx, *specPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load spec: %v\n", err)
		return 1
	}

	client, err := httpclient.New(httpclient.Config{
		Timeout:            15 * time.Second,
		RateLimitPerSecond: *rps,
		MaxRetries:         2,
		RetryWait:          200 * time.Millisecond,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "create http client: %v\n", err)
		return 1
	}

	brokenAuth, err := attack.NewBrokenAuthenticationAttack(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create attack: %v\n", err)
		return 1
	}

	pool, err := runner.NewWorkerPool(*concurrency)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create worker pool: %v\n", err)
		return 1
	}

	findings := make(chan attack.Finding, len(doc.Endpoints))
	jobs := make([]runner.Job, 0, len(doc.Endpoints))
	for _, endpoint := range doc.Endpoints {
		endpoint := endpoint
		jobs = append(jobs, func(ctx context.Context) error {
			finding, err := brokenAuth.Run(ctx, *target, endpoint)
			if err != nil {
				return fmt.Errorf("%s: %w", endpoint.DisplayName(), err)
			}
			if finding != nil {
				findings <- *finding
			}
			return nil
		})
	}

	if err := pool.Run(ctx, jobs); err != nil {
		fmt.Fprintf(os.Stderr, "scan failed: %v\n", err)
		return 1
	}
	close(findings)

	count := 0
	for finding := range findings {
		count++
		fmt.Printf("[%s] %s %s: %s (status=%d)\n",
			finding.Severity,
			finding.Method,
			finding.Path,
			finding.Title,
			finding.StatusCode,
		)
	}
	fmt.Printf("Scanned %d endpoints. Findings: %d\n", len(doc.Endpoints), count)

	return 0
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  sentinel scan --spec petstore.yaml --target http://localhost:3000")
	fmt.Fprintln(os.Stderr, "  sentinel version")
}
