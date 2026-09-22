# Serafort Go SDK (`github.com/Serafort/serafort-go-sdk`)

Official Go client library for the Serafort identity platform. High-performance, concurrency-safe Machine Identity (M2M) caching and local B2B JWT validation with zero runtime dependencies.

## Installation

```bash
go get github.com/Serafort/serafort-go-sdk
```

## Quickstart

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/Serafort/serafort-go-sdk"
)

func main() {
	client := serafort.NewClient(serafort.Config{
		Endpoint:     "https://auth.acme.com",
		ClientID:     "my-client-id",
		ClientSecret: "my-client-secret",
	})

	ctx := context.Background()

	// 1. Machine-to-Machine Token Retrieval (Cached, proactive 5-min refresh)
	token, err := client.GetAccessToken(ctx, []string{"read:users"})
	if err != nil {
		log.Fatalf("failed to get access token: %v", err)
	}
	fmt.Printf("M2M Token: %s\n", token)

	// 2. Local JWT Validation
	user, err := client.ValidateToken(ctx, token)
	if err != nil {
		log.Fatalf("token validation failed: %v", err)
	}

	fmt.Printf("User: %s (Tenant: %s)\n", user.UserID, user.TenantID)

	// 3. RBAC Checks (wildcards supported)
	if client.HasPermission(user, "org:write") {
		fmt.Println("Access granted!")
	}
}
```

## Contributing

### Requirements

- Go 1.22+
- No external dependencies — the module relies solely on the standard library.

### Git hooks

This repo ships a portable pre-commit hook under `.githooks/pre-commit` that runs `gofmt -l .`, `go vet ./...`, and `go test ./...` before every commit. It is **not** installed automatically — enable it once per clone with:

```bash
git config core.hooksPath .githooks
```

There is no Husky setup here: Husky is an npm-ecosystem tool that hooks into `package.json`/`node_modules`, and this is a pure Go module with no Node.js tooling involved. A plain POSIX shell script wired through `core.hooksPath` is the idiomatic equivalent for a Go repo and keeps the module dependency-free.

### CI

Every push and pull request against `main` runs `go vet`, `go build`, `go test -race`, and `golangci-lint` via GitHub Actions (`.github/workflows/ci.yml`).
