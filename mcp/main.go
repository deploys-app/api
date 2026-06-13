// Command deploys-mcp is a local stdio MCP server that exposes the deploys.app
// API to Claude. It wraps the official Go client (github.com/deploys-app/api/client)
// and surfaces the full API surface through a search+execute tool pair, so the
// ~88 actions never flood the model's context window.
//
// Auth: a deploys.app service account authenticates with HTTP Basic auth, where
// the username is the service-account email and the password is a key secret.
// Provide them via DEPLOYS_SA_EMAIL + DEPLOYS_SA_SECRET, or as a single
// DEPLOYS_API_KEY="<email>:<secret>". Override the API endpoint with
// DEPLOYS_ENDPOINT (defaults to https://api.deploys.app/).
package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/deploys-app/api/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("deploys-mcp: ")

	// Remote HTTP (OAuth-protected) mode: when a listen address is set, run as a
	// remote MCP resource server that authenticates each caller with a deploys.app
	// OAuth bearer token (validated via auth's /introspect) instead of a single
	// service account. See http.go.
	if addr := os.Getenv("DEPLOYS_MCP_HTTP_ADDR"); addr != "" {
		if err := runHTTP(addr); err != nil {
			log.Fatalf("http server error: %v", err)
		}
		return
	}

	// Local stdio mode: authenticate to the API with a single service account.
	email, secret := serviceAccountCreds()
	if email == "" || secret == "" {
		log.Fatal(`missing credentials: set DEPLOYS_SA_EMAIL and DEPLOYS_SA_SECRET, or DEPLOYS_API_KEY="<email>:<secret>"`)
	}

	c := &client.Client{
		Endpoint: os.Getenv("DEPLOYS_ENDPOINT"), // empty -> client default
		Auth: func(r *http.Request) {
			r.SetBasicAuth(email, secret)
		},
	}

	server := newMCPServer()
	registerTools(server, buildCatalog(c))

	err := server.Run(context.Background(), &mcp.StdioTransport{})
	if err != nil && !isCleanShutdown(err) {
		log.Fatalf("server error: %v", err)
	}
}

// newMCPServer constructs the MCP server advertising the deploys.app identity.
// The tool set is identical across the stdio and HTTP transports.
func newMCPServer() *mcp.Server {
	return mcp.NewServer(&mcp.Implementation{
		Name:    "deploys-app",
		Version: "0.1.0",
	}, nil)
}

// serviceAccountCreds resolves the Basic-auth username (service-account email)
// and password (key secret) from the environment. DEPLOYS_SA_EMAIL/SECRET take
// precedence; otherwise DEPLOYS_API_KEY is parsed as "<email>:<secret>".
func serviceAccountCreds() (email, secret string) {
	email = strings.TrimSpace(os.Getenv("DEPLOYS_SA_EMAIL"))
	secret = os.Getenv("DEPLOYS_SA_SECRET")
	if email != "" && secret != "" {
		return email, secret
	}
	if raw := strings.TrimSpace(os.Getenv("DEPLOYS_API_KEY")); raw != "" {
		if u, s, ok := strings.Cut(raw, ":"); ok {
			return strings.TrimSpace(u), s
		}
	}
	return email, secret
}

// isCleanShutdown reports whether err is the normal way a host stops a stdio
// server: it closes stdin (EOF) or cancels the context. The SDK surfaces a
// closed stdin as its internal "server is closing: EOF" error, which is not
// importable and does not unwrap to io.EOF, so we also match it by message.
func isCleanShutdown(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "server is closing") || strings.HasSuffix(msg, "EOF")
}
