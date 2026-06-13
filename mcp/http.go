package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/deploys-app/api/client"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

// protectedResourcePath is where this server publishes its OAuth 2.0 Protected
// Resource Metadata (RFC 9728). The same URL is advertised in the
// WWW-Authenticate challenge so a client can discover the authorization server.
const protectedResourcePath = "/.well-known/oauth-protected-resource"

// tokenInfoAccessTokenKey is the auth.TokenInfo.Extra key under which the
// verifier stashes the caller's raw bearer token for upstream forwarding.
const tokenInfoAccessTokenKey = "access_token"

// httpConfig configures the remote HTTP (OAuth-protected) mode.
type httpConfig struct {
	addr               string // listen address, e.g. ":8080"
	baseURL            string // public base URL of THIS MCP server (resource id)
	authURL            string // deploys.app auth server base URL
	introspectionToken string // shared secret guarding auth's /introspect
	apiEndpoint        string // upstream deploys.app API base URL ("" -> client default)
}

// runHTTP starts the OAuth-protected MCP resource server on addr.
func runHTTP(addr string) error {
	cfg, err := httpConfigFromEnv(addr)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           newHTTPHandler(cfg),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("listening on %s (resource=%s, auth=%s)", cfg.addr, cfg.baseURL, cfg.authURL)
	return srv.ListenAndServe()
}

// httpConfigFromEnv reads the HTTP-mode configuration from the environment.
func httpConfigFromEnv(addr string) (httpConfig, error) {
	cfg := httpConfig{
		addr:               addr,
		baseURL:            strings.TrimRight(os.Getenv("DEPLOYS_MCP_BASE_URL"), "/"),
		authURL:            strings.TrimRight(os.Getenv("DEPLOYS_AUTH_URL"), "/"),
		introspectionToken: os.Getenv("INTROSPECTION_TOKEN"),
		apiEndpoint:        os.Getenv("DEPLOYS_ENDPOINT"),
	}
	switch {
	case cfg.baseURL == "":
		return cfg, errors.New("missing DEPLOYS_MCP_BASE_URL")
	case cfg.authURL == "":
		return cfg, errors.New("missing DEPLOYS_AUTH_URL")
	case cfg.introspectionToken == "":
		return cfg, errors.New("missing INTROSPECTION_TOKEN")
	}
	return cfg, nil
}

// newHTTPHandler builds the full HTTP handler: public protected-resource
// metadata, a health check, and the bearer-gated MCP endpoint. The MCP endpoint
// runs the same search+execute tools as stdio mode, but forwards each caller's
// validated token to the upstream API so they act as themselves.
func newHTTPHandler(cfg httpConfig) http.Handler {
	c := &client.Client{
		Endpoint: cfg.apiEndpoint, // empty -> client default
		Auth:     forwardBearerToken,
	}
	server := newMCPServer()
	registerTools(server, buildCatalog(c))

	// Stateless: each HTTP request is authenticated and handled independently,
	// so the per-request token reaches the tool handlers (and thus the upstream
	// client) via the request context. A stateful session would pin identity to
	// the first request, which is wrong for a multi-user resource server.
	streamable := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return server },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)

	metadataURL := cfg.baseURL + protectedResourcePath
	protected := auth.RequireBearerToken(
		introspectVerifier(cfg.authURL, cfg.introspectionToken),
		&auth.RequireBearerTokenOptions{ResourceMetadataURL: metadataURL},
	)(streamable)

	metadata := &oauthex.ProtectedResourceMetadata{
		Resource:               cfg.baseURL,
		AuthorizationServers:   []string{cfg.authURL},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           "deploys.app",
	}

	mux := http.NewServeMux()
	mux.Handle(protectedResourcePath, auth.ProtectedResourceMetadataHandler(metadata))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/", protected)
	return mux
}

// forwardBearerToken copies the caller's validated bearer token (stashed in the
// request context by introspectVerifier) onto the upstream API request, so the
// deploys.app API authorizes the call as that user. The api client invokes this
// with a request whose context is the originating tool-call context.
func forwardBearerToken(r *http.Request) {
	ti := auth.TokenInfoFromContext(r.Context())
	if ti == nil {
		return
	}
	if tok, ok := ti.Extra[tokenInfoAccessTokenKey].(string); ok && tok != "" {
		r.Header.Set("Authorization", "Bearer "+tok)
	}
}

// introspectVerifier validates an incoming bearer token against the deploys
// auth server's RFC 7662 introspection endpoint. The raw token is preserved in
// TokenInfo.Extra so forwardBearerToken can relay it upstream.
func introspectVerifier(authURL, introspectionToken string) auth.TokenVerifier {
	endpoint := authURL + "/introspect"
	return func(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		form := url.Values{}
		form.Set("token", token)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", "Bearer "+introspectionToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		defer io.Copy(io.Discard, resp.Body)

		if resp.StatusCode != http.StatusOK {
			// Transient/config failure (auth down, wrong introspection token):
			// surface as a 500, not an auth challenge.
			return nil, fmt.Errorf("introspect: unexpected status %d", resp.StatusCode)
		}

		var body struct {
			Active bool   `json:"active"`
			Sub    string `json:"sub"`
			Exp    int64  `json:"exp"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
			return nil, err
		}
		if !body.Active {
			return nil, fmt.Errorf("%w: inactive token", auth.ErrInvalidToken)
		}

		ti := &auth.TokenInfo{
			UserID: body.Sub,
			Extra:  map[string]any{tokenInfoAccessTokenKey: token},
		}
		if body.Exp > 0 {
			ti.Expiration = time.Unix(body.Exp, 0)
		} else {
			// RequireBearerToken rejects a token with no expiry; auth always
			// returns exp, but guard against a zero value just in case.
			ti.Expiration = time.Now().Add(time.Hour)
		}
		return ti, nil
	}
}
