package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// testEnv wires a stub upstream deploys.app API and a stub auth introspection
// endpoint behind a real instance of the MCP resource-server handler.
type testEnv struct {
	mcpURL       string
	gotUpstrAuth chan string // Authorization header seen by the upstream API
}

func newTestEnv(t *testing.T, userToken, introspectionToken, userEmail string) *testEnv {
	t.Helper()

	gotUpstrAuth := make(chan string, 1)

	// Stub upstream API: record the forwarded Authorization header and return a
	// minimal me.get result envelope.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case gotUpstrAuth <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"ok":     true,
			"result": map[string]any{"email": userEmail},
		})
	}))
	t.Cleanup(upstream.Close)

	// Stub auth introspection (RFC 7662), guarded by the shared secret.
	authSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/introspect" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+introspectionToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if r.PostForm.Get("token") != userToken {
			json.NewEncoder(w).Encode(map[string]any{"active": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    userEmail,
			"exp":    time.Now().Add(time.Hour).Unix(),
		})
	}))
	t.Cleanup(authSrv.Close)

	h := newHTTPHandler(httpConfig{
		baseURL:            "https://mcp.example.com",
		authURL:            authSrv.URL,
		introspectionToken: introspectionToken,
		apiEndpoint:        upstream.URL,
	})
	mcpSrv := httptest.NewServer(h)
	t.Cleanup(mcpSrv.Close)

	return &testEnv{mcpURL: mcpSrv.URL, gotUpstrAuth: gotUpstrAuth}
}

// bearerRoundTripper injects a fixed bearer token onto every outgoing request.
type bearerRoundTripper struct {
	token string
	base  http.RoundTripper
}

func (b bearerRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return b.base.RoundTrip(r)
}

func TestProtectedResourceMetadata(t *testing.T) {
	env := newTestEnv(t, "user-token", "introspect-secret", "alice@example.com")

	resp, err := http.Get(env.mcpURL + protectedResourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var meta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		t.Fatal(err)
	}
	if meta.Resource != "https://mcp.example.com" {
		t.Errorf("resource = %q", meta.Resource)
	}
	if len(meta.AuthorizationServers) != 1 || !strings.HasPrefix(meta.AuthorizationServers[0], "http") {
		t.Errorf("authorization_servers = %v", meta.AuthorizationServers)
	}
}

func TestUnauthenticatedChallenge(t *testing.T) {
	env := newTestEnv(t, "user-token", "introspect-secret", "alice@example.com")

	// A POST to the MCP endpoint with no bearer must be challenged.
	resp, err := http.Post(env.mcpURL+"/", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	chal := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(chal, "resource_metadata=") {
		t.Errorf("WWW-Authenticate = %q, want resource_metadata", chal)
	}
}

func TestInvalidTokenChallenge(t *testing.T) {
	env := newTestEnv(t, "good-token", "introspect-secret", "alice@example.com")

	req, _ := http.NewRequest(http.MethodPost, env.mcpURL+"/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

// TestAuthenticatedForwardsToken is the end-to-end proof: a valid caller runs a
// tool through the real MCP client, and the upstream API receives that caller's
// bearer token — i.e. identity propagates request -> introspection -> tool
// handler -> upstream client.
func TestAuthenticatedForwardsToken(t *testing.T) {
	const userToken = "user-token-abc"
	env := newTestEnv(t, userToken, "introspect-secret", "alice@example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	httpClient := &http.Client{
		Transport: bearerRoundTripper{token: userToken, base: http.DefaultTransport},
	}
	transport := &mcp.StreamableClientTransport{
		Endpoint:             env.mcpURL + "/",
		HTTPClient:           httpClient,
		DisableStandaloneSSE: true, // request/response only; stateless server
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "deploys_execute_action",
		Arguments: map[string]any{"action": "me.get"},
	})
	if err != nil {
		t.Fatalf("call tool: %v", err)
	}
	if res.IsError {
		t.Fatalf("tool returned error: %+v", res.Content)
	}

	select {
	case got := <-env.gotUpstrAuth:
		if got != "Bearer "+userToken {
			t.Errorf("upstream Authorization = %q, want %q", got, "Bearer "+userToken)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream API was never called")
	}
}
