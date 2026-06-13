package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type searchInput struct {
	Query string `json:"query" jsonschema:"keywords or natural-language intent describing the deploys.app action you want, e.g. 'list deployments' or 'create disk'; empty browses all actions"`
	Limit int    `json:"limit,omitempty" jsonschema:"maximum number of actions to return; defaults to 20"`
}

type executeInput struct {
	Action string         `json:"action" jsonschema:"the action id to execute, exactly as returned by deploys_search_actions, e.g. deployment.list"`
	Params map[string]any `json:"params,omitempty" jsonschema:"the parameters object for the action; match the inputSchema returned by deploys_search_actions"`
}

func registerTools(s *mcp.Server, reg *registry) {
	mcp.AddTool(s, &mcp.Tool{
		Name: "deploys_search_actions",
		Description: "Search the deploys.app API for actions to run. Returns matching action ids, " +
			"descriptions, whether each is read-only or destructive, and the JSON input schema for each. " +
			"Use this first to find the action id and its parameters, then call deploys_execute_action. " +
			"Pass an empty query to browse the whole catalogue.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(_ context.Context, _ *mcp.CallToolRequest, in searchInput) (*mcp.CallToolResult, any, error) {
		limit := in.Limit
		if limit <= 0 {
			limit = 20
		}
		return jsonResult(reg.search(in.Query, limit))
	})

	destructive := true
	mcp.AddTool(s, &mcp.Tool{
		Name: "deploys_execute_action",
		Description: "Execute a deploys.app API action by id with a params object. Discover valid action ids " +
			"and their input schemas with deploys_search_actions first. Returns the JSON result from the API.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &destructive},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in executeInput) (*mcp.CallToolResult, any, error) {
		act, ok := reg.actions[in.Action]
		if !ok {
			return errResult("unknown action %q; call deploys_search_actions to discover valid action ids", in.Action)
		}
		var raw json.RawMessage
		if len(in.Params) > 0 {
			b, err := json.Marshal(in.Params)
			if err != nil {
				return errResult("invalid params: %v", err)
			}
			raw = b
		}
		res, err := act.invoke(ctx, raw)
		if err != nil {
			// API/validation/permission errors are surfaced to the model, not the protocol.
			return errResult("%s failed: %v", in.Action, err)
		}
		return jsonResult(res)
	})
}

func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errResult("encode result: %v", err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func errResult(format string, a ...any) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, a...)}},
	}, nil, nil
}
