package client

import (
	"context"

	"github.com/deploys-app/api"
)

type githubClient struct {
	inv invoker
}

func (c githubClient) Link(ctx context.Context, m *api.GitHubLink) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "github.link", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) Unlink(ctx context.Context, m *api.GitHubUnlink) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "github.unlink", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) List(ctx context.Context, m *api.GitHubList) (*api.GitHubListResult, error) {
	var res api.GitHubListResult
	err := c.inv.invoke(ctx, "github.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) ExchangeToken(ctx context.Context, m *api.GitHubExchangeToken) (*api.GitHubExchangeTokenResult, error) {
	var res api.GitHubExchangeTokenResult
	err := c.inv.invoke(ctx, "github.exchangeToken", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) Notify(ctx context.Context, m *api.GitHubNotify) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "github.notify", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
