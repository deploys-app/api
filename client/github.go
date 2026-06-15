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

func (c githubClient) Update(ctx context.Context, m *api.GitHubUpdate) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "github.update", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) SetWorkflowConfig(ctx context.Context, m *api.GitHubSetWorkflowConfig) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "github.setWorkflowConfig", m, &res)
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

func (c githubClient) LookupRepo(ctx context.Context, m *api.GitHubLookupRepo) (*api.GitHubLookupRepoResult, error) {
	var res api.GitHubLookupRepoResult
	err := c.inv.invoke(ctx, "github.lookupRepo", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) GetApp(ctx context.Context, m *api.GitHubGetApp) (*api.GitHubAppInfo, error) {
	var res api.GitHubAppInfo
	err := c.inv.invoke(ctx, "github.getApp", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) ListRepos(ctx context.Context, m *api.GitHubListRepos) (*api.GitHubListReposResult, error) {
	var res api.GitHubListReposResult
	err := c.inv.invoke(ctx, "github.listRepos", m, &res)
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

func (c githubClient) AddInstallation(ctx context.Context, m *api.GitHubAddInstallation) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "github.addInstallation", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c githubClient) ListInstallations(ctx context.Context, m *api.GitHubListInstallations) (*api.GitHubListInstallationsResult, error) {
	var res api.GitHubListInstallationsResult
	err := c.inv.invoke(ctx, "github.listInstallations", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
