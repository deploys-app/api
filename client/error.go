package client

import (
	"context"

	"github.com/deploys-app/api"
)

type errorClient struct {
	inv invoker
}

func (c errorClient) List(ctx context.Context, m *api.ErrorList) (*api.ErrorListResult, error) {
	var res api.ErrorListResult
	err := c.inv.invoke(ctx, "error.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c errorClient) Get(ctx context.Context, m *api.ErrorGet) (*api.ErrorGetResult, error) {
	var res api.ErrorGetResult
	err := c.inv.invoke(ctx, "error.get", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c errorClient) Update(ctx context.Context, m *api.ErrorUpdate) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "error.update", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c errorClient) Create(ctx context.Context, m *api.ErrorCreate) (*api.ErrorCreateResult, error) {
	var res api.ErrorCreateResult
	err := c.inv.invoke(ctx, "error.create", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
