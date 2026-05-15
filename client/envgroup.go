package client

import (
	"context"

	"github.com/deploys-app/api"
)

type envGroupClient struct {
	inv invoker
}

func (c envGroupClient) Create(ctx context.Context, m *api.EnvGroupCreate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "envgroup.create", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c envGroupClient) Get(ctx context.Context, m *api.EnvGroupGet) (*api.EnvGroupItem, error) {
	var res api.EnvGroupItem
	if err := c.inv.invoke(ctx, "envgroup.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c envGroupClient) List(ctx context.Context, m *api.EnvGroupList) (*api.EnvGroupListResult, error) {
	var res api.EnvGroupListResult
	if err := c.inv.invoke(ctx, "envgroup.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c envGroupClient) Update(ctx context.Context, m *api.EnvGroupUpdate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "envgroup.update", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c envGroupClient) Delete(ctx context.Context, m *api.EnvGroupDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "envgroup.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
