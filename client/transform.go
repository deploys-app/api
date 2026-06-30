package client

import (
	"context"

	"github.com/deploys-app/api"
)

type transformClient struct {
	inv invoker
}

func (c transformClient) Get(ctx context.Context, m *api.TransformGet) (*api.TransformItem, error) {
	var res api.TransformItem
	if err := c.inv.invoke(ctx, "transform.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c transformClient) List(ctx context.Context, m *api.TransformList) (*api.TransformListResult, error) {
	var res api.TransformListResult
	if err := c.inv.invoke(ctx, "transform.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c transformClient) Set(ctx context.Context, m *api.TransformSet) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "transform.set", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c transformClient) Delete(ctx context.Context, m *api.TransformDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "transform.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
