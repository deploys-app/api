package client

import (
	"context"

	"github.com/deploys-app/api"
)

type wafListClient struct {
	inv invoker
}

func (c wafListClient) Set(ctx context.Context, m *api.WAFListSet) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "wafList.set", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c wafListClient) Get(ctx context.Context, m *api.WAFListGet) (*api.WAFListItem, error) {
	var res api.WAFListItem
	if err := c.inv.invoke(ctx, "wafList.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c wafListClient) List(ctx context.Context, m *api.WAFListList) (*api.WAFListListResult, error) {
	var res api.WAFListListResult
	if err := c.inv.invoke(ctx, "wafList.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c wafListClient) Delete(ctx context.Context, m *api.WAFListDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "wafList.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
