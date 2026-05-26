package client

import (
	"context"

	"github.com/deploys-app/api"
)

type wafClient struct {
	inv invoker
}

func (c wafClient) Get(ctx context.Context, m *api.WAFGet) (*api.WAFItem, error) {
	var res api.WAFItem
	if err := c.inv.invoke(ctx, "waf.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c wafClient) Set(ctx context.Context, m *api.WAFSet) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "waf.set", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c wafClient) Delete(ctx context.Context, m *api.WAFDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "waf.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
