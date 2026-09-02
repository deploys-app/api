package client

import (
	"context"

	"github.com/deploys-app/api"
)

type alertClient struct {
	inv invoker
}

func (c alertClient) Create(ctx context.Context, m *api.AlertCreate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "alert.create", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c alertClient) Update(ctx context.Context, m *api.AlertUpdate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "alert.update", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c alertClient) Get(ctx context.Context, m *api.AlertGet) (*api.AlertItem, error) {
	var res api.AlertItem
	if err := c.inv.invoke(ctx, "alert.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c alertClient) List(ctx context.Context, m *api.AlertList) (*api.AlertListResult, error) {
	var res api.AlertListResult
	if err := c.inv.invoke(ctx, "alert.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c alertClient) Delete(ctx context.Context, m *api.AlertDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "alert.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c alertClient) Events(ctx context.Context, m *api.AlertEvents) (*api.AlertEventsResult, error) {
	var res api.AlertEventsResult
	if err := c.inv.invoke(ctx, "alert.events", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
