package client

import (
	"context"

	"github.com/deploys-app/api"
)

type dropboxClient struct {
	inv invoker
}

func (c dropboxClient) List(ctx context.Context, m *api.DropboxList) (*api.DropboxListResult, error) {
	var res api.DropboxListResult
	err := c.inv.invoke(ctx, "dropbox.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c dropboxClient) Metrics(ctx context.Context, m *api.DropboxMetrics) (*api.DropboxMetricsResult, error) {
	var res api.DropboxMetricsResult
	err := c.inv.invoke(ctx, "dropbox.metrics", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
