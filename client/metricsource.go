package client

import (
	"context"

	"github.com/deploys-app/api"
)

type metricSourceClient struct {
	inv invoker
}

func (c metricSourceClient) Set(ctx context.Context, m *api.MetricSourceSet) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "metricSource.set", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c metricSourceClient) Get(ctx context.Context, m *api.MetricSourceGet) (*api.MetricSourceItem, error) {
	var res api.MetricSourceItem
	if err := c.inv.invoke(ctx, "metricSource.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c metricSourceClient) List(ctx context.Context, m *api.MetricSourceList) (*api.MetricSourceListResult, error) {
	var res api.MetricSourceListResult
	if err := c.inv.invoke(ctx, "metricSource.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c metricSourceClient) Delete(ctx context.Context, m *api.MetricSourceDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "metricSource.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c metricSourceClient) Series(ctx context.Context, m *api.MetricSourceSeries) (*api.MetricSourceSeriesResult, error) {
	var res api.MetricSourceSeriesResult
	if err := c.inv.invoke(ctx, "metricSource.series", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c metricSourceClient) Query(ctx context.Context, m *api.MetricSourceQuery) (*api.MetricSourceQueryResult, error) {
	var res api.MetricSourceQueryResult
	if err := c.inv.invoke(ctx, "metricSource.query", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
