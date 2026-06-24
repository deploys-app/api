package client

import (
	"context"

	"github.com/deploys-app/api"
)

type cacheClient struct {
	inv invoker
}

func (c cacheClient) Get(ctx context.Context, m *api.CacheGet) (*api.CacheItem, error) {
	var res api.CacheItem
	if err := c.inv.invoke(ctx, "cache.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c cacheClient) List(ctx context.Context, m *api.CacheList) (*api.CacheListResult, error) {
	var res api.CacheListResult
	if err := c.inv.invoke(ctx, "cache.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c cacheClient) Set(ctx context.Context, m *api.CacheSet) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "cache.set", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c cacheClient) Delete(ctx context.Context, m *api.CacheDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "cache.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c cacheClient) Metrics(ctx context.Context, m *api.CacheMetrics) (*api.CacheMetricsResult, error) {
	var res api.CacheMetricsResult
	if err := c.inv.invoke(ctx, "cache.metrics", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c cacheClient) ResultMetrics(ctx context.Context, m *api.CacheResultMetrics) (*api.CacheResultMetricsResult, error) {
	var res api.CacheResultMetricsResult
	if err := c.inv.invoke(ctx, "cache.resultMetrics", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
