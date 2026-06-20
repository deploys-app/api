package client

import (
	"context"

	"github.com/deploys-app/api"
)

type registryClient struct {
	inv invoker
}

func (c registryClient) List(ctx context.Context, m *api.RegistryList) (*api.RegistryListResult, error) {
	var res api.RegistryListResult
	if err := c.inv.invoke(ctx, "registry.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) Get(ctx context.Context, m *api.RegistryGet) (*api.RegistryRepository, error) {
	var res api.RegistryRepository
	if err := c.inv.invoke(ctx, "registry.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) GetTags(ctx context.Context, m *api.RegistryGetTags) (*api.RegistryGetTagsResult, error) {
	var res api.RegistryGetTagsResult
	if err := c.inv.invoke(ctx, "registry.getTags", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) GetManifests(ctx context.Context, m *api.RegistryGetManifests) (*api.RegistryGetManifestsResult, error) {
	var res api.RegistryGetManifestsResult
	if err := c.inv.invoke(ctx, "registry.getManifests", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) GetProjectStorage(ctx context.Context, m *api.RegistryGetProjectStorage) (*api.RegistryProjectStorage, error) {
	var res api.RegistryProjectStorage
	if err := c.inv.invoke(ctx, "registry.getProjectStorage", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) Delete(ctx context.Context, m *api.RegistryDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "registry.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) DeleteManifest(ctx context.Context, m *api.RegistryDeleteManifest) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "registry.deleteManifest", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) Untag(ctx context.Context, m *api.RegistryUntag) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "registry.untag", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) GC(ctx context.Context, m *api.RegistryGC) (*api.RegistryGCResult, error) {
	var res api.RegistryGCResult
	if err := c.inv.invoke(ctx, "registry.gc", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c registryClient) Metrics(ctx context.Context, m *api.RegistryMetrics) (*api.RegistryMetricsResult, error) {
	var res api.RegistryMetricsResult
	if err := c.inv.invoke(ctx, "registry.metrics", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
