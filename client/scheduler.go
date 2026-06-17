package client

import (
	"context"

	"github.com/deploys-app/api"
)

type schedulerClient struct {
	inv invoker
}

func (c schedulerClient) Create(ctx context.Context, m *api.SchedulerCreate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "scheduler.create", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Update(ctx context.Context, m *api.SchedulerUpdate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "scheduler.update", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Get(ctx context.Context, m *api.SchedulerGet) (*api.SchedulerItem, error) {
	var res api.SchedulerItem
	if err := c.inv.invoke(ctx, "scheduler.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) List(ctx context.Context, m *api.SchedulerList) (*api.SchedulerListResult, error) {
	var res api.SchedulerListResult
	if err := c.inv.invoke(ctx, "scheduler.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Delete(ctx context.Context, m *api.SchedulerDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "scheduler.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Pause(ctx context.Context, m *api.SchedulerPause) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "scheduler.pause", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Resume(ctx context.Context, m *api.SchedulerResume) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "scheduler.resume", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Trigger(ctx context.Context, m *api.SchedulerTrigger) (*api.SchedulerInvocation, error) {
	var res api.SchedulerInvocation
	if err := c.inv.invoke(ctx, "scheduler.trigger", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c schedulerClient) Logs(ctx context.Context, m *api.SchedulerLogs) (*api.SchedulerLogsResult, error) {
	var res api.SchedulerLogsResult
	if err := c.inv.invoke(ctx, "scheduler.logs", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
