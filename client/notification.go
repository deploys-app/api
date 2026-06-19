package client

import (
	"context"

	"github.com/deploys-app/api"
)

type notificationClient struct {
	inv invoker
}

func (c notificationClient) Create(ctx context.Context, m *api.NotificationCreate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "notification.create", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c notificationClient) Update(ctx context.Context, m *api.NotificationUpdate) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "notification.update", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c notificationClient) Get(ctx context.Context, m *api.NotificationGet) (*api.NotificationItem, error) {
	var res api.NotificationItem
	if err := c.inv.invoke(ctx, "notification.get", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c notificationClient) List(ctx context.Context, m *api.NotificationList) (*api.NotificationListResult, error) {
	var res api.NotificationListResult
	if err := c.inv.invoke(ctx, "notification.list", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c notificationClient) Delete(ctx context.Context, m *api.NotificationDelete) (*api.Empty, error) {
	var res api.Empty
	if err := c.inv.invoke(ctx, "notification.delete", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c notificationClient) Test(ctx context.Context, m *api.NotificationTest) (*api.NotificationDelivery, error) {
	var res api.NotificationDelivery
	if err := c.inv.invoke(ctx, "notification.test", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (c notificationClient) Deliveries(ctx context.Context, m *api.NotificationDeliveries) (*api.NotificationDeliveriesResult, error) {
	var res api.NotificationDeliveriesResult
	if err := c.inv.invoke(ctx, "notification.deliveries", m, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
