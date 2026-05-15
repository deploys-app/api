package client

import (
	"context"

	"github.com/deploys-app/api"
)

type auditLogClient struct {
	inv invoker
}

func (c auditLogClient) List(ctx context.Context, m *api.AuditLogList) (*api.AuditLogListResult, error) {
	var res api.AuditLogListResult
	err := c.inv.invoke(ctx, "auditlog.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
