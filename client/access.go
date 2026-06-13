package client

import (
	"context"

	"github.com/deploys-app/api"
)

type accessClient struct {
	inv invoker
}

func (c accessClient) Policy(ctx context.Context, m *api.AccessPolicy) (*api.AccessPolicyResult, error) {
	var res api.AccessPolicyResult
	err := c.inv.invoke(ctx, "access.policy", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
