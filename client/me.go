package client

import (
	"context"

	"github.com/deploys-app/api"
)

type meClient struct {
	inv invoker
}

func (c meClient) Get(ctx context.Context, m *api.Empty) (*api.MeItem, error) {
	var res api.MeItem
	err := c.inv.invoke(ctx, "me.get", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c meClient) Authorized(ctx context.Context, m *api.MeAuthorized) (*api.MeAuthorizedResult, error) {
	var res api.MeAuthorizedResult
	err := c.inv.invoke(ctx, "me.authorized", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c meClient) Permissions(ctx context.Context, m *api.MePermissions) (*api.MePermissionsResult, error) {
	var res api.MePermissionsResult
	err := c.inv.invoke(ctx, "me.permissions", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c meClient) GenerateToken(ctx context.Context, m *api.MeGenerateToken) (*api.MeGenerateTokenResult, error) {
	var res api.MeGenerateTokenResult
	err := c.inv.invoke(ctx, "me.generateToken", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c meClient) UploadKYCDocument(ctx context.Context, _ *api.MeUploadKYCDocument) (*api.MeUploadKYCDocumentResult, error) {
	return nil, nil
}
