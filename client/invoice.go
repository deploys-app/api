package client

import (
	"context"

	"github.com/deploys-app/api"
)

type invoiceClient struct {
	inv invoker
}

func (c invoiceClient) List(ctx context.Context, m *api.InvoiceList) (*api.InvoiceListResult, error) {
	var res api.InvoiceListResult
	err := c.inv.invoke(ctx, "invoice.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c invoiceClient) Get(ctx context.Context, m *api.InvoiceGet) (*api.InvoiceItem, error) {
	var res api.InvoiceItem
	err := c.inv.invoke(ctx, "invoice.get", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}
