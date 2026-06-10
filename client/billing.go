package client

import (
	"context"

	"github.com/deploys-app/api"
)

type billingClient struct {
	inv invoker
}

func (c billingClient) Create(ctx context.Context, m *api.BillingCreate) (*api.BillingCreateResult, error) {
	var res api.BillingCreateResult
	err := c.inv.invoke(ctx, "billing.create", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) List(ctx context.Context, m *api.Empty) (*api.BillingListResult, error) {
	var res api.BillingListResult
	err := c.inv.invoke(ctx, "billing.list", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) Delete(ctx context.Context, m *api.BillingDelete) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "billing.delete", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) Get(ctx context.Context, m *api.BillingGet) (*api.BillingItem, error) {
	var res api.BillingItem
	err := c.inv.invoke(ctx, "billing.get", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) Update(ctx context.Context, m *api.BillingUpdate) (*api.Empty, error) {
	var res api.Empty
	err := c.inv.invoke(ctx, "billing.update", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) Report(ctx context.Context, m *api.BillingReport) (*api.BillingReportResult, error) {
	var res api.BillingReportResult
	err := c.inv.invoke(ctx, "billing.report", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) SKUs(ctx context.Context, m *api.Empty) (*api.BillingSKUs, error) {
	var res api.BillingSKUs
	err := c.inv.invoke(ctx, "billing.skus", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) Project(ctx context.Context, m *api.BillingProject) (*api.BillingProjectResult, error) {
	var res api.BillingProjectResult
	err := c.inv.invoke(ctx, "billing.project", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) ListInvoices(ctx context.Context, m *api.InvoiceList) (*api.InvoiceListResult, error) {
	var res api.InvoiceListResult
	err := c.inv.invoke(ctx, "billing.listInvoices", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) GetInvoice(ctx context.Context, m *api.InvoiceGet) (*api.InvoiceItem, error) {
	var res api.InvoiceItem
	err := c.inv.invoke(ctx, "billing.getInvoice", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) DownloadInvoice(ctx context.Context, m *api.InvoiceGet) (*api.InvoiceDownloadResult, error) {
	var res api.InvoiceDownloadResult
	err := c.inv.invoke(ctx, "billing.downloadInvoice", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

func (c billingClient) DownloadReceipt(ctx context.Context, m *api.InvoiceGet) (*api.InvoiceDownloadResult, error) {
	var res api.InvoiceDownloadResult
	err := c.inv.invoke(ctx, "billing.downloadReceipt", m, &res)
	if err != nil {
		return nil, err
	}
	return &res, nil
}

// UploadTransferSlip is a multipart upload; the JSON invoker can't express it,
// so the Go client leaves it unimplemented (same as Me.UploadKYCDocument).
// Callers upload directly via multipart POST to billing.uploadTransferSlip.
func (c billingClient) UploadTransferSlip(_ context.Context, _ *api.InvoiceUploadSlip) (*api.InvoiceUploadSlipResult, error) {
	return nil, nil
}
