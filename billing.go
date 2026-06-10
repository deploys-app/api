package api

import (
	"context"
	"mime/multipart"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

type Billing interface {
	Create(ctx context.Context, m *BillingCreate) (*BillingCreateResult, error)
	List(ctx context.Context, m *Empty) (*BillingListResult, error)
	Delete(ctx context.Context, m *BillingDelete) (*Empty, error)
	Get(ctx context.Context, m *BillingGet) (*BillingItem, error)
	Update(ctx context.Context, m *BillingUpdate) (*Empty, error)
	Report(ctx context.Context, m *BillingReport) (*BillingReportResult, error)
	SKUs(ctx context.Context, m *Empty) (*BillingSKUs, error)
	Project(ctx context.Context, m *BillingProject) (*BillingProjectResult, error)
	ListInvoices(ctx context.Context, m *InvoiceList) (*InvoiceListResult, error)
	GetInvoice(ctx context.Context, m *InvoiceGet) (*InvoiceItem, error)
	DownloadInvoice(ctx context.Context, m *InvoiceGet) (*InvoiceDownloadResult, error)
	UploadTransferSlip(ctx context.Context, m *InvoiceUploadSlip) (*InvoiceUploadSlipResult, error)
}

type BillingCreate struct {
	Name       string `json:"name" yaml:"name"`
	TaxID      string `json:"taxId" yaml:"taxId"`
	TaxName    string `json:"taxName" yaml:"taxName"`
	TaxAddress string `json:"taxAddress" yaml:"taxAddress"`
}

func (m *BillingCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.TaxID = strings.TrimSpace(m.TaxID)
	m.TaxName = strings.TrimSpace(m.TaxName)
	m.TaxAddress = strings.TrimSpace(m.TaxAddress)

	v := validator.New()

	if ok := v.Must(m.Name != "", "name required"); ok {
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.TaxID != "", "tax id required")
	v.Must(utf8.RuneCountInString(m.TaxID) < 100, "tax id too long")
	v.Must(m.TaxName != "", "tax name required")
	v.Must(utf8.RuneCountInString(m.TaxName) < 200, "tax name too long")
	v.Must(m.TaxAddress != "", "tax address required")
	v.Must(utf8.RuneCountInString(m.TaxAddress) < 500, "tax address too long")

	return WrapValidate(v)
}

type BillingCreateResult struct {
	ID int64 `json:"id,string" yaml:"id"`
}

type BillingListResult struct {
	Items []*BillingItem `json:"items" yaml:"items"`
}

type BillingDelete struct {
	ID int64 `json:"id,string" yaml:"id"`
}

func (m *BillingDelete) Valid() error {
	v := validator.New()

	v.Must(m.ID > 0, "id required")

	return WrapValidate(v)
}

type BillingGet struct {
	ID int64 `json:"id,string" yaml:"id"`
}

func (m *BillingGet) Valid() error {
	v := validator.New()

	v.Must(m.ID > 0, "id required")

	return WrapValidate(v)
}

type BillingItem struct {
	ID         int64  `json:"id,string" yaml:"id"`
	Name       string `json:"name" yaml:"name"`
	TaxID      string `json:"taxId" yaml:"taxId"`
	TaxName    string `json:"taxName" yaml:"taxName"`
	TaxAddress string `json:"taxAddress" yaml:"taxAddress"`
	Active     bool   `json:"active" yaml:"active"`
}

type BillingUpdate struct {
	ID         int64  `json:"id,string" yaml:"id"`
	Name       string `json:"name" yaml:"name"`
	TaxID      string `json:"taxId" yaml:"taxId"`
	TaxName    string `json:"taxName" yaml:"taxName"`
	TaxAddress string `json:"taxAddress" yaml:"taxAddress"`
}

func (m *BillingUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.TaxID = strings.TrimSpace(m.TaxID)
	m.TaxName = strings.TrimSpace(m.TaxName)
	m.TaxAddress = strings.TrimSpace(m.TaxAddress)

	v := validator.New()

	if ok := v.Must(m.Name != "", "name required"); ok {
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.TaxID != "", "tax id required")
	v.Must(utf8.RuneCountInString(m.TaxID) < 100, "tax id too long")
	v.Must(m.TaxName != "", "tax name required")
	v.Must(utf8.RuneCountInString(m.TaxName) < 200, "tax name too long")
	v.Must(m.TaxAddress != "", "tax address required")
	v.Must(utf8.RuneCountInString(m.TaxAddress) < 500, "tax address too long")

	return WrapValidate(v)
}

type BillingReport struct {
	ID          int64    `json:"id,string" yaml:"id"`
	Range       string   `json:"range" yaml:"range"`
	ProjectSIDs []string `json:"projectSids" yaml:"projectSids"`
}

type BillingReportListItem struct {
	ProjectSID   string  `json:"projectSid" yaml:"projectSid"`
	Name         string  `json:"name" yaml:"name"`
	UsageValue   float64 `json:"usageValue" yaml:"usageValue"`
	BillingValue float64 `json:"billingValue" yaml:"billingValue"`
}

type BillingReportChartSeries struct {
	Name string    `json:"name" yaml:"name"`
	Data []float64 `json:"data" yaml:"data"`
}

type BillingReportChart struct {
	Categories []string                    `json:"categories" yaml:"categories"`
	Series     []*BillingReportChartSeries `json:"series" yaml:"series"`
}

type ReportProjectListItem struct {
	SID  string `json:"sid" yaml:"sid"`
	Name string `json:"name" yaml:"name"`
}

type BillingReportResult struct {
	Range       string                   `json:"range" yaml:"range"`
	List        []*BillingReportListItem `json:"list" yaml:"list"`
	Chart       *BillingReportChart      `json:"chart" yaml:"chart"`
	ProjectList []*ReportProjectListItem `json:"projectList" yaml:"projectList"`
	ProjectSIDs []string                 `json:"projectSids" yaml:"projectSids"`
}

type BillingSKUs struct {
	CPUUsage       float64 `json:"cpuUsage" yaml:"cpuUsage"`
	CPU            float64 `json:"cpu" yaml:"cpu"`
	Memory         float64 `json:"memory" yaml:"memory"`
	Egress         float64 `json:"egress" yaml:"egress"`
	RegistryEgress float64 `json:"registryEgress" yaml:"registryEgress"`
	DropboxEgress  float64 `json:"dropboxEgress" yaml:"dropboxEgress"`
	Disk           float64 `json:"disk" yaml:"disk"`
	Replica        float64 `json:"replica" yaml:"replica"`
}

type BillingProject struct {
	Project string `json:"project" yaml:"project"`
}

type BillingProjectResult struct {
	Price float64 `json:"price" yaml:"price"`
}

type InvoiceList struct {
	BillingAccountID int64 `json:"billingAccountId,string" yaml:"billingAccountId"`
}

func (m *InvoiceList) Valid() error {
	v := validator.New()

	v.Must(m.BillingAccountID > 0, "billingAccountId required")

	return WrapValidate(v)
}

type InvoiceListItem struct {
	ID          int64     `json:"id,string" yaml:"id"`
	Number      string    `json:"number" yaml:"number"`
	Currency    string    `json:"currency" yaml:"currency"`
	PeriodStart time.Time `json:"periodStart" yaml:"periodStart"`
	PeriodEnd   time.Time `json:"periodEnd" yaml:"periodEnd"`
	Subtotal    float64   `json:"subtotal" yaml:"subtotal"`
	TaxAmount   float64   `json:"taxAmount" yaml:"taxAmount"`
	Total       float64   `json:"total" yaml:"total"`
	Status      string    `json:"status" yaml:"status"`
	IssuedAt    time.Time `json:"issuedAt" yaml:"issuedAt"`
	PaidAt      time.Time `json:"paidAt" yaml:"paidAt"`
	VoidedAt    time.Time `json:"voidedAt" yaml:"voidedAt"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
}

type InvoiceListResult struct {
	Items []*InvoiceListItem `json:"items" yaml:"items"`
}

type InvoiceGet struct {
	// InvoiceID rather than ID: this is a billing-module request, where a bare
	// "id" would be ambiguous with the billing-account id.
	InvoiceID int64 `json:"invoiceId,string" yaml:"invoiceId"`
}

func (m *InvoiceGet) Valid() error {
	v := validator.New()

	v.Must(m.InvoiceID > 0, "invoiceId required")

	return WrapValidate(v)
}

// InvoiceLineItem is one summary line on an invoice: a single project's total
// charge for the billing period. Invoices are grouped by project (not by SKU),
// so the per-resource breakdown does not appear here — only the project's
// aggregate Amount. ProjectID / Project / Description are snapshotted at issue
// time so the line stays stable even if the project is later renamed or deleted.
type InvoiceLineItem struct {
	// ProjectID is the billed project's id, snapshotted at issue time.
	ProjectID int64 `json:"projectId,string" yaml:"projectId"`
	// Project is the project's sid (stable slug), snapshotted at issue time.
	Project string `json:"project" yaml:"project"`
	// Description is the project's display name at issue time (falls back to the
	// sid when the project has no name).
	Description string `json:"description" yaml:"description"`
	// Amount is the project's total charge for the period (gross, VAT-inclusive).
	Amount float64 `json:"amount" yaml:"amount"`
}

type InvoiceItem struct {
	ID               int64     `json:"id,string" yaml:"id"`
	BillingAccountID int64     `json:"billingAccountId,string" yaml:"billingAccountId"`
	Number           string    `json:"number" yaml:"number"`
	Currency         string    `json:"currency" yaml:"currency"`
	PeriodStart      time.Time `json:"periodStart" yaml:"periodStart"`
	PeriodEnd        time.Time `json:"periodEnd" yaml:"periodEnd"`
	Subtotal         float64   `json:"subtotal" yaml:"subtotal"`
	TaxRate          float64   `json:"taxRate" yaml:"taxRate"`
	TaxAmount        float64   `json:"taxAmount" yaml:"taxAmount"`
	Total            float64   `json:"total" yaml:"total"`
	Status           string    `json:"status" yaml:"status"`
	TaxID            string    `json:"taxId" yaml:"taxId"`
	TaxName          string    `json:"taxName" yaml:"taxName"`
	TaxAddress       string    `json:"taxAddress" yaml:"taxAddress"`
	IssuedAt         time.Time `json:"issuedAt" yaml:"issuedAt"`
	PaidAt           time.Time `json:"paidAt" yaml:"paidAt"`
	VoidedAt         time.Time `json:"voidedAt" yaml:"voidedAt"`
	CreatedAt        time.Time `json:"createdAt" yaml:"createdAt"`

	LineItems []*InvoiceLineItem `json:"lineItems" yaml:"lineItems"`
}

// InvoiceDownloadResult points at a rendered PDF copy of an invoice. The PDF
// is uploaded to the dropbox service, so DownloadURL is a short-lived signed
// link that expires at ExpiresAt — callers should fetch it promptly rather
// than storing it.
type InvoiceDownloadResult struct {
	DownloadURL string    `json:"downloadUrl" yaml:"downloadUrl"`
	ExpiresAt   time.Time `json:"expiresAt" yaml:"expiresAt"`
}

// MaxTransferSlipSize caps an uploaded payment slip. Slips are photos or PDF
// scans of a bank transfer; 10 MiB is generous for either.
const MaxTransferSlipSize = 10 << 20

// InvoiceUploadSlip carries a customer's proof-of-payment (bank transfer slip)
// for an invoice. It is a multipart upload: the invoice id in the `id` form
// field and the file in the `slip` file field.
type InvoiceUploadSlip struct {
	ID   int64
	File *multipart.FileHeader
}

func (m *InvoiceUploadSlip) UnmarshalMultipartForm(v *multipart.Form) error {
	if ids := v.Value["id"]; len(ids) == 1 {
		m.ID, _ = strconv.ParseInt(ids[0], 10, 64)
	}
	if fps := v.File["slip"]; len(fps) == 1 {
		m.File = fps[0]
	}
	return nil
}

func (m *InvoiceUploadSlip) Valid() error {
	v := validator.New()

	v.Must(m.ID > 0, "id required")
	if ok := v.Must(m.File != nil, "slip required"); ok {
		v.Must(m.File.Size > 0, "slip required")
		v.Must(m.File.Size <= MaxTransferSlipSize, "slip too large")
	}

	return WrapValidate(v)
}

type InvoiceUploadSlipResult struct {
	DownloadURL string    `json:"downloadUrl" yaml:"downloadUrl"`
	ExpiresAt   time.Time `json:"expiresAt" yaml:"expiresAt"`
}
