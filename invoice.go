package api

import (
	"context"
	"time"

	"github.com/moonrhythm/validator"
)

type Invoice interface {
	List(ctx context.Context, m *InvoiceList) (*InvoiceListResult, error)
	Get(ctx context.Context, m *InvoiceGet) (*InvoiceItem, error)
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
	ID int64 `json:"id,string" yaml:"id"`
}

func (m *InvoiceGet) Valid() error {
	v := validator.New()

	v.Must(m.ID > 0, "id required")

	return WrapValidate(v)
}

type InvoiceLineItem struct {
	SKU         string  `json:"sku" yaml:"sku"`
	Description string  `json:"description" yaml:"description"`
	Quantity    float64 `json:"quantity" yaml:"quantity"`
	Unit        string  `json:"unit" yaml:"unit"`
	UnitPrice   float64 `json:"unitPrice" yaml:"unitPrice"`
	Amount      float64 `json:"amount" yaml:"amount"`
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
