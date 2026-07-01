package api

import (
	"context"
	"mime/multipart"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/asaskevich/govalidator"
	"github.com/moonrhythm/validator"
)

type Billing interface {
	// Create requires authentication only (no specific permission; creates a billing account owned by the caller).
	Create(ctx context.Context, m *BillingCreate) (*BillingCreateResult, error)
	// List requires authentication only (no specific permission; lists the caller's own billing accounts).
	List(ctx context.Context, m *Empty) (*BillingListResult, error)
	// Delete requires ownership of the billing account (the caller must be its owner).
	Delete(ctx context.Context, m *BillingDelete) (*Empty, error)
	// Get requires ownership of the billing account (the caller must be its owner).
	Get(ctx context.Context, m *BillingGet) (*BillingItem, error)
	// Update requires ownership of the billing account (the caller must be its owner).
	Update(ctx context.Context, m *BillingUpdate) (*Empty, error)
	// Report requires ownership of the billing account (the caller must be its owner).
	Report(ctx context.Context, m *BillingReport) (*BillingReportResult, error)
	// SKUs requires no authentication (public static price list).
	SKUs(ctx context.Context, m *Empty) (*BillingSKUs, error)
	// Project requires the `project.get` permission.
	Project(ctx context.Context, m *BillingProject) (*BillingProjectResult, error)
	// ListInvoices requires ownership of the billing account (the caller must own the account).
	ListInvoices(ctx context.Context, m *InvoiceList) (*InvoiceListResult, error)
	// GetInvoice requires ownership of the invoice's billing account (the caller must own it).
	GetInvoice(ctx context.Context, m *InvoiceGet) (*InvoiceItem, error)
	// DownloadInvoice requires ownership of the invoice's billing account (enforced via GetInvoice).
	DownloadInvoice(ctx context.Context, m *InvoiceGet) (*InvoiceDownloadResult, error)
	// DownloadReceipt renders the receipt / tax-invoice PDF for a PAID invoice.
	// Calling it on a draft/open/void invoice returns ErrInvoiceNotPaid.
	// DownloadReceipt requires ownership of the invoice's billing account (enforced via GetInvoice).
	DownloadReceipt(ctx context.Context, m *InvoiceGet) (*InvoiceDownloadResult, error)
	// UploadTransferSlip requires ownership of the invoice's billing account (enforced via GetInvoice).
	UploadTransferSlip(ctx context.Context, m *InvoiceUploadSlip) (*InvoiceUploadSlipResult, error)
	// ListMembers lists the invited members of a billing account.
	// Requires the caller to be the account's owner or an admin member.
	ListMembers(ctx context.Context, m *BillingMemberList) (*BillingMemberListResult, error)
	// AddMember invites a user to a billing account (or changes an existing
	// member's role). Requires the caller to be the account's owner or an admin
	// member. The owner cannot be added as a member.
	AddMember(ctx context.Context, m *BillingMemberAdd) (*Empty, error)
	// RemoveMember removes an invited member from a billing account.
	// Requires the caller to be the account's owner or an admin member.
	RemoveMember(ctx context.Context, m *BillingMemberRemove) (*Empty, error)
}

// Billing account roles. The owner is implicit (the billing_accounts.owner
// column) and is never stored as a member row. Invited members hold one of the
// two member roles below.
const (
	// BillingRoleOwner is the account's sole owner: full control, including
	// deleting the account and managing members. Reported by Get/List for the
	// caller's own access; never a stored member role.
	BillingRoleOwner = "owner"
	// BillingRoleAdmin is a full co-manager: view + pay invoices, edit the
	// account's tax details, and manage members. Cannot delete the account.
	BillingRoleAdmin = "admin"
	// BillingRoleAccountant can view invoices/receipts, view the usage report,
	// and pay (upload a transfer slip). Cannot edit tax details, delete the
	// account, or manage members.
	BillingRoleAccountant = "accountant"
)

// IsValidBillingMemberRole reports whether role is a role that can be assigned
// to an invited member (owner is implicit and not assignable).
func IsValidBillingMemberRole(role string) bool {
	return role == BillingRoleAdmin || role == BillingRoleAccountant
}

// Billing account entity types. A billing account is either an Individual
// (บุคคลธรรมดา) or a Company (นิติบุคคล). The distinction is a Thai tax-document
// requirement: a juristic person must show the "Head Office" (สำนักงานใหญ่)
// branch designation on its tax invoices, so a Company account prints that line
// on the invoice/receipt while an Individual does not. Empty normalizes to
// Individual (the safe default for accounts that predate this field).
const (
	BillingTypeIndividual = "individual"
	BillingTypeCompany    = "company"
)

// normalizeBillingType trims and defaults an entity type, mapping "" to
// Individual. It returns the normalized value; the caller validates membership.
func normalizeBillingType(t string) string {
	t = strings.TrimSpace(t)
	if t == "" {
		return BillingTypeIndividual
	}
	return t
}

type BillingCreate struct {
	Name       string `json:"name" yaml:"name"`
	Type       string `json:"type" yaml:"type"`
	TaxID      string `json:"taxId" yaml:"taxId"`
	TaxName    string `json:"taxName" yaml:"taxName"`
	TaxAddress string `json:"taxAddress" yaml:"taxAddress"`
}

func (m *BillingCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Type = normalizeBillingType(m.Type)
	m.TaxID = strings.TrimSpace(m.TaxID)
	m.TaxName = strings.TrimSpace(m.TaxName)
	m.TaxAddress = strings.TrimSpace(m.TaxAddress)

	v := validator.New()

	if ok := v.Must(m.Name != "", "name required"); ok {
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.Type == BillingTypeIndividual || m.Type == BillingTypeCompany, "type must be individual or company")
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
	Type       string `json:"type" yaml:"type"`
	TaxID      string `json:"taxId" yaml:"taxId"`
	TaxName    string `json:"taxName" yaml:"taxName"`
	TaxAddress string `json:"taxAddress" yaml:"taxAddress"`
	Active     bool   `json:"active" yaml:"active"`
	// Role is the calling user's effective role on this account
	// (owner|admin|accountant), so a client can gate management UI without a
	// second lookup. Empty on responses that predate membership.
	Role string `json:"role" yaml:"role"`
}

type BillingUpdate struct {
	ID         int64  `json:"id,string" yaml:"id"`
	Name       string `json:"name" yaml:"name"`
	Type       string `json:"type" yaml:"type"`
	TaxID      string `json:"taxId" yaml:"taxId"`
	TaxName    string `json:"taxName" yaml:"taxName"`
	TaxAddress string `json:"taxAddress" yaml:"taxAddress"`
}

func (m *BillingUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Type = normalizeBillingType(m.Type)
	m.TaxID = strings.TrimSpace(m.TaxID)
	m.TaxName = strings.TrimSpace(m.TaxName)
	m.TaxAddress = strings.TrimSpace(m.TaxAddress)

	v := validator.New()

	if ok := v.Must(m.Name != "", "name required"); ok {
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.Type == BillingTypeIndividual || m.Type == BillingTypeCompany, "type must be individual or company")
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
	StaticStorage  float64 `json:"staticStorage" yaml:"staticStorage"`
	StaticEgress   float64 `json:"staticEgress" yaml:"staticEgress"`
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
	ID     int64  `json:"id,string" yaml:"id"`
	Number string `json:"number" yaml:"number"`
	// ReceiptNumber is the receipt's own running number (DPLY-RC-YYYYMM-NNNN),
	// assigned when the invoice is marked paid and distinct from Number. Empty
	// until paid.
	ReceiptNumber string    `json:"receiptNumber" yaml:"receiptNumber"`
	Currency      string    `json:"currency" yaml:"currency"`
	PeriodStart   time.Time `json:"periodStart" yaml:"periodStart"`
	PeriodEnd     time.Time `json:"periodEnd" yaml:"periodEnd"`
	Subtotal      float64   `json:"subtotal" yaml:"subtotal"`
	TaxAmount     float64   `json:"taxAmount" yaml:"taxAmount"`
	Total         float64   `json:"total" yaml:"total"`
	Status        string    `json:"status" yaml:"status"`
	IssuedAt      time.Time `json:"issuedAt" yaml:"issuedAt"`
	PaidAt        time.Time `json:"paidAt" yaml:"paidAt"`
	VoidedAt      time.Time `json:"voidedAt" yaml:"voidedAt"`
	CreatedAt     time.Time `json:"createdAt" yaml:"createdAt"`
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
	ID               int64  `json:"id,string" yaml:"id"`
	BillingAccountID int64  `json:"billingAccountId,string" yaml:"billingAccountId"`
	Number           string `json:"number" yaml:"number"`
	// ReceiptNumber is the receipt's own running number (DPLY-RC-YYYYMM-NNNN),
	// assigned when the invoice is marked paid and independent of Number. It is
	// what the receipt / tax-invoice PDF carries as its document number; empty
	// until the invoice is paid.
	ReceiptNumber string    `json:"receiptNumber" yaml:"receiptNumber"`
	Currency      string    `json:"currency" yaml:"currency"`
	PeriodStart   time.Time `json:"periodStart" yaml:"periodStart"`
	PeriodEnd     time.Time `json:"periodEnd" yaml:"periodEnd"`
	Subtotal      float64   `json:"subtotal" yaml:"subtotal"`
	TaxRate       float64   `json:"taxRate" yaml:"taxRate"`
	TaxAmount     float64   `json:"taxAmount" yaml:"taxAmount"`
	Total         float64   `json:"total" yaml:"total"`
	Status        string    `json:"status" yaml:"status"`
	TaxID         string    `json:"taxId" yaml:"taxId"`
	TaxName       string    `json:"taxName" yaml:"taxName"`
	TaxAddress    string    `json:"taxAddress" yaml:"taxAddress"`
	// TaxEntityType is the buyer's entity type (individual|company) snapshotted
	// from the billing account at issue time. A "company" prints the Head Office
	// (สำนักงานใหญ่) branch designation on the tax document; empty/individual does
	// not.
	TaxEntityType string    `json:"taxEntityType" yaml:"taxEntityType"`
	IssuedAt      time.Time `json:"issuedAt" yaml:"issuedAt"`
	PaidAt        time.Time `json:"paidAt" yaml:"paidAt"`
	VoidedAt      time.Time `json:"voidedAt" yaml:"voidedAt"`
	CreatedAt     time.Time `json:"createdAt" yaml:"createdAt"`

	LineItems []*InvoiceLineItem `json:"lineItems" yaml:"lineItems"`

	// Payment is how a customer settles this invoice — the seller's bank-transfer
	// and PromptPay details. These are static seller facts (identical on every
	// invoice), surfaced here so a client can show "how to pay" without rendering
	// the PDF. The server is the single source of truth.
	Payment InvoicePayment `json:"payment" yaml:"payment"`
}

// InvoicePayment is the seller's settlement details shown on an invoice: where
// to send a bank transfer and the PromptPay handle. It is static company info,
// not per-invoice data, so the same values appear on every invoice.
type InvoicePayment struct {
	Bank        string `json:"bank" yaml:"bank"`
	AccountName string `json:"accountName" yaml:"accountName"`
	AccountNo   string `json:"accountNo" yaml:"accountNo"`
	PromptPay   string `json:"promptPay" yaml:"promptPay"`
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

// BillingMember is an invited (non-owner) user on a billing account.
type BillingMember struct {
	Email string `json:"email" yaml:"email"`
	// Role is the member's role: "admin" or "accountant".
	Role      string    `json:"role" yaml:"role"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	// CreatedBy is the email of whoever added the member (attribution).
	CreatedBy string `json:"createdBy" yaml:"createdBy"`
}

type BillingMemberList struct {
	ID int64 `json:"id,string" yaml:"id"` // billing account id
}

func (m *BillingMemberList) Valid() error {
	v := validator.New()

	v.Must(m.ID > 0, "id required")

	return WrapValidate(v)
}

type BillingMemberListResult struct {
	// Owner is the account's owner email — the implicit "owner" role, listed
	// alongside members so a client can render the full access list.
	Owner string           `json:"owner" yaml:"owner"`
	Items []*BillingMember `json:"items" yaml:"items"`
}

type BillingMemberAdd struct {
	ID    int64  `json:"id,string" yaml:"id"` // billing account id
	Email string `json:"email" yaml:"email"`
	Role  string `json:"role" yaml:"role"` // "admin" or "accountant"
}

func (m *BillingMemberAdd) Valid() error {
	// Canonicalize to lower-case: the invitee is matched against the email their
	// identity provider hands us (canonical lower-case), so a mixed-case invite
	// like "Bob@Example.com" must resolve to the same member row, not lock them out.
	m.Email = strings.ToLower(strings.TrimSpace(m.Email))
	m.Role = strings.TrimSpace(m.Role)

	v := validator.New()

	v.Must(m.ID > 0, "id required")
	v.Must(m.Email != "", "email required")
	// IsEmail also rejects allUsers / allAuthenticatedUsers: billing is money,
	// so a member must be a real, addressable identity — no public principals.
	v.Must(govalidator.IsEmail(m.Email), "email invalid")
	v.Must(IsValidBillingMemberRole(m.Role), "role must be admin or accountant")

	return WrapValidate(v)
}

type BillingMemberRemove struct {
	ID    int64  `json:"id,string" yaml:"id"` // billing account id
	Email string `json:"email" yaml:"email"`
}

func (m *BillingMemberRemove) Valid() error {
	// Match the canonicalization AddMember applies, so a member added as
	// "Bob@Example.com" (stored lower-case) can be removed by any casing.
	m.Email = strings.ToLower(strings.TrimSpace(m.Email))

	v := validator.New()

	v.Must(m.ID > 0, "id required")
	v.Must(m.Email != "", "email required")

	return WrapValidate(v)
}
