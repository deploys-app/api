package api

import (
	"context"
	"mime/multipart"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

type Me interface {
	// Get requires authentication only (no specific permission).
	Get(ctx context.Context, _ *Empty) (*MeItem, error)
	// Authorized requires authentication only (no specific permission).
	Authorized(ctx context.Context, m *MeAuthorized) (*MeAuthorizedResult, error)
	// Permissions requires authentication only (no specific permission; returns the caller's own effective permissions for a project).
	Permissions(ctx context.Context, m *MePermissions) (*MePermissionsResult, error)
	// GenerateToken mints a short-lived bearer token scoped to a project and a
	// subset of the caller's own permissions. The caller must already hold every
	// requested permission on the project; the minted token is strictly weaker
	// than the caller (it grants only the requested permissions on the requested
	// project). Any permission the caller holds may be delegated except the
	// non-delegatable classes (wildcards, role.*, serviceaccount.key.*,
	// billing.*, pullsecret.get; see IsDelegatablePermission). Intended for
	// handing a narrowly-scoped credential to an automated agent — e.g. to upload
	// a file to dropbox — without exposing a full token. A scoped-token caller is
	// rejected (an agent token cannot mint a further token).
	GenerateToken(ctx context.Context, m *MeGenerateToken) (*MeGenerateTokenResult, error)
	// ListTokens lists the caller's own active (unexpired) scoped tokens for a
	// project. Requires authentication only (you list your own tokens); the token
	// value is never returned. A scoped-token caller is rejected.
	ListTokens(ctx context.Context, m *MeListTokens) (*MeListTokensResult, error)
	// RevokeToken revokes one of the caller's own scoped tokens by its public id.
	// Requires authentication only (you revoke your own tokens). A scoped-token
	// caller is rejected.
	RevokeToken(ctx context.Context, m *MeRevokeToken) (*Empty, error)
	// UploadKYCDocument requires authentication only (no specific permission; the caller uploads their own KYC document).
	UploadKYCDocument(ctx context.Context, m *MeUploadKYCDocument) (*MeUploadKYCDocumentResult, error)
}

// MaxTokenLabelLength caps the optional attribution label on a generated token.
const MaxTokenLabelLength = 64

// ReValidTokenLabelStr matches an optional token label: a short, printable
// attribution string (e.g. "claude-code:pr-42"). It is deliberately
// restrictive — the label is free text used only for attribution/listing, never
// for authorization, so it carries no sensitive material and a tight charset
// keeps it log- and display-safe. Empty is allowed (the label is optional) and
// is handled by the caller, not this pattern.
const ReValidTokenLabelStr = `^[A-Za-z0-9][A-Za-z0-9 ._:/-]*$`

// ReValidTokenLabel validates MeGenerateToken.Label. See ReValidTokenLabelStr.
var ReValidTokenLabel = regexp.MustCompile(ReValidTokenLabelStr)

// MeGenerateToken requests a scoped, short-lived token. The caller must already
// hold each requested permission on Project, and each must be delegatable
// (IsDelegatablePermission) — i.e. not a wildcard or a containment-breaking
// class. TTLSeconds defaults to 900 (15m) and is clamped to [60, 3600]. Label is
// an optional attribution tag for the agent session (e.g. "claude-code:pr-42").
type MeGenerateToken struct {
	Project     string   `json:"project" yaml:"project"`
	Permissions []string `json:"permissions" yaml:"permissions"`
	TTLSeconds  int      `json:"ttlSeconds" yaml:"ttlSeconds"`
	Label       string   `json:"label" yaml:"label"`
}

func (m *MeGenerateToken) Valid() error {
	if m.TTLSeconds == 0 {
		m.TTLSeconds = 900
	}
	m.Label = strings.TrimSpace(m.Label)

	v := validator.New()
	v.Must(m.Project != "", "project required")
	v.Must(len(m.Permissions) > 0, "permissions required")
	for _, p := range m.Permissions {
		v.Mustf(IsDelegatablePermission(p),
			"permission %q cannot be delegated to a generated token", p)
	}
	v.Must(m.TTLSeconds >= 60 && m.TTLSeconds <= 3600, "ttlSeconds must be between 60 and 3600")
	if m.Label != "" {
		v.Mustf(utf8.RuneCountInString(m.Label) <= MaxTokenLabelLength, "label must be at most %d characters", MaxTokenLabelLength)
		v.Must(ReValidTokenLabel.MatchString(m.Label), "label must use letters, numbers, spaces, and ._:/- (starting with a letter or number)")
	}
	return WrapValidate(v)
}

// MeGenerateTokenResult carries the minted token. Token is returned only here
// (it is stored hashed) — capture it from this response.
type MeGenerateTokenResult struct {
	Token       string    `json:"token" yaml:"token"`
	ExpiresAt   time.Time `json:"expiresAt" yaml:"expiresAt"`
	Project     string    `json:"project" yaml:"project"`
	Permissions []string  `json:"permissions" yaml:"permissions"`
}

func (m *MeGenerateTokenResult) Table() [][]string {
	return [][]string{
		{"TOKEN", "EXPIRES AT", "PROJECT", "PERMISSIONS"},
		{m.Token, m.ExpiresAt.Format(time.RFC3339), m.Project, strings.Join(m.Permissions, ",")},
	}
}

// MeListTokens lists the caller's own active scoped tokens for a project.
type MeListTokens struct {
	Project string `json:"project" yaml:"project"`
}

func (m *MeListTokens) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	return WrapValidate(v)
}

// MeTokenItem describes one active scoped token in MeListTokensResult. ID is a
// non-secret public handle for revoke; the token value itself is never listed
// (it is hash-stored and shown only once at mint).
type MeTokenItem struct {
	ID          string    `json:"id" yaml:"id"`
	Label       string    `json:"label" yaml:"label"`
	Permissions []string  `json:"permissions" yaml:"permissions"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
	ExpiresAt   time.Time `json:"expiresAt" yaml:"expiresAt"`
}

// MeListTokensResult is the caller's active scoped tokens for the project.
type MeListTokensResult struct {
	Items []*MeTokenItem `json:"items" yaml:"items"`
}

func (m *MeListTokensResult) Table() [][]string {
	table := [][]string{
		{"ID", "LABEL", "PERMISSIONS", "EXPIRES AT", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.ID,
			x.Label,
			strings.Join(x.Permissions, ","),
			x.ExpiresAt.Format(time.RFC3339),
			age(x.CreatedAt),
		})
	}
	return table
}

// MeRevokeToken revokes one of the caller's own scoped tokens by its public id.
type MeRevokeToken struct {
	Project string `json:"project" yaml:"project"`
	ID      string `json:"id" yaml:"id"`
}

func (m *MeRevokeToken) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "id required")
	return WrapValidate(v)
}

type MeItem struct {
	Email string `json:"email" yaml:"email"`
	KYC   bool   `json:"kyc" yaml:"kyc"`
}

func (m *MeItem) Table() [][]string {
	return [][]string{
		{"EMAIL"},
		{
			m.Email,
		},
	}
}

type MeAuthorized struct {
	ProjectID   int64    `json:"projectId,string" yaml:"projectId"`
	Project     string   `json:"project" yaml:"project"`
	Permissions []string `json:"permissions" yaml:"permissions"`
}

type MeAuthorizedResult struct {
	Authorized bool `json:"authorized" yaml:"authorized"`
	Project    struct {
		ID             int64  `json:"id,string" yaml:"id"`
		Project        string `json:"project" yaml:"project"`
		BillingAccount struct {
			Active bool `json:"active" yaml:"active"`
		} `json:"billingAccount" yaml:"billingAccount"`
	} `json:"project" yaml:"project"`
}

func (m *MeAuthorizedResult) Table() [][]string {
	return [][]string{
		{"AUTHORIZED"},
		{
			strconv.FormatBool(m.Authorized),
		},
	}
}

// MePermissions requests the caller's effective permissions in a project.
type MePermissions struct {
	Project string `json:"project" yaml:"project"`
}

func (m *MePermissions) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	return WrapValidate(v)
}

// MePermissionsResult is the caller's effective permission set for the project.
// Permissions may contain the wildcards "*" (all) and "<resource>.*" (all
// actions on a resource), matching the server's authorization semantics. When
// Admin is true the caller is a platform admin and implicitly holds every
// permission.
type MePermissionsResult struct {
	Permissions []string `json:"permissions" yaml:"permissions"`
	Admin       bool     `json:"admin" yaml:"admin"`
}

func (m *MePermissionsResult) Table() [][]string {
	table := [][]string{
		{"PERMISSION"},
	}
	if m.Admin {
		table = append(table, []string{"* (admin)"})
	}
	for _, p := range m.Permissions {
		table = append(table, []string{p})
	}
	return table
}

type MeUploadKYCDocument struct {
	File *multipart.FileHeader
}

func (m *MeUploadKYCDocument) UnmarshalMultipartForm(v *multipart.Form) error {
	fps, ok := v.File["document"]
	if !ok {
		return nil
	}
	if len(fps) != 1 {
		return nil
	}
	m.File = fps[0]
	return nil
}

type MeUploadKYCDocumentResult struct {
	DocumentID int64 `json:"documentId" yaml:"documentId"`
}
