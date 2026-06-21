package api

import (
	"context"
	"mime/multipart"
	"slices"
	"strconv"
	"strings"
	"time"

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
	// project). Intended for handing a narrowly-scoped credential to an automated
	// agent — e.g. to upload a file to dropbox — without exposing a full token.
	GenerateToken(ctx context.Context, m *MeGenerateToken) (*MeGenerateTokenResult, error)
	// UploadKYCDocument requires authentication only (no specific permission; the caller uploads their own KYC document).
	UploadKYCDocument(ctx context.Context, m *MeUploadKYCDocument) (*MeUploadKYCDocumentResult, error)
}

// GenerateTokenPermissions is the closed set of permissions a me.generateToken
// token may carry. It is intentionally restricted to the agent flows that need a
// scoped, short-lived credential — the no-CLI upload flow (host an archive in
// dropbox, then publish it), the read-only observability flow (read a
// deployment's status and logs), and direct error reporting (an app reports its
// own errors via error.create, optionally reading them back) — rather than
// allowing an arbitrary downscope of the caller's permissions. Extend it as new
// agent flows need it.
var GenerateTokenPermissions = []string{
	"dropbox.upload",
	"site.publish",
	"deployment.get",
	"deployment.logs",
	"error.create",
	"error.list",
	"error.get",
}

// MeGenerateToken requests a scoped, short-lived token. Permissions must be a
// subset of GenerateTokenPermissions, and the caller must already hold each on
// Project. TTLSeconds defaults to 900 (15m) and is clamped to [60, 3600].
type MeGenerateToken struct {
	Project     string   `json:"project" yaml:"project"`
	Permissions []string `json:"permissions" yaml:"permissions"`
	TTLSeconds  int      `json:"ttlSeconds" yaml:"ttlSeconds"`
}

func (m *MeGenerateToken) Valid() error {
	if m.TTLSeconds == 0 {
		m.TTLSeconds = 900
	}

	v := validator.New()
	v.Must(m.Project != "", "project required")
	v.Must(len(m.Permissions) > 0, "permissions required")
	for _, p := range m.Permissions {
		v.Mustf(slices.Contains(GenerateTokenPermissions, p),
			"permission %q is not allowed for generated tokens (allowed: %s)", p, strings.Join(GenerateTokenPermissions, ", "))
	}
	v.Must(m.TTLSeconds >= 60 && m.TTLSeconds <= 3600, "ttlSeconds must be between 60 and 3600")
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
