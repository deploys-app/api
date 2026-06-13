package api

import (
	"context"
	"mime/multipart"
	"strconv"

	"github.com/moonrhythm/validator"
)

type Me interface {
	Get(ctx context.Context, _ *Empty) (*MeItem, error)
	Authorized(ctx context.Context, m *MeAuthorized) (*MeAuthorizedResult, error)
	Permissions(ctx context.Context, m *MePermissions) (*MePermissionsResult, error)
	UploadKYCDocument(ctx context.Context, m *MeUploadKYCDocument) (*MeUploadKYCDocumentResult, error)
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
