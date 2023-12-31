package api

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

type ServiceAccount interface {
	Create(ctx context.Context, m *ServiceAccountCreate) (*Empty, error)
	Get(ctx context.Context, m *ServiceAccountGet) (*ServiceAccountGetResult, error)
	List(ctx context.Context, m *ServiceAccountList) (*ServiceAccountListResult, error)
	Update(ctx context.Context, m *ServiceAccountUpdate) (*Empty, error)
	Delete(ctx context.Context, m *ServiceAccountDelete) (*Empty, error)
	CreateKey(ctx context.Context, m *ServiceAccountCreateKey) (*Empty, error)
	DeleteKey(ctx context.Context, m *ServiceAccountDeleteKey) (*Empty, error)
}

type ServiceAccountCreate struct {
	Project     string `json:"project" yaml:"project"`
	SID         string `json:"sid" yaml:"sid"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

func (m *ServiceAccountCreate) Valid() error {
	m.SID = strings.TrimSpace(m.SID)
	m.Name = strings.TrimSpace(m.Name)
	m.Description = strings.TrimSpace(m.Description)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	if v.Must(m.SID != "", "sid required") {
		v.Mustf(ReValidSID.MatchString(m.SID), "sid invalid %s", ReValidSIDStr)
		cnt := utf8.RuneCountInString(m.SID)
		v.Must(cnt >= 3 && cnt <= 20, "sid must have length between 3-20 characters")
	}
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= 60, "name must have length between %d-%d characters", MinNameLength, 60)
	}

	return WrapValidate(v)
}

type ServiceAccountUpdate struct {
	Project     string `json:"project" yaml:"project"`
	SID         string `json:"sid" yaml:"sid"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
}

func (m *ServiceAccountUpdate) Valid() error {
	m.SID = strings.TrimSpace(m.SID)
	m.Name = strings.TrimSpace(m.Name)
	m.Description = strings.TrimSpace(m.Description)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	if v.Must(m.SID != "", "sid required") {
		v.Mustf(ReValidSID.MatchString(m.SID), "sid invalid %s", ReValidSIDStr)
		cnt := utf8.RuneCountInString(m.SID)
		v.Must(cnt >= 3 && cnt <= 20, "sid must have length between 3-20 characters")
	}
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= 60, "name must have length between %d-%d characters", MinNameLength, 60)
	}

	return WrapValidate(v)
}

type ServiceAccountCreateKey struct {
	Project string `json:"project" yaml:"project"`
	ID      string `json:"id" yaml:"id"` // TODO: sid
}

func (m *ServiceAccountCreateKey) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "service account id required")
	return WrapValidate(v)
}

type ServiceAccountList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *ServiceAccountList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type ServiceAccountListItem struct {
	SID         string    `json:"sid" yaml:"sid"`
	Email       string    `json:"email" yaml:"email"`
	Name        string    `json:"name" yaml:"name"`
	Description string    `json:"description" yaml:"description"`
	CreatedAt   time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy   string    `json:"createdBy" yaml:"createdBy"`
}

type ServiceAccountListResult struct {
	Project string                    `json:"project" yaml:"project"`
	Items   []*ServiceAccountListItem `json:"items" yaml:"items"`
}

func (m *ServiceAccountListResult) Table() [][]string {
	table := [][]string{
		{"ID", "EMAIL", "NAME", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.SID,
			x.Email,
			x.Name,
			age(x.CreatedAt),
		})
	}
	return table
}

type ServiceAccountGet struct {
	Project string `json:"project" yaml:"project"`
	ID      string `json:"id" yaml:"id"` // TODO: sid
}

func (m *ServiceAccountGet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "service account id required")

	return WrapValidate(v)
}

type ServiceAccountGetResult struct {
	SID         string               `json:"sid" yaml:"sid"`
	Project     string               `json:"project" yaml:"project"`
	Email       string               `json:"email" yaml:"email"`
	Name        string               `json:"name" yaml:"name"`
	Description string               `json:"description" yaml:"description"`
	CreatedAt   time.Time            `json:"createdAt" yaml:"createdAt"`
	CreatedBy   string               `json:"createdBy" yaml:"createdBy"`
	Keys        []*ServiceAccountKey `json:"keys" yaml:"keys"`
}

func (m *ServiceAccountGetResult) Table() [][]string {
	table := [][]string{
		{"ID", "EMAIL", "NAME", "AGE"},
		{
			m.SID,
			m.Email,
			m.Name,
			age(m.CreatedAt),
		},
	}
	return table
}

type ServiceAccountKey struct {
	Secret    string    `json:"secret" yaml:"secret"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy string    `json:"createdBy" yaml:"createdBy"`
}

type ServiceAccountDeleteKey struct {
	Project string `json:"project" yaml:"project"`
	ID      string `json:"id" yaml:"id"` // TODO: sid
	Secret  string `json:"secret" yaml:"secret"`
}

func (m *ServiceAccountDeleteKey) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "service account id required")
	v.Must(m.Secret != "", "secret required")

	return WrapValidate(v)
}

type ServiceAccountDelete struct {
	Project string `json:"project" yaml:"project"`
	ID      string `json:"id" yaml:"id"` // TODO: sid
}

func (m *ServiceAccountDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.ID != "", "service account id required")

	return WrapValidate(v)
}
