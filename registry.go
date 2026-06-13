package api

import (
	"context"
	"time"

	"github.com/moonrhythm/validator"
)

type Registry interface {
	// List requires the `registry.list` permission.
	List(ctx context.Context, m *RegistryList) (*RegistryListResult, error)
	// Get requires the `registry.get` permission.
	Get(ctx context.Context, m *RegistryGet) (*RegistryRepository, error)
	// GetTags requires the `registry.get` permission.
	GetTags(ctx context.Context, m *RegistryGetTags) (*RegistryGetTagsResult, error)
	// GetManifests requires the `registry.get` permission.
	GetManifests(ctx context.Context, m *RegistryGetManifests) (*RegistryGetManifestsResult, error)
	// GetProjectStorage requires the `registry.get` permission.
	GetProjectStorage(ctx context.Context, m *RegistryGetProjectStorage) (*RegistryProjectStorage, error)
	// Delete requires the `registry.push` permission.
	Delete(ctx context.Context, m *RegistryDelete) (*Empty, error)
	// DeleteManifest requires the `registry.push` permission.
	DeleteManifest(ctx context.Context, m *RegistryDeleteManifest) (*Empty, error)
	// Untag requires the `registry.push` permission.
	Untag(ctx context.Context, m *RegistryUntag) (*Empty, error)
	// Metrics requires the `registry.get` permission.
	Metrics(ctx context.Context, m *RegistryMetrics) (*RegistryMetricsResult, error)
}

type RegistryList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *RegistryList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type RegistryListItem struct {
	Name      string    `json:"name" yaml:"name"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
}

type RegistryListResult struct {
	Items []*RegistryListItem `json:"items" yaml:"items"`
}

type RegistryGet struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"`
}

func (m *RegistryGet) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Repository != "", "repository required")

	return WrapValidate(v)
}

type RegistryRepository struct {
	Name      string    `json:"name" yaml:"name"`
	Size      int64     `json:"size" yaml:"size"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
}

type RegistryGetTags struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"`
}

func (m *RegistryGetTags) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Repository != "", "repository required")

	return WrapValidate(v)
}

type RegistryTag struct {
	Tag       string    `json:"tag" yaml:"tag"`
	Digest    string    `json:"digest" yaml:"digest"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
}

type RegistryGetTagsResult struct {
	Name  string         `json:"name" yaml:"name"`
	Items []*RegistryTag `json:"items" yaml:"items"`
}

type RegistryGetManifests struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"`
}

func (m *RegistryGetManifests) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Repository != "", "repository required")

	return WrapValidate(v)
}

type RegistryManifest struct {
	Digest    string    `json:"digest" yaml:"digest"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
}

type RegistryGetManifestsResult struct {
	Name  string              `json:"name" yaml:"name"`
	Items []*RegistryManifest `json:"items" yaml:"items"`
}

type RegistryGetProjectStorage struct {
	Project string `json:"project" yaml:"project"`
}

func (m *RegistryGetProjectStorage) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type RegistryProjectStorage struct {
	Size      int64      `json:"size" yaml:"size"`
	UpdatedAt *time.Time `json:"updatedAt,omitempty" yaml:"updatedAt,omitempty"`
}

type RegistryDelete struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"`
}

func (m *RegistryDelete) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Repository != "", "repository required")

	return WrapValidate(v)
}

type RegistryDeleteManifest struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"`
	Digest     string `json:"digest" yaml:"digest"`
}

func (m *RegistryDeleteManifest) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Repository != "", "repository required")
	v.Must(m.Digest != "", "digest required")

	return WrapValidate(v)
}

type RegistryUntag struct {
	Project    string `json:"project" yaml:"project"`
	Repository string `json:"repository" yaml:"repository"`
	Tag        string `json:"tag" yaml:"tag"`
}

func (m *RegistryUntag) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(m.Repository != "", "repository required")
	v.Must(m.Tag != "", "tag required")

	return WrapValidate(v)
}

type RegistryMetrics struct {
	Project   string                `json:"project" yaml:"project"`
	TimeRange UsageMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *RegistryMetrics) Valid() error {
	if m.TimeRange == "" {
		m.TimeRange = UsageMetricsTimeRange30d
	}

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(validUsageMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

type RegistryMetricsResult struct {
	Egress  []*UsageMetricsLine `json:"egress" yaml:"egress"`
	Storage []*UsageMetricsLine `json:"storage" yaml:"storage"`
}
