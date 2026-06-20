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
	// GC garbage-collects manifests in the project's repositories that no
	// deployment references (across the current revision and all revision
	// history), by tag or by digest. It requires the `registry.push` permission.
	GC(ctx context.Context, m *RegistryGC) (*RegistryGCResult, error)
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
	Size      int64     `json:"size" yaml:"size"`
	Manifests int64     `json:"manifests" yaml:"manifests"`
	Tags      int64     `json:"tags" yaml:"tags"`
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

type RegistryGC struct {
	Project string `json:"project" yaml:"project"`
	// DryRun reports what would be removed without deleting anything. The API
	// deletes by default (DryRun=false), consistent with registry.delete/untag.
	DryRun bool `json:"dryRun" yaml:"dryRun"`
}

func (m *RegistryGC) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

// RegistryGCRepository is the per-repository breakdown of a GC run.
type RegistryGCRepository struct {
	// Repository is the repository name without the project-namespace prefix.
	Repository string `json:"repository" yaml:"repository"`
	// Manifests are the digests removed (or, in dry-run, that would be removed).
	Manifests []string `json:"manifests" yaml:"manifests"`
	// Tags are the tag names removed because they pointed at a removed manifest.
	Tags []string `json:"tags" yaml:"tags"`
	// Size is the bytes reclaimable in this repository: the size of blobs that
	// become unreferenced once the listed manifests are gone (the registry's
	// blob GC frees them).
	Size int64 `json:"size" yaml:"size"`
}

type RegistryGCResult struct {
	DryRun bool `json:"dryRun" yaml:"dryRun"`
	// RemovedManifests / RemovedTags are project-wide totals.
	RemovedManifests int64 `json:"removedManifests" yaml:"removedManifests"`
	RemovedTags      int64 `json:"removedTags" yaml:"removedTags"`
	// ReclaimedSize is the project-wide total of reclaimable blob bytes.
	ReclaimedSize int64                   `json:"reclaimedSize" yaml:"reclaimedSize"`
	Repositories  []*RegistryGCRepository `json:"repositories" yaml:"repositories"`
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
