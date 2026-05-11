package api

import (
	"context"
	"time"

	"github.com/moonrhythm/validator"
)

type Registry interface {
	List(ctx context.Context, m *RegistryList) (*RegistryListResult, error)
	Get(ctx context.Context, m *RegistryGet) (*RegistryRepository, error)
	GetTags(ctx context.Context, m *RegistryGetTags) (*RegistryGetTagsResult, error)
	GetManifests(ctx context.Context, m *RegistryGetManifests) (*RegistryGetManifestsResult, error)
	Delete(ctx context.Context, m *RegistryDelete) (*Empty, error)
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
