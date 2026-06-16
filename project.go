package api

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dustin/go-humanize"
	"github.com/moonrhythm/validator"
)

type Project interface {
	// Create requires authentication only (no specific permission; the new owner role is granted to the creator).
	Create(ctx context.Context, m *ProjectCreate) (*Empty, error)
	// Get requires authentication only (no specific permission; scoped to projects the caller is a member of, or all projects for a platform admin).
	Get(ctx context.Context, m *ProjectGet) (*ProjectItem, error)
	// List requires authentication only (no specific permission; lists the caller's projects, or all projects for a platform admin).
	List(ctx context.Context, m *Empty) (*ProjectListResult, error)
	// Update requires the `*` (owner/wildcard) permission.
	Update(ctx context.Context, m *ProjectUpdate) (*Empty, error)
	// Delete requires the `project.delete` permission.
	Delete(ctx context.Context, m *ProjectDelete) (*Empty, error)
	// Usage requires the `project.get` permission.
	Usage(ctx context.Context, m *ProjectUsage) (*ProjectUsageResult, error)
	// StorageMetrics requires the `project.get` permission.
	StorageMetrics(ctx context.Context, m *ProjectStorageMetrics) (*ProjectStorageMetricsResult, error)
	// Metrics requires the `project.get` permission.
	Metrics(ctx context.Context, m *ProjectMetrics) (*ProjectMetricsResult, error)
}

type ProjectCreate struct {
	SID            string `json:"sid" yaml:"sid"`
	Name           string `json:"name" yaml:"name"`
	BillingAccount int64  `json:"billingAccount,string" yaml:"billingAccount"`
}

var (
	ReValidSIDStr = `^[a-z][a-z0-9\-]*[^\-]$`
	ReValidSID    = regexp.MustCompile(ReValidSIDStr)
)

func (m *ProjectCreate) Valid() error {
	m.SID = strings.TrimSpace(m.SID)
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	if v.Must(m.SID != "", "sid required") {
		v.Mustf(ReValidSID.MatchString(m.SID), "sid invalid %s", ReValidSIDStr)
		cnt := utf8.RuneCountInString(m.SID)
		v.Must(cnt >= 6 && cnt <= 32, "sid must have length between 6-32 characters")
	}

	v.Must(utf8.ValidString(m.Name), "name invalid")
	cnt := utf8.RuneCountInString(m.Name)
	v.Must(cnt >= 4 && cnt <= 64, "name must have length between 4-64 characters")

	v.Must(m.BillingAccount > 0, "billing account required")

	return WrapValidate(v)
}

type ProjectUpdate struct {
	Project        string  `json:"project" yaml:"project"`
	Name           *string `json:"name" yaml:"name"`
	BillingAccount *int64  `json:"billingAccount,string" yaml:"billingAccount"`
}

func (m *ProjectUpdate) Valid() error {
	m.Project = strings.TrimSpace(m.Project)

	v := validator.New()

	v.Must(m.Project != "", "project required")

	if m.Name != nil {
		*m.Name = strings.TrimSpace(*m.Name)
		v.Must(utf8.ValidString(*m.Name), "name invalid")
		cnt := utf8.RuneCountInString(*m.Name)
		v.Must(cnt >= 4 && cnt <= 64, "name must have length between 4-64 characters")
	}

	if m.BillingAccount != nil {
		v.Must(*m.BillingAccount > 0, "billing account invalid")
	}

	return WrapValidate(v)
}

type ProjectGet struct {
	Project string `json:"project" yaml:"project"`
}

type ProjectItem struct {
	ID             int64         `json:"id,string" yaml:"id"`
	Project        string        `json:"project" yaml:"project"`
	Name           string        `json:"name" yaml:"name"`
	BillingAccount int64         `json:"billingAccount,string" yaml:"billingAccount"`
	Quota          ProjectQuota  `json:"quota" yaml:"quota"`
	Config         ProjectConfig `json:"config" yaml:"config"`
	CreatedAt      time.Time     `json:"createdAt" yaml:"createdAt"`
}

func (m *ProjectItem) Table() [][]string {
	return [][]string{
		{"PROJECT", "NAME", "AGE"},
		{
			m.Project,
			m.Name,
			age(m.CreatedAt),
		},
	}
}

type ProjectQuota struct {
	Deployments           int `json:"deployments" yaml:"deployments"`
	DeploymentMaxReplicas int `json:"deploymentMaxReplicas" yaml:"deploymentMaxReplicas"`
}

type ProjectConfig struct {
}

type ProjectListResult struct {
	Items []*ProjectItem `json:"items" yaml:"items"`
}

func (m *ProjectListResult) Table() [][]string {
	table := [][]string{
		{"PROJECT", "NAME", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Project,
			x.Name,
			age(x.CreatedAt),
		})
	}
	return table
}

type ProjectDelete struct {
	Project string `json:"project" yaml:"project"`
}

type ProjectUsage struct {
	Project string `json:"project" yaml:"project"`
}

type ProjectUsageResult struct {
	CPUUsage       float64 `json:"cpuUsage" yaml:"cpuUsage"`
	CPU            float64 `json:"cpu" yaml:"cpu"`
	Memory         float64 `json:"memory" yaml:"memory"`
	Egress         float64 `json:"egress" yaml:"egress"`
	RegistryEgress float64 `json:"registryEgress" yaml:"registryEgress"`
	DropboxEgress  float64 `json:"dropboxEgress" yaml:"dropboxEgress"`
	Disk           float64 `json:"disk" yaml:"disk"`
	Replica        float64 `json:"replica" yaml:"replica"`
	StaticStorage  float64 `json:"staticStorage" yaml:"staticStorage"`
}

func (m *ProjectUsageResult) Table() [][]string {
	table := [][]string{
		{"RESOURCE", "USAGE"},
		{"CPUUsage", humanize.CommafWithDigits(m.CPUUsage, 2)},
		{"CPU", humanize.CommafWithDigits(m.CPU, 2)},
		{"Memory", humanize.CommafWithDigits(m.Memory, 2)},
		{"Egress", humanize.CommafWithDigits(m.Egress, 2)},
		{"RegistryEgress", humanize.CommafWithDigits(m.RegistryEgress, 2)},
		{"DropboxEgress", humanize.CommafWithDigits(m.DropboxEgress, 2)},
		{"Disk", humanize.CommafWithDigits(m.Disk, 2)},
		{"Replica", humanize.CommafWithDigits(m.Replica, 2)},
		{"StaticStorage", humanize.CommafWithDigits(m.StaticStorage, 2)},
	}
	return table
}

// ProjectStorageMetrics requests the daily project-level storage usage series.
type ProjectStorageMetrics struct {
	Project   string                `json:"project" yaml:"project"`
	TimeRange UsageMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *ProjectStorageMetrics) Valid() error {
	if m.Project == "" {
		return newError("project required")
	}
	if m.TimeRange == "" {
		m.TimeRange = UsageMetricsTimeRange30d
	}
	if !validUsageMetricsTimeRange[m.TimeRange] {
		return newError("timeRange invalid")
	}
	return nil
}

// ProjectStorageMetricsResult carries the per-day static-web storage gauge
// (bytes) as a single project-wide series.
type ProjectStorageMetricsResult struct {
	StaticStorage []*UsageMetricsLine `json:"staticStorage" yaml:"staticStorage"`
}

// ProjectMetrics requests the daily project-level usage series for the project
// metrics page (CPU, memory, egress, replicas, static storage).
type ProjectMetrics struct {
	Project   string                `json:"project" yaml:"project"`
	TimeRange UsageMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *ProjectMetrics) Valid() error {
	if m.Project == "" {
		return newError("project required")
	}
	if m.TimeRange == "" {
		m.TimeRange = UsageMetricsTimeRange30d
	}
	if !validUsageMetricsTimeRange[m.TimeRange] {
		return newError("timeRange invalid")
	}
	return nil
}

// ProjectMetricsResult carries daily project-wide usage series. CPUUsage,
// Memory, Disk and Replica are per-second averages for each day (the integrated
// daily quantity divided by seconds/day), so they read as levels (vCPU, bytes,
// replicas). Egress is the day's total bytes (pod + cache + WAF egress folded).
// StaticStorage is the day's storage gauge in bytes.
type ProjectMetricsResult struct {
	CPUUsage      []*UsageMetricsLine `json:"cpuUsage" yaml:"cpuUsage"`
	Memory        []*UsageMetricsLine `json:"memory" yaml:"memory"`
	Disk          []*UsageMetricsLine `json:"disk" yaml:"disk"`
	Egress        []*UsageMetricsLine `json:"egress" yaml:"egress"`
	Replica       []*UsageMetricsLine `json:"replica" yaml:"replica"`
	StaticStorage []*UsageMetricsLine `json:"staticStorage" yaml:"staticStorage"`
}
