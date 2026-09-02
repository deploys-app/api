package api

import (
	"cmp"
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

// MetricSource manages a project's Prometheus scrape sources: the platform
// scrapes a path on the project's own deployment (port+path, never a free-form
// URL) once a minute from the in-cluster collector, stores a capped set of
// series, and serves them for charts and custom alert rules.
//
// A source is project-scoped and addressed by (project, name); Location lives
// in the config (like Alert). Set is a full upsert (cache.set style): the first
// Set of a name creates the source, subsequent Sets of the same name replace
// the config. The per-project cap (MetricSourceMaxPerProject) is server-enforced
// when creating a new name — Valid() does not count existing sources.
//
// The scrape target is (Deployment, Port, Path) resolved by apiserver to
// http://<kubeName>.<project-ns>:port/path. There is no URL field on this
// resource; Path must be a path (leading slash, no host, no ://). That is the
// v1 SSRF bound.
type MetricSource interface {
	// Set upserts a scrape source. Requires the `metricSource.set` permission.
	Set(ctx context.Context, m *MetricSourceSet) (*Empty, error)
	// Get requires the `metricSource.get` permission.
	Get(ctx context.Context, m *MetricSourceGet) (*MetricSourceItem, error)
	// List requires the `metricSource.list` permission.
	List(ctx context.Context, m *MetricSourceList) (*MetricSourceListResult, error)
	// Delete requires the `metricSource.delete` permission.
	Delete(ctx context.Context, m *MetricSourceDelete) (*Empty, error)
	// Series lists discovered series for a source (name{sortedLabels}, type,
	// last seen). Requires the `metricSource.get` permission.
	Series(ctx context.Context, m *MetricSourceSeries) (*MetricSourceSeriesResult, error)
	// Query returns chart data in the DeploymentMetricsLine shape. Requires
	// the `metricSource.get` permission.
	Query(ctx context.Context, m *MetricSourceQuery) (*MetricSourceQueryResult, error)
}

// Discovered series types stored for a scrape source. Histograms/summaries are
// not kept in v1 (only gauge, counter, and untyped).
const (
	MetricSourceSeriesTypeGauge   = "gauge"
	MetricSourceSeriesTypeCounter = "counter"
	MetricSourceSeriesTypeUntyped = "untyped"
)

// Query time-range vocabulary: the waf/cache short windows (not deployment
// 1hagg). Required on MetricSourceQuery.
const (
	MetricSourceQueryTimeRange1h  = "1h"
	MetricSourceQueryTimeRange6h  = "6h"
	MetricSourceQueryTimeRange12h = "12h"
	MetricSourceQueryTimeRange1d  = "1d"
	MetricSourceQueryTimeRange7d  = "7d"
	MetricSourceQueryTimeRange30d = "30d"
)

var validMetricSourceQueryTimeRange = map[string]bool{
	MetricSourceQueryTimeRange1h:  true,
	MetricSourceQueryTimeRange6h:  true,
	MetricSourceQueryTimeRange12h: true,
	MetricSourceQueryTimeRange1d:  true,
	MetricSourceQueryTimeRange7d:  true,
	MetricSourceQueryTimeRange30d: true,
}

func validMetricSourceName(v *validator.Validator, name string) {
	v.Must(ReValidName.MatchString(name), "name invalid: "+ReValidNameDesc)
	cnt := utf8.RuneCountInString(name)
	v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
}

func validMetricSourceDeployment(v *validator.Validator, name string) {
	v.Must(ReValidName.MatchString(name), "deployment invalid: "+ReValidNameDesc)
	cnt := utf8.RuneCountInString(name)
	v.Mustf(cnt >= MinNameLength && cnt <= DeploymentMaxNameLength, "deployment must have length between %d-%d characters", MinNameLength, DeploymentMaxNameLength)
}

// validMetricSourcePath is the SSRF bound: Path is a path, never a URL.
func validMetricSourcePath(v *validator.Validator, path string) {
	v.Must(!strings.Contains(path, "://"), "path must not contain a URL")
	v.Must(strings.HasPrefix(path, "/"), "path must start with /")
	cnt := utf8.RuneCountInString(path)
	v.Mustf(cnt <= MetricSourceMaxPath, "path must not exceed %d characters", MetricSourceMaxPath)
	u, err := url.Parse(path)
	if err != nil {
		v.Must(false, "path invalid")
		return
	}
	v.Must(u.Scheme == "" && u.Host == "", "path must not contain a host")
}

// MetricSourceSet upserts a scrape source. Path defaults to "/metrics" when
// empty. There is no URL field — the platform resolves (deployment, port, path)
// to the in-cluster scrape URL.
type MetricSourceSet struct {
	Project    string `json:"project" yaml:"project"`
	Name       string `json:"name" yaml:"name"`
	Location   string `json:"location" yaml:"location"`
	Deployment string `json:"deployment" yaml:"deployment"`
	Port       int    `json:"port" yaml:"port"`
	Path       string `json:"path" yaml:"path"`
	Disabled   bool   `json:"disabled" yaml:"disabled"`
}

func (m *MetricSourceSet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Location = strings.TrimSpace(m.Location)
	m.Deployment = strings.TrimSpace(m.Deployment)
	m.Path = cmp.Or(strings.TrimSpace(m.Path), "/metrics")

	v := validator.New()
	v.Must(m.Project != "", "project required")
	validMetricSourceName(v, m.Name)
	v.Must(m.Location != "", "location required")
	validMetricSourceDeployment(v, m.Deployment)
	v.Must(m.Port >= 1 && m.Port <= 65535, "port must be between 1 and 65535")
	validMetricSourcePath(v, m.Path)

	return WrapValidate(v)
}

type MetricSourceGet struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *MetricSourceGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validMetricSourceName(v, m.Name)
	return WrapValidate(v)
}

type MetricSourceDelete struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *MetricSourceDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validMetricSourceName(v, m.Name)
	return WrapValidate(v)
}

type MetricSourceList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *MetricSourceList) Valid() error {
	v := validator.New()
	v.Must(m.Project != "", "project required")
	return WrapValidate(v)
}

type MetricSourceSeries struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *MetricSourceSeries) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validMetricSourceName(v, m.Name)
	return WrapValidate(v)
}

// MetricSourceQuery returns chart data for a source. Series empty means the
// server picks the top N by last-seen. TimeRange is required (1h/6h/12h/1d/7d/30d).
type MetricSourceQuery struct {
	Project   string   `json:"project" yaml:"project"`
	Name      string   `json:"name" yaml:"name"`
	Series    []string `json:"series" yaml:"series"`
	TimeRange string   `json:"timeRange" yaml:"timeRange"`
}

func (m *MetricSourceQuery) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	v := validator.New()
	v.Must(m.Project != "", "project required")
	validMetricSourceName(v, m.Name)
	v.Must(validMetricSourceQueryTimeRange[m.TimeRange], "timeRange invalid")
	v.Mustf(len(m.Series) <= MetricSourceMaxSeries, "series must not exceed %d entries", MetricSourceMaxSeries)
	for i, s := range m.Series {
		m.Series[i] = strings.TrimSpace(s)
		v.Must(m.Series[i] != "", "series must not be empty")
		v.Mustf(utf8.RuneCountInString(m.Series[i]) <= MetricSourceMaxSeriesKey, "series must not exceed %d characters", MetricSourceMaxSeriesKey)
	}
	return WrapValidate(v)
}

type MetricSourceItem struct {
	Project       string     `json:"project" yaml:"project"`
	Name          string     `json:"name" yaml:"name"`
	Location      string     `json:"location" yaml:"location"`
	Deployment    string     `json:"deployment" yaml:"deployment"`
	Port          int        `json:"port" yaml:"port"`
	Path          string     `json:"path" yaml:"path"`
	Disabled      bool       `json:"disabled" yaml:"disabled"`
	Truncated     bool       `json:"truncated" yaml:"truncated"`
	LastScrapedAt *time.Time `json:"lastScrapedAt" yaml:"lastScrapedAt"`
	LastError     string     `json:"lastError" yaml:"lastError"`
	CreatedAt     time.Time  `json:"createdAt" yaml:"createdAt"`
	CreatedBy     string     `json:"createdBy" yaml:"createdBy"`
	UpdatedAt     time.Time  `json:"updatedAt" yaml:"updatedAt"`
	UpdatedBy     string     `json:"updatedBy" yaml:"updatedBy"`
}

func metricSourceStatus(x *MetricSourceItem) string {
	if x.Disabled {
		return "disabled"
	}
	if x.LastError != "" {
		return "error"
	}
	if x.Truncated {
		return "truncated"
	}
	return "ok"
}

func metricSourceRow(x *MetricSourceItem) []string {
	return []string{
		x.Name,
		x.Location,
		x.Deployment,
		strconv.Itoa(x.Port),
		x.Path,
		metricSourceStatus(x),
	}
}

func (m *MetricSourceItem) Table() [][]string {
	return [][]string{
		{"NAME", "LOCATION", "DEPLOYMENT", "PORT", "PATH", "STATUS"},
		metricSourceRow(m),
	}
}

type MetricSourceListResult struct {
	Project string              `json:"project" yaml:"project"`
	Items   []*MetricSourceItem `json:"items" yaml:"items"`
}

func (m *MetricSourceListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "LOCATION", "DEPLOYMENT", "PORT", "PATH", "STATUS"},
	}
	for _, x := range m.Items {
		table = append(table, metricSourceRow(x))
	}
	return table
}

type MetricSourceSeriesItem struct {
	Series     string    `json:"series" yaml:"series"` // name{sortedLabels}
	Type       string    `json:"type" yaml:"type"`     // gauge|counter|untyped
	LastSeenAt time.Time `json:"lastSeenAt" yaml:"lastSeenAt"`
}

type MetricSourceSeriesResult struct {
	Project string                    `json:"project" yaml:"project"`
	Name    string                    `json:"name" yaml:"name"`
	Items   []*MetricSourceSeriesItem `json:"items" yaml:"items"`
}

// MetricSourceQueryResult reuses DeploymentMetricsLine so Chart.svelte consumes
// it unmodified.
type MetricSourceQueryResult struct {
	Items []*DeploymentMetricsLine `json:"items" yaml:"items"`
}
