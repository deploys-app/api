package api

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func validMetricSourceSet() *MetricSourceSet {
	return &MetricSourceSet{
		Project:    "p",
		Name:       "web",
		Location:   "gke.cluster-rcf2",
		Deployment: "web",
		Port:       9090,
		Path:       "/metrics",
	}
}

func TestMetricSourceSetValid(t *testing.T) {
	if err := validMetricSourceSet().Valid(); err != nil {
		t.Fatalf("a valid set was rejected: %v", err)
	}

	def := validMetricSourceSet()
	def.Path = ""
	if err := def.Valid(); err != nil {
		t.Fatalf("empty path was rejected: %v", err)
	}
	if def.Path != "/metrics" {
		t.Fatalf("empty path must default to /metrics, got %q", def.Path)
	}

	cases := []struct {
		name   string
		mutate func(*MetricSourceSet)
		want   string
	}{
		{"missing project", func(m *MetricSourceSet) { m.Project = "" }, "project required"},
		{"bad name", func(m *MetricSourceSet) { m.Name = "Bad Name" }, "name invalid"},
		{"missing location", func(m *MetricSourceSet) { m.Location = "" }, "location required"},
		{"bad deployment", func(m *MetricSourceSet) { m.Deployment = "Bad Name" }, "deployment invalid"},
		{"missing deployment", func(m *MetricSourceSet) { m.Deployment = "" }, "deployment invalid"},
		{"port zero", func(m *MetricSourceSet) { m.Port = 0 }, "port must be between 1 and 65535"},
		{"port too large", func(m *MetricSourceSet) { m.Port = 65536 }, "port must be between 1 and 65535"},
		{"url path", func(m *MetricSourceSet) { m.Path = "http://evil.example/metrics" }, "path"},
		{"path without leading slash", func(m *MetricSourceSet) { m.Path = "metrics" }, "path must start with /"},
		{"path with scheme", func(m *MetricSourceSet) { m.Path = "/metrics://foo" }, "path must not contain a URL"},
		{"protocol-relative path", func(m *MetricSourceSet) { m.Path = "//evil.example/metrics" }, "path must not contain a host"},
		{"path too long", func(m *MetricSourceSet) { m.Path = "/" + strings.Repeat("a", MetricSourceMaxPath) }, "path must not exceed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validMetricSourceSet()
			tc.mutate(m)
			err := m.Valid()
			if err == nil {
				t.Fatalf("expected a validation error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error to contain %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestMetricSourceSetHasNoURLField(t *testing.T) {
	assertNoURLField(t, reflect.TypeFor[MetricSourceSet]())
	assertNoURLField(t, reflect.TypeFor[MetricSourceItem]())
	assertNoURLField(t, reflect.TypeFor[MetricSourceGet]())
	assertNoURLField(t, reflect.TypeFor[MetricSourceQuery]())
}

func assertNoURLField(t *testing.T, tpe reflect.Type) {
	t.Helper()
	for i := range tpe.NumField() {
		f := tpe.Field(i)
		name := strings.ToLower(f.Name)
		jsonTag := strings.ToLower(f.Tag.Get("json"))
		yamlTag := strings.ToLower(f.Tag.Get("yaml"))
		if strings.Contains(name, "url") || strings.HasPrefix(jsonTag, "url") || strings.HasPrefix(yamlTag, "url") {
			t.Fatalf("%s must not have a URL field (SSRF bound); found %s %s", tpe.Name(), f.Name, f.Tag)
		}
	}
}

func TestMetricSourceGetDeleteValid(t *testing.T) {
	get := &MetricSourceGet{Project: "p", Name: "web"}
	if err := get.Valid(); err != nil {
		t.Fatalf("valid MetricSourceGet rejected: %v", err)
	}
	get.Project = ""
	if err := get.Valid(); err == nil || !strings.Contains(err.Error(), "project required") {
		t.Fatalf("expected project required, got: %v", err)
	}

	del := &MetricSourceDelete{Project: "p", Name: "web"}
	if err := del.Valid(); err != nil {
		t.Fatalf("valid MetricSourceDelete rejected: %v", err)
	}
	del.Name = "Bad Name"
	if err := del.Valid(); err == nil || !strings.Contains(err.Error(), "name invalid") {
		t.Fatalf("expected name invalid, got: %v", err)
	}
}

func TestMetricSourceListValid(t *testing.T) {
	list := &MetricSourceList{Project: "p"}
	if err := list.Valid(); err != nil {
		t.Fatalf("valid MetricSourceList rejected: %v", err)
	}
	list.Project = ""
	if err := list.Valid(); err == nil || !strings.Contains(err.Error(), "project required") {
		t.Fatalf("expected project required, got: %v", err)
	}
}

func TestMetricSourceSeriesValid(t *testing.T) {
	m := &MetricSourceSeries{Project: "p", Name: "web"}
	if err := m.Valid(); err != nil {
		t.Fatalf("valid MetricSourceSeries rejected: %v", err)
	}
	m.Name = ""
	if err := m.Valid(); err == nil || !strings.Contains(err.Error(), "name invalid") {
		t.Fatalf("expected name invalid, got: %v", err)
	}
}

func TestMetricSourceQueryValid(t *testing.T) {
	m := &MetricSourceQuery{Project: "p", Name: "web", TimeRange: MetricSourceQueryTimeRange1h}
	if err := m.Valid(); err != nil {
		t.Fatalf("valid query with empty series was rejected: %v", err)
	}

	m = &MetricSourceQuery{
		Project:   "p",
		Name:      "web",
		Series:    []string{`queue_depth{queue="email"}`},
		TimeRange: MetricSourceQueryTimeRange7d,
	}
	if err := m.Valid(); err != nil {
		t.Fatalf("valid query was rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*MetricSourceQuery)
		want   string
	}{
		{"missing project", func(q *MetricSourceQuery) { q.Project = "" }, "project required"},
		{"missing timeRange", func(q *MetricSourceQuery) { q.TimeRange = "" }, "timeRange invalid"},
		{"deployment agg range", func(q *MetricSourceQuery) { q.TimeRange = "1hagg" }, "timeRange invalid"},
		{"disk 2d range", func(q *MetricSourceQuery) { q.TimeRange = "2d" }, "timeRange invalid"},
		{"empty series entry", func(q *MetricSourceQuery) { q.Series = []string{""} }, "series must not be empty"},
		{"too many series", func(q *MetricSourceQuery) {
			q.Series = make([]string, MetricSourceMaxSeries+1)
			for i := range q.Series {
				q.Series[i] = "s"
			}
		}, "series must not exceed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := &MetricSourceQuery{Project: "p", Name: "web", TimeRange: MetricSourceQueryTimeRange1h}
			tc.mutate(q)
			err := q.Valid()
			if err == nil {
				t.Fatalf("expected a validation error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error to contain %q, got: %v", tc.want, err)
			}
		})
	}
}

func TestMetricSourceQueryResultReusesDeploymentMetricsLine(t *testing.T) {
	f, ok := reflect.TypeFor[MetricSourceQueryResult]().FieldByName("Items")
	if !ok {
		t.Fatal("Items field missing")
	}
	want := reflect.TypeFor[[]*DeploymentMetricsLine]()
	if f.Type != want {
		t.Fatalf("Items type = %s, want %s", f.Type, want)
	}
}

func TestMetricSourcePermissionsInCatalog(t *testing.T) {
	perms := Permissions()
	for _, want := range []string{"metricSource.*", "metricSource.set", "metricSource.get", "metricSource.list", "metricSource.delete"} {
		if !slices.Contains(perms, want) {
			t.Fatalf("permission catalog is missing %q", want)
		}
	}
}

func TestMetricSourcePublicBindable(t *testing.T) {
	for _, p := range []string{"metricSource.get", "metricSource.list"} {
		if !IsPublicBindablePermission(p) {
			t.Fatalf("%s should be public-bindable", p)
		}
	}
	for _, p := range []string{"metricSource.set", "metricSource.delete", "metricSource.*", "*"} {
		if IsPublicBindablePermission(p) {
			t.Fatalf("%s must not be public-bindable", p)
		}
	}
}

func TestMetricSourceDelegatable(t *testing.T) {
	for _, p := range []string{"metricSource.set", "metricSource.get", "metricSource.list", "metricSource.delete"} {
		if !IsDelegatablePermission(p) {
			t.Fatalf("%s should be delegatable", p)
		}
	}
	if IsDelegatablePermission("metricSource.*") {
		t.Fatal("metricSource.* must not be delegatable (wildcard)")
	}
}

func TestMetricSourceEventsInCatalog(t *testing.T) {
	events := NotificationEvents()
	for _, want := range []string{"metricSource.set", "metricSource.delete"} {
		if !slices.Contains(events, want) {
			t.Fatalf("notification event catalog is missing %q", want)
		}
	}
}

func TestMetricSourceStatus(t *testing.T) {
	m := &MetricSourceItem{}
	if got := metricSourceStatus(m); got != "ok" {
		t.Fatalf("status = %q, want ok", got)
	}
	m.Truncated = true
	if got := metricSourceStatus(m); got != "truncated" {
		t.Fatalf("truncated status = %q, want truncated", got)
	}
	m.LastError = "timeout"
	if got := metricSourceStatus(m); got != "error" {
		t.Fatalf("error status = %q, want error", got)
	}
	m.Disabled = true
	if got := metricSourceStatus(m); got != "disabled" {
		t.Fatalf("disabled status = %q, want disabled", got)
	}
}
