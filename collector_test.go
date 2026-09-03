package api

import (
	"reflect"
	"strings"
	"testing"
)

func TestCollectorListMetricSourcesHasNoURLField(t *testing.T) {
	tpe := reflect.TypeFor[CollectorListMetricSources]()
	for i := range tpe.NumField() {
		f := tpe.Field(i)
		name := strings.ToLower(f.Name)
		jsonTag := strings.ToLower(f.Tag.Get("json"))
		yamlTag := strings.ToLower(f.Tag.Get("yaml"))
		if strings.Contains(name, "url") || strings.HasPrefix(jsonTag, "url") || strings.HasPrefix(yamlTag, "url") {
			t.Fatalf("CollectorListMetricSources must not have a URL field (SSRF bound); found %s %s", f.Name, f.Tag)
		}
	}
}

func TestCollectorListMetricSourcesValid(t *testing.T) {
	m := &CollectorListMetricSources{}
	err := m.Valid()
	if err == nil || !strings.Contains(err.Error(), "location required") {
		t.Fatalf("expected location required, got: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "url") {
		t.Fatalf("Valid must not mention url, got: %v", err)
	}

	m.Location = "gke.cluster-rcf2"
	if err := m.Valid(); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestCollectorSetCustomUsageValid(t *testing.T) {
	empty := &CollectorSetCustomUsage{Location: "gke.cluster-rcf2"}
	if err := empty.Valid(); err != nil {
		t.Fatalf("empty list was rejected: %v", err)
	}

	withItems := &CollectorSetCustomUsage{
		Location: "gke.cluster-rcf2",
		List: []*CollectorCustomUsageItem{
			{ProjectID: 1, SourceID: 2, Series: "jobs_total", Type: MetricSourceSeriesTypeCounter, Value: 3, At: 4},
		},
	}
	if err := withItems.Valid(); err != nil {
		t.Fatalf("valid setCustomUsage was rejected: %v", err)
	}

	missing := &CollectorSetCustomUsage{}
	if err := missing.Valid(); err == nil || !strings.Contains(err.Error(), "location required") {
		t.Fatalf("expected location required, got: %v", err)
	}

	flagged := &CollectorSetCustomUsage{
		Location:  "gke.cluster-rcf2",
		Truncated: true,
		LastError: "timeout",
	}
	if err := flagged.Valid(); err != nil {
		t.Fatalf("truncated/error report was rejected: %v", err)
	}
}
