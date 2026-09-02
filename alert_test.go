package api

import (
	"math"
	"slices"
	"strings"
	"testing"
)

func TestAlertMetrics(t *testing.T) {
	metrics := AlertMetrics()
	if len(metrics) == 0 {
		t.Fatal("the metric vocabulary must not be empty")
	}
	// AlertMetrics returns a copy — mutating it must not affect the vocabulary.
	metrics[0] = "mutated"
	if AlertMetrics()[0] == "mutated" {
		t.Fatal("AlertMetrics must return a copy")
	}

	for _, want := range []string{AlertMetricCPU, AlertMetricMemory, AlertMetricRequests, AlertMetricEgress} {
		if !slices.Contains(AlertMetrics(), want) {
			t.Fatalf("vocabulary is missing %q", want)
		}
	}
}

func validAlertCreate() *AlertCreate {
	return &AlertCreate{
		Project: "p",
		Name:    "cpu-hot",
		Target:  AlertTarget{Location: "gke.cluster-rcf2", Deployment: "web"},
		Condition: AlertCondition{
			Metric:     AlertMetricCPU,
			Op:         AlertOpGTE,
			Threshold:  90,
			ForMinutes: 10,
		},
	}
}

func TestAlertCreateValid(t *testing.T) {
	if err := validAlertCreate().Valid(); err != nil {
		t.Fatalf("a valid create was rejected: %v", err)
	}

	// op defaults to >= when left empty.
	m := validAlertCreate()
	m.Condition.Op = ""
	if err := m.Valid(); err != nil {
		t.Fatalf("empty op was rejected: %v", err)
	}
	if m.Condition.Op != AlertOpGTE {
		t.Fatalf("empty op must default to %q, got %q", AlertOpGTE, m.Condition.Op)
	}

	// <= is a valid op too.
	lte := validAlertCreate()
	lte.Condition.Op = AlertOpLTE
	if err := lte.Valid(); err != nil {
		t.Fatalf("<= op was rejected: %v", err)
	}

	// every metric in the vocabulary must validate with an in-bounds threshold.
	for _, metric := range AlertMetrics() {
		mm := validAlertCreate()
		mm.Condition.Metric = metric
		mm.Condition.Threshold = 10
		if err := mm.Valid(); err != nil {
			t.Fatalf("metric %q with a valid threshold was rejected: %v", metric, err)
		}
	}

	// renotifyMinutes: 0 (disabled) and any value in range must validate.
	renotify := validAlertCreate()
	renotify.RenotifyMinutes = 0
	if err := renotify.Valid(); err != nil {
		t.Fatalf("renotifyMinutes=0 was rejected: %v", err)
	}
	renotify.RenotifyMinutes = 60
	if err := renotify.Valid(); err != nil {
		t.Fatalf("renotifyMinutes=60 was rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*AlertCreate)
		want   string
	}{
		{"missing project", func(m *AlertCreate) { m.Project = "" }, "project required"},
		{"bad name", func(m *AlertCreate) { m.Name = "Bad Name" }, "name invalid"},
		{"missing target location", func(m *AlertCreate) { m.Target.Location = "" }, "target.location required"},
		{"bad target deployment", func(m *AlertCreate) { m.Target.Deployment = "Bad Name" }, "target.deployment invalid"},
		{"missing target deployment", func(m *AlertCreate) { m.Target.Deployment = "" }, "target.deployment invalid"},
		{"unknown metric", func(m *AlertCreate) { m.Condition.Metric = "disk" }, "condition.metric invalid"},
		{"bad op", func(m *AlertCreate) { m.Condition.Op = "==" }, "condition.op invalid"},
		{"zero threshold", func(m *AlertCreate) { m.Condition.Threshold = 0 }, "threshold must be greater than 0"},
		{"negative threshold", func(m *AlertCreate) { m.Condition.Threshold = -1 }, "threshold must be greater than 0"},
		{"percent threshold too large", func(m *AlertCreate) { m.Condition.Threshold = AlertPercentThresholdMax + 1 }, "must not exceed"},
		{"forMinutes zero", func(m *AlertCreate) { m.Condition.ForMinutes = 0 }, "condition.forMinutes"},
		{"forMinutes too large", func(m *AlertCreate) { m.Condition.ForMinutes = AlertForMinutesMax + 1 }, "condition.forMinutes"},
		{"renotifyMinutes too small", func(m *AlertCreate) { m.RenotifyMinutes = 1 }, "renotifyMinutes"},
		{"renotifyMinutes too large", func(m *AlertCreate) { m.RenotifyMinutes = AlertRenotifyMinutesMax + 1 }, "renotifyMinutes"},
		{"infinite threshold", func(m *AlertCreate) {
			m.Condition.Metric = AlertMetricRequests
			m.Condition.Threshold = math.Inf(1)
		}, "must be finite"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validAlertCreate()
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

// non-percent metrics (requests, egress) allow thresholds above
// AlertPercentThresholdMax — the cap only applies to cpu/memory.
func TestAlertCreateNonPercentMetricAllowsLargeThreshold(t *testing.T) {
	m := validAlertCreate()
	m.Condition.Metric = AlertMetricRequests
	m.Condition.Threshold = AlertPercentThresholdMax + 1
	if err := m.Valid(); err != nil {
		t.Fatalf("a large requests threshold was rejected: %v", err)
	}
}

func TestAlertUpdateValid(t *testing.T) {
	m := &AlertUpdate{
		Project: "p",
		Name:    "cpu-hot",
		Target:  AlertTarget{Location: "gke.cluster-rcf2", Deployment: "web"},
		Condition: AlertCondition{
			Metric:     AlertMetricMemory,
			Threshold:  80,
			ForMinutes: 5,
		},
	}
	if err := m.Valid(); err != nil {
		t.Fatalf("a valid update was rejected: %v", err)
	}
	if m.Condition.Op != AlertOpGTE {
		t.Fatalf("empty op must default to %q, got %q", AlertOpGTE, m.Condition.Op)
	}

	bad := &AlertUpdate{Project: "p", Name: "cpu-hot"}
	if err := bad.Valid(); err == nil {
		t.Fatal("expected an incomplete update to be rejected")
	}
}

func TestAlertGetDeleteValid(t *testing.T) {
	get := &AlertGet{Project: "p", Name: "cpu-hot"}
	if err := get.Valid(); err != nil {
		t.Fatalf("valid AlertGet rejected: %v", err)
	}
	get.Project = ""
	if err := get.Valid(); err == nil || !strings.Contains(err.Error(), "project required") {
		t.Fatalf("expected project required, got: %v", err)
	}

	del := &AlertDelete{Project: "p", Name: "cpu-hot"}
	if err := del.Valid(); err != nil {
		t.Fatalf("valid AlertDelete rejected: %v", err)
	}
	del.Name = "Bad Name"
	if err := del.Valid(); err == nil || !strings.Contains(err.Error(), "name invalid") {
		t.Fatalf("expected name invalid, got: %v", err)
	}
}

func TestAlertListValid(t *testing.T) {
	list := &AlertList{Project: "p"}
	if err := list.Valid(); err != nil {
		t.Fatalf("valid AlertList rejected: %v", err)
	}
	list.Project = ""
	if err := list.Valid(); err == nil || !strings.Contains(err.Error(), "project required") {
		t.Fatalf("expected project required, got: %v", err)
	}
}

func TestAlertEventsValidLimitClamp(t *testing.T) {
	m := &AlertEvents{Project: "p", Name: "cpu-hot"}
	if err := m.Valid(); err != nil {
		t.Fatalf("valid AlertEvents rejected: %v", err)
	}
	if m.Limit != AlertEventsDefaultLimit {
		t.Fatalf("expected default limit %d, got %d", AlertEventsDefaultLimit, m.Limit)
	}

	m = &AlertEvents{Project: "p", Name: "cpu-hot", Limit: AlertEventsMaxLimit + 1000}
	if err := m.Valid(); err != nil {
		t.Fatalf("valid AlertEvents rejected: %v", err)
	}
	if m.Limit != AlertEventsMaxLimit {
		t.Fatalf("expected clamped limit %d, got %d", AlertEventsMaxLimit, m.Limit)
	}

	m = &AlertEvents{Name: "cpu-hot"}
	if err := m.Valid(); err == nil || !strings.Contains(err.Error(), "project required") {
		t.Fatalf("expected project required, got: %v", err)
	}
}

func TestAlertEventsInCatalog(t *testing.T) {
	events := NotificationEvents()
	for _, want := range []string{"alert.create", "alert.update", "alert.delete", "alert.trigger", "alert.resolve"} {
		if !slices.Contains(events, want) {
			t.Fatalf("notification event catalog is missing %q", want)
		}
	}
}

func TestAlertPermissionsInCatalog(t *testing.T) {
	perms := Permissions()
	for _, want := range []string{"alert.*", "alert.create", "alert.update", "alert.get", "alert.list", "alert.delete"} {
		if !slices.Contains(perms, want) {
			t.Fatalf("permission catalog is missing %q", want)
		}
	}
}

func TestAlertPublicBindable(t *testing.T) {
	// nothing secret in the payloads: reads are safe to grant publicly.
	for _, p := range []string{"alert.get", "alert.list"} {
		if !IsPublicBindablePermission(p) {
			t.Fatalf("%s should be public-bindable", p)
		}
	}
	for _, p := range []string{"alert.create", "alert.update", "alert.delete", "alert.*", "*"} {
		if IsPublicBindablePermission(p) {
			t.Fatalf("%s must not be public-bindable", p)
		}
	}
}

func TestAlertDelegatable(t *testing.T) {
	for _, p := range []string{"alert.create", "alert.update", "alert.get", "alert.list", "alert.delete"} {
		if !IsDelegatablePermission(p) {
			t.Fatalf("%s should be delegatable", p)
		}
	}
	if IsDelegatablePermission("alert.*") {
		t.Fatal("alert.* must not be delegatable (wildcard)")
	}
}

func TestAlertItemTableDisabled(t *testing.T) {
	m := &AlertItem{Name: "cpu-hot", Status: AlertStatusFiring, Disabled: true}
	if got := alertStatus(m); got != "disabled" {
		t.Fatalf("disabled rule status = %q, want disabled", got)
	}
	m.Disabled = false
	if got := alertStatus(m); got != AlertStatusFiring {
		t.Fatalf("enabled firing rule status = %q, want %q", got, AlertStatusFiring)
	}
}
