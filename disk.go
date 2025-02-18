package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

type Disk interface {
	Create(ctx context.Context, m *DiskCreate) (*Empty, error)
	Get(ctx context.Context, m *DiskGet) (*DiskItem, error)
	List(ctx context.Context, m *DiskList) (*DiskListResult, error)
	Update(ctx context.Context, m *DiskUpdate) (*Empty, error)
	Delete(ctx context.Context, m *DiskDelete) (*Empty, error)
	Metrics(ctx context.Context, m *DiskMetrics) (*DiskMetricsResult, error)
}

type DiskCreate struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
	Size     int64  `json:"size" yaml:"size"`
}

func (m *DiskCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.Size >= 1, "minimum disk size 1 Gi")
	v.Mustf(m.Size <= DiskMaxSize, "maximum disk size %d Gi", DiskMaxSize)

	return WrapValidate(v)
}

type DiskUpdate struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
	Size     int64  `json:"size" yaml:"size"`
}

func (m *DiskUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(m.Size >= 1, "minimum disk size 1 Gi")
	v.Mustf(m.Size <= DiskMaxSize, "maximum disk size %d Gi", DiskMaxSize)

	return WrapValidate(v)
}

type DiskGet struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DiskGet) Valid() error {
	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(m.Name != "", "name required")

	return WrapValidate(v)
}

type DiskList struct {
	Location string `json:"location" yaml:"location"` // optional
	Project  string `json:"project" yaml:"project"`
}

func (m *DiskList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type DiskListResult struct {
	Items []*DiskItem `json:"items" yaml:"items"`
}

func (m *DiskListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "SIZE", "LOCATION", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Name,
			strconv.FormatInt(x.Size, 10) + "Gi",
			x.Location,
			age(x.CreatedAt),
		})
	}
	return table
}

type DiskItem struct {
	Project   string    `json:"project" yaml:"project"`
	Location  string    `json:"location" yaml:"location"`
	Name      string    `json:"name" yaml:"name"`
	Size      int64     `json:"size" yaml:"size"`
	Status    Status    `json:"status" yaml:"status"`
	Action    string    `json:"action" yaml:"action"`
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
	CreatedBy string    `json:"createdBy" yaml:"createdBy"`
	SuccessAt time.Time `json:"successAt" yaml:"successAt"`
}

func (m *DiskItem) Table() [][]string {
	table := [][]string{
		{"NAME", "SIZE", "LOCATION", "AGE"},
		{
			m.Name,
			strconv.FormatInt(m.Size, 10) + "Gi",
			m.Location,
			age(m.CreatedAt),
		},
	}
	return table
}

type DiskDelete struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DiskDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	if cnt := utf8.RuneCountInString(m.Name); cnt > MaxNameLength {
		return fmt.Errorf("name invalid")
	}

	return WrapValidate(v)
}

type DiskMetricsTimeRange string

const (
	DiskMetricsTimeRange1h  = "1h"
	DiskMetricsTimeRange6h  = "6h"
	DiskMetricsTimeRange12h = "12h"
	DiskMetricsTimeRange1d  = "1d"
	DiskMetricsTimeRange2d  = "2d"
	DiskMetricsTimeRange7d  = "7d"
	DiskMetricsTimeRange30d = "30d"
)

var allDiskMetricsTimeRange = []DiskMetricsTimeRange{
	DiskMetricsTimeRange1h,
	DiskMetricsTimeRange6h,
	DiskMetricsTimeRange12h,
	DiskMetricsTimeRange1d,
	DiskMetricsTimeRange2d,
	DiskMetricsTimeRange7d,
	DiskMetricsTimeRange30d,
}

var validDiskMetricsTimeRange = func() map[DiskMetricsTimeRange]bool {
	m := map[DiskMetricsTimeRange]bool{}
	for _, t := range allDiskMetricsTimeRange {
		m[t] = true
	}
	return m
}()

type DiskMetrics struct {
	Location  string               `json:"location" yaml:"location"`
	Project   string               `json:"project" yaml:"project"`
	Name      string               `json:"name" yaml:"name"`
	TimeRange DiskMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *DiskMetrics) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	v.Mustf(utf8.RuneCountInString(m.Name) <= MaxNameLength, "name must have length less then %d characters", MaxNameLength)
	v.Must(m.Project != "", "project required")
	v.Must(validDiskMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

type DiskMetricsResult struct {
	Usage []*DiskMetricsLine `json:"usage" yaml:"usage"`
	Size  []*DiskMetricsLine `json:"size" yaml:"size"`
}

type DiskMetricsLine struct {
	Name   string       `json:"name" yaml:"name"`
	Points [][2]float64 `json:"points" yaml:"points"`
}
