package api

// UsageMetricsLine is a single named series of [unixSecond, value] points.
// It is shared by the daily usage-metrics RPCs (dropbox.metrics, registry.metrics).
type UsageMetricsLine struct {
	Name   string       `json:"name" yaml:"name"`
	Points [][2]float64 `json:"points" yaml:"points"`
}

// UsageMetricsTimeRange selects the trailing daily window for a usage-metrics query.
type UsageMetricsTimeRange string

const (
	UsageMetricsTimeRange7d  UsageMetricsTimeRange = "7d"
	UsageMetricsTimeRange30d UsageMetricsTimeRange = "30d"
	UsageMetricsTimeRange90d UsageMetricsTimeRange = "90d"
)

var validUsageMetricsTimeRange = map[UsageMetricsTimeRange]bool{
	UsageMetricsTimeRange7d:  true,
	UsageMetricsTimeRange30d: true,
	UsageMetricsTimeRange90d: true,
}

// Days returns the number of days the range covers.
func (t UsageMetricsTimeRange) Days() int {
	switch t {
	case UsageMetricsTimeRange7d:
		return 7
	case UsageMetricsTimeRange90d:
		return 90
	default:
		return 30
	}
}
