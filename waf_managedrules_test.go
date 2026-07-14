package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func validManagedRulesSet() WAFSet {
	return WAFSet{
		Project:  "p",
		Location: "gke",
		ManagedRules: &WAFManagedRules{
			Enabled:          true,
			Mode:             "enforce",
			ParanoiaLevel:    2,
			AnomalyThreshold: 5,
			ExcludedRules:    []int{942100, 920420},
		},
	}
}

func TestWAFSetValidManagedRules(t *testing.T) {
	t.Parallel()

	t.Run("valid cases", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*WAFSet)
		}{
			{"nil block", func(m *WAFSet) { m.ManagedRules = nil }},
			{"full tuning", func(m *WAFSet) {}},
			{"zero defaults", func(m *WAFSet) { m.ManagedRules = &WAFManagedRules{Enabled: true} }},
			{"detect mode", func(m *WAFSet) { m.ManagedRules.Mode = "detect" }},
			// enabled:false with tuning kept must validate — toggling off must
			// not destroy a curated exclusion list (spec §2.2).
			{"disabled with tuning kept", func(m *WAFSet) { m.ManagedRules.Enabled = false }},
			{"bounds", func(m *WAFSet) {
				m.ManagedRules.ParanoiaLevel = 4
				m.ManagedRules.AnomalyThreshold = 100
				m.ManagedRules.ExcludedRules = []int{WAFManagedExcludedRuleIDMin, WAFManagedExcludedRuleIDMax}
			}},
			{"max excluded rules", func(m *WAFSet) {
				ids := make([]int, WAFManagedMaxExcludedRules)
				for i := range ids {
					ids[i] = WAFManagedExcludedRuleIDMin + i
				}
				m.ManagedRules.ExcludedRules = ids
			}},
		}
		for _, tc := range cases {
			m := validManagedRulesSet()
			tc.mutate(&m)
			if err := m.Valid(); err != nil {
				t.Errorf("%s: valid WAFSet rejected: %v", tc.name, err)
			}
		}
	})

	t.Run("invalid cases", func(t *testing.T) {
		cases := []struct {
			name    string
			mutate  func(*WAFSet)
			wantMsg string
		}{
			{"unknown mode", func(m *WAFSet) { m.ManagedRules.Mode = "shadow" }, "mode invalid"},
			{"paranoia too high", func(m *WAFSet) { m.ManagedRules.ParanoiaLevel = 5 }, "paranoiaLevel out of range"},
			{"paranoia negative", func(m *WAFSet) { m.ManagedRules.ParanoiaLevel = -1 }, "paranoiaLevel out of range"},
			{"threshold too high", func(m *WAFSet) { m.ManagedRules.AnomalyThreshold = 101 }, "anomalyThreshold out of range"},
			{"threshold negative", func(m *WAFSet) { m.ManagedRules.AnomalyThreshold = -1 }, "anomalyThreshold out of range"},
			// below the floor: the platform SecActions and CRS setup must be
			// unreachable by exclusion.
			{"excluded platform SecAction", func(m *WAFSet) { m.ManagedRules.ExcludedRules = []int{900000} }, "out of range"},
			{"excluded CRS setup", func(m *WAFSet) { m.ManagedRules.ExcludedRules = []int{901100} }, "out of range"},
			// at/above the ceiling: the blocking-evaluation machinery.
			{"excluded scoring rule", func(m *WAFSet) { m.ManagedRules.ExcludedRules = []int{949110} }, "out of range"},
			{"duplicate excluded rule", func(m *WAFSet) { m.ManagedRules.ExcludedRules = []int{942100, 942100} }, "duplicated"},
			{"too many excluded rules", func(m *WAFSet) {
				ids := make([]int, WAFManagedMaxExcludedRules+1)
				for i := range ids {
					ids[i] = WAFManagedExcludedRuleIDMin + i
				}
				m.ManagedRules.ExcludedRules = ids
			}, "must not exceed"},
			// a disabled block is still fully validated, so garbage tuning can't
			// hide behind enabled:false and explode on re-enable.
			{"disabled block still validated", func(m *WAFSet) {
				m.ManagedRules.Enabled = false
				m.ManagedRules.ParanoiaLevel = 9
			}, "paranoiaLevel out of range"},
		}
		for _, tc := range cases {
			m := validManagedRulesSet()
			tc.mutate(&m)
			err := m.Valid()
			if err == nil {
				t.Errorf("%s: expected rejection", tc.name)
				continue
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("%s: error %q does not contain %q", tc.name, err.Error(), tc.wantMsg)
			}
		}
	})
}

// TestWAFTableCRSColumn guards the on/off/- three-state cell: "off" (disabled
// but tuned) must render distinctly from "-" (never configured), because the
// two states differ in what a re-enable restores.
func TestWAFTableCRSColumn(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		managed *WAFManagedRules
		want    string
	}{
		{"unset", nil, "-"},
		{"enabled", &WAFManagedRules{Enabled: true}, "on"},
		{"disabled with tuning", &WAFManagedRules{ExcludedRules: []int{942100}}, "off"},
	}

	for _, tc := range cases {
		item := WAFItem{Project: "p", Location: "gke", ManagedRules: tc.managed}

		table := item.Table()
		header, row := table[0], table[1]
		if header[4] != "CRS" {
			t.Fatalf("%s: WAFItem header[4] = %q, want CRS", tc.name, header[4])
		}
		if row[4] != tc.want {
			t.Errorf("%s: WAFItem CRS cell = %q, want %q", tc.name, row[4], tc.want)
		}

		list := WAFListResult{Project: "p", Items: []*WAFItem{&item}}
		table = list.Table()
		header, row = table[0], table[1]
		if header[3] != "CRS" {
			t.Fatalf("%s: WAFListResult header[3] = %q, want CRS", tc.name, header[3])
		}
		if row[3] != tc.want {
			t.Errorf("%s: WAFListResult CRS cell = %q, want %q", tc.name, row[3], tc.want)
		}
	}
}

// TestWAFManagedRulesWire pins the wire field names — the console, CLI, MCP,
// apiserver JSONB column, and deployer command all round-trip these exact
// keys, and the deployer's mixed-version guard depends on corazaZoneId
// unmarshaling to "" from old-apiserver commands.
func TestWAFManagedRulesWire(t *testing.T) {
	t.Parallel()

	t.Run("WAFSet round-trip", func(t *testing.T) {
		in := validManagedRulesSet()
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{`"managedRules"`, `"enabled"`, `"mode"`, `"paranoiaLevel"`, `"anomalyThreshold"`, `"excludedRules"`} {
			if !strings.Contains(string(b), key) {
				t.Errorf("marshaled WAFSet missing %s: %s", key, b)
			}
		}
		var out WAFSet
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatal(err)
		}
		if out.ManagedRules == nil || !out.ManagedRules.Enabled || out.ManagedRules.ParanoiaLevel != 2 ||
			out.ManagedRules.Mode != "enforce" || len(out.ManagedRules.ExcludedRules) != 2 {
			t.Errorf("round-trip mismatch: %+v", out.ManagedRules)
		}
	})

	t.Run("item omits unset managed rules", func(t *testing.T) {
		b, err := json.Marshal(WAFItem{Project: "p", Location: "gke"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"managedRules"`) {
			t.Errorf(`unset managedRules must be omitted, not emitted as null: %s`, b)
		}

		b, err = json.Marshal(WAFItem{Project: "p", Location: "gke", ManagedRules: &WAFManagedRules{}})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), `"excludedRules"`) {
			t.Errorf(`empty excludedRules must be omitted, not emitted as null: %s`, b)
		}
		if !strings.Contains(string(b), `"managedRules"`) {
			t.Errorf(`configured managedRules block must be emitted: %s`, b)
		}
	})

	t.Run("old payload leaves field nil", func(t *testing.T) {
		var m WAFSet
		if err := json.Unmarshal([]byte(`{"project":"p","location":"gke","rules":[],"limits":[]}`), &m); err != nil {
			t.Fatal(err)
		}
		if m.ManagedRules != nil {
			t.Errorf("absent managedRules must unmarshal to nil, got %+v", m.ManagedRules)
		}
	})

	t.Run("deployer command", func(t *testing.T) {
		cmd := DeployerCommandWAFSet{
			ID:           1,
			ProjectID:    42,
			ZoneID:       "waf-42",
			CorazaZoneID: "coraza-42",
			ManagedRules: &WAFManagedRules{Enabled: true},
		}
		b, err := json.Marshal(cmd)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{`"corazaZoneId":"coraza-42"`, `"managedRules"`} {
			if !strings.Contains(string(b), key) {
				t.Errorf("marshaled DeployerCommandWAFSet missing %s: %s", key, b)
			}
		}

		var oldSet DeployerCommandWAFSet
		if err := json.Unmarshal([]byte(`{"id":1,"projectId":42,"zoneId":"waf-42","rateLimitZoneId":"ratelimit-42","rules":[],"limits":[]}`), &oldSet); err != nil {
			t.Fatal(err)
		}
		if oldSet.CorazaZoneID != "" || oldSet.ManagedRules != nil {
			t.Errorf("old-apiserver WAFSet command must leave Coraza fields zero, got %q %+v", oldSet.CorazaZoneID, oldSet.ManagedRules)
		}

		var oldDelete DeployerCommandWAFDelete
		if err := json.Unmarshal([]byte(`{"id":1,"projectId":42,"zoneId":"waf-42","rateLimitZoneId":"ratelimit-42"}`), &oldDelete); err != nil {
			t.Fatal(err)
		}
		if oldDelete.CorazaZoneID != "" {
			t.Errorf("old-apiserver WAFDelete command must leave CorazaZoneID empty, got %q", oldDelete.CorazaZoneID)
		}
	})
}

// TestWAFLocationFeatureCompat guards the *struct{} → *WAFLocationFeature
// widening: every stored/legacy `"waf": {}` must keep meaning "WAF supported,
// managed rules off", and absence must stay nil (feature off).
func TestWAFLocationFeatureCompat(t *testing.T) {
	t.Parallel()

	var f LocationFeatures
	if err := json.Unmarshal([]byte(`{"waf":{}}`), &f); err != nil {
		t.Fatal(err)
	}
	if f.WAF == nil {
		t.Fatal(`legacy {"waf":{}} must unmarshal to a non-nil WAF feature`)
	}
	if f.WAF.ManagedRules {
		t.Error(`legacy {"waf":{}} must not enable managed rules`)
	}

	f = LocationFeatures{}
	if err := json.Unmarshal([]byte(`{"waf":{"managedRules":true}}`), &f); err != nil {
		t.Fatal(err)
	}
	if f.WAF == nil || !f.WAF.ManagedRules {
		t.Errorf("managedRules flag lost: %+v", f.WAF)
	}

	f = LocationFeatures{}
	if err := json.Unmarshal([]byte(`{}`), &f); err != nil {
		t.Fatal(err)
	}
	if f.WAF != nil {
		t.Errorf("absent waf feature must stay nil, got %+v", f.WAF)
	}

	// Marshal direction: a zero WAFLocationFeature must round-trip back to the
	// legacy {"waf":{}} shape (ManagedRules omitempty), so stored features and
	// old-CLI location output stay byte-stable if the server re-marshals them.
	b, err := json.Marshal(LocationFeatures{WAF: &WAFLocationFeature{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"waf":{}}` {
		t.Errorf(`zero WAF feature must marshal to {"waf":{}}, got %s`, b)
	}
}
