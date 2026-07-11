package api

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validWAFEvents() *WAFEvents {
	return &WAFEvents{
		Project:  "p",
		Location: "gke.cluster",
	}
}

func TestWAFEventsValid(t *testing.T) {
	if err := validWAFEvents().Valid(); err != nil {
		t.Fatalf("a minimal valid request was rejected: %v", err)
	}

	full := validWAFEvents()
	full.RuleID = "abc-123"
	full.Action = "block"
	full.Before = "01HZZZZZZZZZZZZZZZZZZZZZZZ"
	full.Limit = WAFEventsMaxLimit
	if err := full.Valid(); err != nil {
		t.Fatalf("a fully-populated valid request was rejected: %v", err)
	}

	for _, a := range []string{"", "log", "allow", "block"} {
		m := validWAFEvents()
		m.Action = a
		if err := m.Valid(); err != nil {
			t.Fatalf("action %q must be valid: %v", a, err)
		}
	}

	cases := []struct {
		name string
		mod  func(*WAFEvents)
		msg  string
	}{
		{"missing project", func(m *WAFEvents) { m.Project = "" }, "project required"},
		{"missing location", func(m *WAFEvents) { m.Location = "" }, "location required"},
		{"unknown action", func(m *WAFEvents) { m.Action = "deny" }, "action invalid"},
		// action is a filter over stored strings, so case matters
		{"upper-case action", func(m *WAFEvents) { m.Action = "Block" }, "action invalid"},
		{"negative limit", func(m *WAFEvents) { m.Limit = -1 }, "limit out of bounds"},
		{"limit over cap", func(m *WAFEvents) { m.Limit = WAFEventsMaxLimit + 1 }, "limit out of bounds"},
		{"ruleId bad shape", func(m *WAFEvents) { m.RuleID = "-abc" }, "ruleId invalid"},
		{"ruleId too long", func(m *WAFEvents) { m.RuleID = strings.Repeat("a", WAFMaxRuleIDLength+1) }, "ruleId must not exceed"},
		{"before too short", func(m *WAFEvents) { m.Before = "01HZZ" }, "before invalid"},
		{"before too long", func(m *WAFEvents) { m.Before = strings.Repeat("0", WAFEventIDLength+1) }, "before invalid"},
		// lower case would break the server's lexicographic id < before paging
		{"before lower case", func(m *WAFEvents) { m.Before = strings.Repeat("z", WAFEventIDLength) }, "before invalid"},
		// I, L, O, U are not in the Crockford base32 alphabet
		{"before non-crockford", func(m *WAFEvents) { m.Before = "01HI" + strings.Repeat("0", WAFEventIDLength-4) }, "before invalid"},
	}
	for _, tc := range cases {
		m := validWAFEvents()
		tc.mod(m)
		err := m.Valid()
		if err == nil {
			t.Fatalf("%s: must be rejected", tc.name)
		}
		if !strings.Contains(err.Error(), tc.msg) {
			t.Fatalf("%s: error %q must contain %q", tc.name, err.Error(), tc.msg)
		}
	}

	// limit bounds are inclusive; 0 means the server default
	for _, l := range []int{0, WAFEventsDefaultLimit, WAFEventsMaxLimit} {
		m := validWAFEvents()
		m.Limit = l
		if err := m.Valid(); err != nil {
			t.Fatalf("limit %d must be valid: %v", l, err)
		}
	}

	// filters are trimmed like WAFRule.ID (a copy-pasted value keeps working;
	// §G blesses hand-editing the query params these map onto)
	m := validWAFEvents()
	m.RuleID = "  abc  "
	m.Action = " block "
	m.Before = " 01HZZZZZZZZZZZZZZZZZZZZZZZ "
	if err := m.Valid(); err != nil {
		t.Fatalf("padded filters must validate after trim: %v", err)
	}
	if m.RuleID != "abc" {
		t.Fatalf("ruleId must be trimmed, got %q", m.RuleID)
	}
	if m.Action != "block" {
		t.Fatalf("action must be trimmed, got %q", m.Action)
	}
	if m.Before != "01HZZZZZZZZZZZZZZZZZZZZZZZ" {
		t.Fatalf("before must be trimmed, got %q", m.Before)
	}
}

func TestWAFEventsResultTable(t *testing.T) {
	at := time.Date(2026, 7, 10, 12, 34, 56, 0, time.UTC)
	res := &WAFEventsResult{
		Items: []*WAFEvent{{
			ID:       "01HZZZZZZZZZZZZZZZZZZZZZZZ",
			At:       at,
			RuleID:   "abc",
			Action:   "block",
			Status:   403,
			ClientIP: "203.0.113.7",
			Country:  "TH",
			ASN:      13335,
			Method:   "POST",
			Host:     "app.example.com",
			Path:     "/wp-login.php",
		}},
		Next: "01HZZZZZZZZZZZZZZZZZZZZZZZ",
	}
	table := res.Table()
	if len(table) != 2 {
		t.Fatalf("table must have header + 1 row, got %d rows", len(table))
	}
	header := []string{"TIME", "ACTION", "RULE", "IP", "COUNTRY", "METHOD", "HOST", "PATH"}
	for i, h := range header {
		if table[0][i] != h {
			t.Fatalf("header[%d]=%q want %q", i, table[0][i], h)
		}
	}
	row := table[1]
	want := []string{"2026-07-10T12:34:56Z", "block", "abc", "203.0.113.7", "TH", "POST", "app.example.com", "/wp-login.php"}
	if len(row) != len(header) {
		t.Fatalf("row width %d must match header width %d", len(row), len(header))
	}
	for i := range want {
		if row[i] != want[i] {
			t.Fatalf("row[%d]=%q want %q", i, row[i], want[i])
		}
	}

	empty := (&WAFEventsResult{}).Table()
	if len(empty) != 1 {
		t.Fatalf("empty result must render header only, got %d rows", len(empty))
	}
}

// TestCollectorWAFEventItemWire pins the JSON field names shared with the
// engine's cursor-endpoint Event (SPEC-waf-events §C.1/§D.1): the collector
// copies fields by name between the two, so a silent rename here would break
// the pipeline at compile-distance from both ends.
func TestCollectorWAFEventItemWire(t *testing.T) {
	b, err := json.Marshal(&CollectorWAFEventItem{
		ID:        "01HZZZZZZZZZZZZZZZZZZZZZZZ",
		ProjectID: 42,
		RuleID:    "42-abc",
		Action:    "block",
		Status:    403,
		At:        1760000000,
		ClientIP:  "203.0.113.7",
		Country:   "TH",
		ASN:       13335,
		Method:    "POST",
		Host:      "app.example.com",
		Path:      "/wp-login.php",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "projectId", "ruleId", "action", "status", "at", "clientIp", "country", "asn", "method", "host", "path"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("wire field %q missing (got %s)", k, b)
		}
	}
	if len(got) != 12 {
		t.Fatalf("unexpected wire fields (got %s)", b)
	}
	// ProjectID travels as a string like every collector item
	if string(got["projectId"]) != `"42"` {
		t.Fatalf(`projectId must encode as "42", got %s`, got["projectId"])
	}
}

func TestValidWAFEventID(t *testing.T) {
	cases := []struct {
		id string
		ok bool
	}{
		{"01HZZZZZZZZZZZZZZZZZZZZZZZ", true},
		{"00000000000000000000000000", true},
		{"0123456789ABCDEFGHJKMNPQRS", true}, // every legal char class
		{"", false},
		{"01HZ", false},
		{"01HZZZZZZZZZZZZZZZZZZZZZZZZ", false}, // 27 chars
		{"01hzzzzzzzzzzzzzzzzzzzzzzz", false},  // lower case
		{"01HIZZZZZZZZZZZZZZZZZZZZZZ", false},  // I excluded
		{"01HLZZZZZZZZZZZZZZZZZZZZZZ", false},  // L excluded
		{"01HOZZZZZZZZZZZZZZZZZZZZZZ", false},  // O excluded
		{"01HUZZZZZZZZZZZZZZZZZZZZZZ", false},  // U excluded
		{"01H-ZZZZZZZZZZZZZZZZZZZZZZ", false},  // punctuation
		{"01H ZZZZZZZZZZZZZZZZZZZZZZ", false},  // space
	}
	for _, tc := range cases {
		if got := ValidWAFEventID(tc.id); got != tc.ok {
			t.Fatalf("ValidWAFEventID(%q)=%v want %v", tc.id, got, tc.ok)
		}
	}
}

// TestWAFEventWire pins the read-API JSON field names: console (TypeScript,
// no shared types), the MCP catalog, and the CLI all consume them by name, so
// a silent tag rename here would break them at runtime-distance.
func TestWAFEventWire(t *testing.T) {
	b, err := json.Marshal(&WAFEvent{
		ID:       "01HZZZZZZZZZZZZZZZZZZZZZZZ",
		At:       time.Date(2026, 7, 10, 12, 34, 56, 0, time.UTC),
		RuleID:   "abc",
		Action:   "block",
		Status:   403,
		ClientIP: "203.0.113.7",
		Country:  "TH",
		ASN:      13335,
		Method:   "POST",
		Host:     "app.example.com",
		Path:     "/wp-login.php",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "at", "ruleId", "action", "status", "clientIp", "country", "asn", "method", "host", "path"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("wire field %q missing (got %s)", k, b)
		}
	}
	if len(got) != 11 {
		t.Fatalf("unexpected wire fields (got %s)", b)
	}

	rb, err := json.Marshal(&WAFEventsResult{Next: "01HZZZZZZZZZZZZZZZZZZZZZZZ"})
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]json.RawMessage
	if err := json.Unmarshal(rb, &res); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"items", "next"} {
		if _, ok := res[k]; !ok {
			t.Fatalf("result wire field %q missing (got %s)", k, rb)
		}
	}
	if len(res) != 2 {
		t.Fatalf("unexpected result wire fields (got %s)", rb)
	}
}
