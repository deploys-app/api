package api

import (
	"strings"
	"testing"
)

func validWAFTestExpr() *WAFTest {
	return &WAFTest{
		Project:    "p",
		Location:   "gke.cluster",
		Expression: `request.path.startsWith("/admin")`,
		Request: WAFTestRequest{
			Path: "/admin",
		},
	}
}

func validWAFTestDraft() *WAFTest {
	return &WAFTest{
		Project:  "p",
		Location: "gke.cluster",
		Rules: []WAFRule{
			{Expression: `request.country == "TH"`, Action: WAFActionBlock},
		},
		Limits: []WAFLimit{
			{Key: []string{"ip"}, Rate: 10, Window: "1m"},
		},
		Request: WAFTestRequest{
			Method:  "POST",
			Path:    "/api/v1",
			Query:   "a=1&b=2",
			Host:    "app.example.com",
			Scheme:  "https",
			Headers: map[string]string{"x-api-key": "k"},
			Cookies: map[string]string{"session": "s"},
			IP:      "203.0.113.7",
			Country: "TH",
			ASN:     13335,
		},
	}
}

func TestWAFTestValid(t *testing.T) {
	t.Parallel()

	if err := validWAFTestExpr().Valid(); err != nil {
		t.Fatalf("a valid expression-mode request was rejected: %v", err)
	}
	if err := validWAFTestDraft().Valid(); err != nil {
		t.Fatalf("a valid draft-mode request was rejected: %v", err)
	}

	// limits-only draft is a legal draft mode
	m := validWAFTestDraft()
	m.Rules = nil
	if err := m.Valid(); err != nil {
		t.Fatalf("a limits-only draft was rejected: %v", err)
	}

	m = validWAFTestExpr()
	m.Request.IP = "2001:db8::1"
	if err := m.Valid(); err != nil {
		t.Fatalf("an IPv6 sample ip was rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(m *WAFTest)
	}{
		{"missing project", func(m *WAFTest) { m.Project = "" }},
		{"missing location", func(m *WAFTest) { m.Location = "" }},
		{"neither mode", func(m *WAFTest) { m.Expression = "" }},
		{"whitespace-only expression is neither mode", func(m *WAFTest) { m.Expression = "  " }},
		{"both modes", func(m *WAFTest) {
			m.Rules = []WAFRule{{Expression: "true", Action: WAFActionLog}}
		}},
		{"expression too long", func(m *WAFTest) {
			m.Expression = "request.path == \"" + strings.Repeat("a", WAFMaxExpressionLength) + "\""
		}},
		{"missing path", func(m *WAFTest) { m.Request.Path = "" }},
		{"relative path", func(m *WAFTest) { m.Request.Path = "admin" }},
		{"path too long", func(m *WAFTest) { m.Request.Path = "/" + strings.Repeat("a", WAFTestMaxPathLength) }},
		{"query with leading ?", func(m *WAFTest) { m.Request.Query = "?a=1" }},
		{"query too long", func(m *WAFTest) { m.Request.Query = strings.Repeat("a", WAFTestMaxQueryLength+1) }},
		{"host too long", func(m *WAFTest) { m.Request.Host = strings.Repeat("a", WAFTestMaxValueLength+1) }},
		{"method not a token", func(m *WAFTest) { m.Request.Method = "GET POST" }},
		{"method too long", func(m *WAFTest) { m.Request.Method = strings.Repeat("A", WAFTestMaxMethodLength+1) }},
		{"invalid scheme", func(m *WAFTest) { m.Request.Scheme = "ftp" }},
		{"invalid header name", func(m *WAFTest) { m.Request.Headers = map[string]string{"bad header": "v"} }},
		{"host header lowercase", func(m *WAFTest) { m.Request.Headers = map[string]string{"host": "evil"} }},
		{"host header canonical", func(m *WAFTest) { m.Request.Headers = map[string]string{"Host": "evil"} }},
		{"case-duplicate header names", func(m *WAFTest) {
			m.Request.Headers = map[string]string{"X-Api-Key": "a", "x-api-key": "b"}
		}},
		{"header value too long", func(m *WAFTest) {
			m.Request.Headers = map[string]string{"x": strings.Repeat("a", WAFTestMaxValueLength+1)}
		}},
		{"too many headers", func(m *WAFTest) {
			h := map[string]string{}
			for i := 0; i <= WAFTestMaxHeaders; i++ {
				h["x-"+strings.Repeat("a", i+1)] = "v"
			}
			m.Request.Headers = h
		}},
		{"invalid cookie name", func(m *WAFTest) { m.Request.Cookies = map[string]string{"bad;cookie": "v"} }},
		{"cookie value too long", func(m *WAFTest) {
			m.Request.Cookies = map[string]string{"c": strings.Repeat("a", WAFTestMaxValueLength+1)}
		}},
		{"too many cookies", func(m *WAFTest) {
			c := map[string]string{}
			for i := 0; i <= WAFTestMaxCookies; i++ {
				c["c-"+strings.Repeat("a", i+1)] = "v"
			}
			m.Request.Cookies = c
		}},
		{"ip not an ip", func(m *WAFTest) { m.Request.IP = "not-an-ip" }},
		{"country one letter", func(m *WAFTest) { m.Request.Country = "T" }},
		{"country three letters", func(m *WAFTest) { m.Request.Country = "THA" }},
		{"country non-letter", func(m *WAFTest) { m.Request.Country = "T1" }},
		{"negative asn", func(m *WAFTest) { m.Request.ASN = -1 }},
		{"asn above 32-bit", func(m *WAFTest) { m.Request.ASN = WAFTestMaxASN + 1 }},
	}
	for _, tc := range cases {
		m := validWAFTestExpr()
		tc.mutate(m)
		if err := m.Valid(); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}

	// draft mode reuses the waf.set structural contract
	draftCases := []struct {
		name   string
		mutate func(m *WAFTest)
	}{
		{"rule without expression", func(m *WAFTest) { m.Rules[0].Expression = "" }},
		{"rule invalid status", func(m *WAFTest) { m.Rules[0].Status = 42 }},
		{"limit without rate", func(m *WAFTest) { m.Limits[0].Rate = 0 }},
		{"limit invalid window", func(m *WAFTest) { m.Limits[0].Window = "24h" }},
	}
	for _, tc := range draftCases {
		m := validWAFTestDraft()
		tc.mutate(m)
		if err := m.Valid(); err == nil {
			t.Errorf("%s: expected a validation error", tc.name)
		}
	}
}

func TestWAFTestValidCasingNotNormalized(t *testing.T) {
	t.Parallel()

	// method/country casing is normalized server-side; Valid accepts both.
	m := validWAFTestExpr()
	m.Request.Method = "post"
	m.Request.Country = "th"
	if err := m.Valid(); err != nil {
		t.Fatalf("lowercase method/country must pass structural validation: %v", err)
	}
	if m.Request.Method != "post" || m.Request.Country != "th" {
		t.Fatal("Valid must not normalize casing (server-side concern)")
	}
}

func TestWAFTestResultTable(t *testing.T) {
	t.Parallel()

	res := &WAFTestResult{
		Outcome:       "block",
		WinningRuleID: "r1",
		Status:        403,
		Rules: []WAFTestRuleResult{
			{ID: "r1", Matched: true},
			{ID: "r2", Matched: false},
		},
		Limits: []WAFTestLimitResult{
			{ID: "l1", FilterMatched: true},
		},
	}
	table := res.Table()
	if len(table) != 2 {
		t.Fatalf("table must have a header and one row, got %d rows", len(table))
	}
	want := []string{"block", "r1", "403", "1", "1"}
	for i, cell := range want {
		if table[1][i] != cell {
			t.Fatalf("table cell %d = %q, want %q", i, table[1][i], cell)
		}
	}

	// pass outcome has no winning rule and no status; render placeholders,
	// not "" and "0"
	pass := &WAFTestResult{Outcome: "pass", Valid: true}
	row := pass.Table()[1]
	if row[1] != "-" || row[2] != "-" {
		t.Fatalf("pass row rule/status = %q/%q, want placeholders", row[1], row[2])
	}
}
