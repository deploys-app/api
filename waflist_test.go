package api

import (
	"strings"
	"testing"
)

func validWAFListSet() WAFListSet {
	return WAFListSet{
		Project: "p",
		Name:    "office-ips",
		Entries: []string{"203.0.113.0/24", "198.51.100.7", "2001:db8::/48"},
	}
}

func TestWAFListSetValid(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		m := validWAFListSet()
		if err := m.Valid(); err != nil {
			t.Fatalf("valid WAFListSet rejected: %v", err)
		}
		if m.Type != WAFListTypeIP {
			t.Fatalf("empty type not normalized to ip: %q", m.Type)
		}
	})

	t.Run("entries trimmed", func(t *testing.T) {
		m := validWAFListSet()
		m.Entries = []string{"  203.0.113.0/24\t"}
		if err := m.Valid(); err != nil {
			t.Fatal(err)
		}
		if m.Entries[0] != "203.0.113.0/24" {
			t.Fatalf("entry not trimmed: %q", m.Entries[0])
		}
	})

	t.Run("empty entries ok", func(t *testing.T) {
		m := validWAFListSet()
		m.Entries = nil
		if err := m.Valid(); err != nil {
			t.Fatalf("empty list rejected: %v", err)
		}
	})

	bad := []struct {
		name    string
		mutate  func(*WAFListSet)
		wantMsg string
	}{
		{"project required", func(m *WAFListSet) { m.Project = "" }, "project required"},
		{"name required", func(m *WAFListSet) { m.Name = "" }, "name invalid"},
		{"name bad grammar", func(m *WAFListSet) { m.Name = "Office_IPs" }, "name invalid"},
		{"name too short", func(m *WAFListSet) { m.Name = strings.Repeat("a", MinNameLength-1) }, "name must have length between"},
		{"name too long", func(m *WAFListSet) { m.Name = strings.Repeat("a", MaxNameLength+1) }, "name must have length between"},
		{"type invalid", func(m *WAFListSet) { m.Type = "string" }, "type invalid"},
		{"description too long", func(m *WAFListSet) { m.Description = strings.Repeat("x", WAFMaxMessageLength+1) }, "description must not exceed"},
		{"too many entries", func(m *WAFListSet) {
			m.Entries = make([]string, WAFListMaxEntries+1)
			for i := range m.Entries {
				m.Entries[i] = "203.0.113.7"
			}
		}, "entries must not exceed"},
		{"empty entry", func(m *WAFListSet) { m.Entries = []string{"  "} }, "entry #0: required"},
		{"garbage entry", func(m *WAFListSet) { m.Entries = []string{"office"} }, "is not an ip address or cidr"},
		{"hostname entry", func(m *WAFListSet) { m.Entries = []string{"example.com"} }, "is not an ip address or cidr"},
		{"zoned entry", func(m *WAFListSet) { m.Entries = []string{"fe80::1%eth0"} }, "is not an ip address or cidr"},
		{"zoned cidr entry", func(m *WAFListSet) { m.Entries = []string{"fe80::1%eth0/64"} }, "is not an ip address or cidr"},
		{"bad prefix entry", func(m *WAFListSet) { m.Entries = []string{"203.0.113.0/33"} }, "is not an ip address or cidr"},
		{"entry too long", func(m *WAFListSet) {
			m.Entries = []string{"0000:0000:0000:0000:0000:0000:0000:0001" + strings.Repeat("0", WAFListMaxEntryLength)}
		}, "must not exceed"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			m := validWAFListSet()
			c.mutate(&m)
			err := m.Valid()
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !IsValidateError(err) {
				t.Fatalf("expected *ValidateError, got %T", err)
			}
			if !strings.Contains(err.Error(), c.wantMsg) {
				t.Fatalf("error %q does not contain %q", err.Error(), c.wantMsg)
			}
		})
	}
}

func TestWAFListRequestsValid(t *testing.T) {
	t.Parallel()

	if err := (&WAFListGet{Project: "p", Name: "office-ips"}).Valid(); err != nil {
		t.Fatal(err)
	}
	if err := (&WAFListGet{Name: "office-ips"}).Valid(); err == nil {
		t.Fatal("WAFListGet without project accepted")
	}
	if err := (&WAFListGet{Project: "p"}).Valid(); err == nil {
		t.Fatal("WAFListGet without name accepted")
	}

	if err := (&WAFListList{Project: "p"}).Valid(); err != nil {
		t.Fatal(err)
	}
	if err := (&WAFListList{}).Valid(); err == nil {
		t.Fatal("WAFListList without project accepted")
	}

	if err := (&WAFListDelete{Project: "p", Name: "office-ips"}).Valid(); err != nil {
		t.Fatal(err)
	}
	if err := (&WAFListDelete{Project: "p"}).Valid(); err == nil {
		t.Fatal("WAFListDelete without name accepted")
	}
}

// TestWAFSetValidMacros guards the structural macro step added to
// validWAFRules/validWAFLimits: a well-formed ipInList reference passes, a
// malformed one fails with the rule/limit ref convention.
func TestWAFSetValidMacros(t *testing.T) {
	t.Parallel()

	base := func() WAFSet {
		return WAFSet{
			Project:  "p",
			Location: "gke",
			Rules: []WAFRule{{
				Description: "office allowlist",
				Expression:  `ipInList(request.remote_ip, "office-ips")`,
				Action:      WAFActionAllow,
			}},
			Limits: []WAFLimit{{
				Description: "api limit",
				Key:         []string{"ip"},
				Rate:        600,
				Window:      "1m",
				Filter:      `!ipInList(request.remote_ip, "office-ips")`,
			}},
		}
	}

	m := base()
	if err := m.Valid(); err != nil {
		t.Fatalf("zone with valid macros rejected: %v", err)
	}

	m = base()
	m.Rules[0].Expression = `ipInList(request.remote_ip, "office-ips"`
	err := m.Valid()
	if err == nil {
		t.Fatal("malformed rule macro accepted")
	}
	if !strings.Contains(err.Error(), "rule #0: ipInList usage must be") {
		t.Fatalf("rule macro error %q missing ref convention", err.Error())
	}

	m = base()
	m.Limits[0].Filter = `ipInList(lower(request.host), "office-ips")`
	err = m.Valid()
	if err == nil {
		t.Fatal("malformed limit filter macro accepted")
	}
	if !strings.Contains(err.Error(), "limit #0: ipInList usage must be") {
		t.Fatalf("limit macro error %q missing ref convention", err.Error())
	}
}

func TestWAFListTables(t *testing.T) {
	t.Parallel()

	item := &WAFListItem{
		Project:      "p",
		Name:         "office-ips",
		Type:         WAFListTypeIP,
		Entries:      []string{"203.0.113.0/24", "198.51.100.7"},
		ReferencedBy: []string{"gke.cluster-rcf2", "cluster-lab"},
	}

	table := item.Table()
	if len(table) != 2 {
		t.Fatalf("item table rows = %d; want 2", len(table))
	}
	if got := table[1]; got[0] != "office-ips" || got[1] != "ip" || got[2] != "2" || got[3] != "gke.cluster-rcf2,cluster-lab" {
		t.Fatalf("item row = %v", got)
	}

	list := &WAFListListResult{Project: "p", Items: []*WAFListItem{item, item}}
	if got := len(list.Table()); got != 3 {
		t.Fatalf("list table rows = %d; want 3", got)
	}
}
