package api

import (
	"reflect"
	"strings"
	"testing"
)

func TestWAFListRefs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		expr string
		want []string
	}{
		{"no macro", `request.remote_ip == "1.2.3.4"`, nil},
		{"empty", ``, nil},
		{"simple", `ipInList(request.remote_ip, "office-ips")`, []string{"office-ips"}},
		{"negated", `!ipInList(request.remote_ip, "office-ips")`, []string{"office-ips"}},
		{"header operand", `ipInList(request.headers["x-real-ip"], "office-ips")`, []string{"office-ips"}},
		{"whitespace everywhere", "ipInList (\n\trequest.remote_ip\t,\r\n \"office-ips\" )", []string{"office-ips"}},
		{
			"sorted deduped",
			`ipInList(a.b, "zzz") || ipInList(a.b, "aaa") || ipInList(a.b, "zzz")`,
			[]string{"aaa", "zzz"},
		},
		{
			"composed with other cel",
			`ipInList(request.remote_ip, "office-ips") && request.path.startsWith("/admin")`,
			[]string{"office-ips"},
		},
		// string literals and comments must hide the token
		{"in dq literal", `request.path == "ipInList(a, \"bcd\")"`, nil},
		{"in sq literal", `request.path == 'ipInList(a, "bcd")'`, nil},
		{"in raw sq literal", `regexMatch(request.path, r'ipInList(a, "bcd")')`, nil},
		{"in raw upper literal", `regexMatch(request.path, R'ipInList(a, "bcd")')`, nil},
		{"in bytes literal", `request.body == b'ipInList(a, "bcd")'`, nil},
		{"in raw bytes literal", `request.body == rb'ipInList(a, "bcd")'`, nil},
		{"in triple dq literal", `request.body == """x "quoted" ipInList(a, "bcd")"""`, nil},
		{"in triple sq literal", `request.body == '''ipInList(a, "bcd")'''`, nil},
		{"in comment", "true // ipInList junk that would not parse", nil},
		{
			"literal then real macro",
			`request.path == "ipInList(a, \"bcd\")" && ipInList(request.remote_ip, "office-ips")`,
			[]string{"office-ips"},
		},
		// identifier-boundary: not the reserved token
		{"prefixed ident", `myipInList(a, "bcd")`, nil},
		{"suffixed ident", `ipInListx(a, "bcd")`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := WAFListRefs(c.expr)
			if err != nil {
				t.Fatalf("WAFListRefs(%q) error: %v", c.expr, err)
			}
			if len(got) == 0 && len(c.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("WAFListRefs(%q) = %v; want %v", c.expr, got, c.want)
			}
		})
	}
}

func TestWAFListRefsMalformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		expr string
	}{
		{"bare token", `ipInList`},
		{"bare token in expr", `ipInList && true`},
		{"selector use", `x.ipInList == 1`}, // reserved everywhere outside literals/comments
		{"missing args", `ipInList()`},
		{"missing name", `ipInList(request.remote_ip)`},
		{"unquoted name", `ipInList(request.remote_ip, office)`},
		{"single-quoted name", `ipInList(request.remote_ip, 'office-ips')`},
		{"unterminated name", `ipInList(request.remote_ip, "office-ips`},
		{"missing close paren", `ipInList(request.remote_ip, "office-ips"`},
		{"call operand", `ipInList(lower(request.host), "office-ips")`},
		{"paren operand", `ipInList((request.remote_ip), "office-ips")`},
		{"int index operand", `ipInList(request.headers[0], "office-ips")`},
		{"sq index operand", `ipInList(request.headers['x'], "office-ips")`},
		{"name too short", `ipInList(request.remote_ip, "ab")`},
		{"name too long", `ipInList(request.remote_ip, "` + strings.Repeat("a", MaxNameLength+1) + `")`},
		{"name bad grammar", `ipInList(request.remote_ip, "Office-IPs")`},
		{"name with escape", `ipInList(request.remote_ip, "off\"ice")`},
		{"empty name", `ipInList(request.remote_ip, "")`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := WAFListRefs(c.expr)
			if err == nil {
				t.Fatalf("WAFListRefs(%q) accepted a malformed usage", c.expr)
			}
			if !strings.Contains(err.Error(), "ipInList usage must be") {
				t.Fatalf("WAFListRefs(%q) error %q is not the structural usage error", c.expr, err)
			}
		})
	}
}

func TestExpandWAFListMacros(t *testing.T) {
	t.Parallel()

	lists := map[string][]string{
		"office-ips": {"203.0.113.0/24", "198.51.100.7", "2001:db8::/48"},
		"empty-list": {},
		"one-v6":     {"2001:db8::1"},
	}
	resolve := func(name string) ([]string, bool) {
		entries, ok := lists[name]
		return entries, ok
	}

	cases := []struct {
		name string
		expr string
		want string
	}{
		{
			"golden",
			`ipInList(request.remote_ip, "office-ips")`,
			`(ipInCidr(request.remote_ip, "203.0.113.0/24") || ipInCidr(request.remote_ip, "198.51.100.7/32") || ipInCidr(request.remote_ip, "2001:db8::/48"))`,
		},
		{
			"empty list",
			`ipInList(request.remote_ip, "empty-list")`,
			`(false)`,
		},
		{
			"bare ipv6 gets /128",
			`ipInList(request.remote_ip, "one-v6")`,
			`(ipInCidr(request.remote_ip, "2001:db8::1/128"))`,
		},
		{
			"operand splice with header accessor",
			`!ipInList(request.headers["x-real-ip"], "empty-list") && request.path == "/x"`,
			`!(false) && request.path == "/x"`,
		},
		{
			"surrounding text preserved",
			`request.asn == 13335 || ipInList(request.remote_ip, "empty-list") || request.country == "TH"`,
			`request.asn == 13335 || (false) || request.country == "TH"`,
		},
		{
			"whitespace form normalizes to expansion",
			"ipInList ( request.remote_ip , \"one-v6\" )",
			`(ipInCidr(request.remote_ip, "2001:db8::1/128"))`,
		},
		{
			"token in literal untouched",
			`request.path == "ipInList(a, \"office-ips\")"`,
			`request.path == "ipInList(a, \"office-ips\")"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ExpandWAFListMacros(c.expr, resolve)
			if err != nil {
				t.Fatalf("ExpandWAFListMacros(%q) error: %v", c.expr, err)
			}
			if got != c.want {
				t.Fatalf("ExpandWAFListMacros(%q)\n got:  %s\n want: %s", c.expr, got, c.want)
			}
		})
	}

	t.Run("macro-free pass-through is byte-identical", func(t *testing.T) {
		expr := `request.remote_ip == "1.2.3.4" && request.path.startsWith("/x") // ipInList note`
		got, err := ExpandWAFListMacros(expr, resolve)
		if err != nil {
			t.Fatal(err)
		}
		if got != expr {
			t.Fatalf("pass-through changed text: %q", got)
		}
	})

	t.Run("missing list", func(t *testing.T) {
		_, err := ExpandWAFListMacros(`ipInList(request.remote_ip, "no-such")`, resolve)
		if err == nil || !strings.Contains(err.Error(), `waf list "no-such" not found`) {
			t.Fatalf("expected not-found error, got %v", err)
		}
	})

	t.Run("malformed usage", func(t *testing.T) {
		_, err := ExpandWAFListMacros(`ipInList(request.remote_ip)`, resolve)
		if err == nil || !strings.Contains(err.Error(), "ipInList usage must be") {
			t.Fatalf("expected usage error, got %v", err)
		}
	})

	t.Run("corrupt entry rejected", func(t *testing.T) {
		bad := func(string) ([]string, bool) { return []string{`1.2.3.4") || true || ipInCidr(x, "0.0.0.0/0`}, true }
		_, err := ExpandWAFListMacros(`ipInList(request.remote_ip, "office-ips")`, bad)
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("expected invalid-entry error, got %v", err)
		}
	})
}
