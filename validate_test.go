package api

import (
	"net"
	"testing"
)

// TestIsPublicIP locks down the SSRF guard: only globally-routable unicast
// addresses are "public"; every range that could be turned into a request
// against internal infrastructure must be rejected.
func TestIsPublicIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// Globally routable.
		{"8.8.8.8", true},
		{"1.1.1.1", true},
		{"203.0.113.10", true}, // not in any blocked range
		{"2606:4700:4700::1111", true},
		// Loopback.
		{"127.0.0.1", false},
		{"127.0.0.53", false},
		{"::1", false},
		// Private (RFC 1918 / ULA).
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"172.31.255.255", false},
		{"192.168.1.1", false},
		{"fc00::1", false},
		{"fd12:3456::1", false},
		// Link-local — includes the cloud metadata endpoint.
		{"169.254.169.254", false},
		{"169.254.0.1", false},
		{"fe80::1", false},
		// Unspecified.
		{"0.0.0.0", false},
		{"::", false},
		// 0.0.0.0/8.
		{"0.1.2.3", false},
		// Carrier-grade NAT 100.64.0.0/10.
		{"100.64.0.1", false},
		{"100.127.255.255", false},
		// Just outside CGNAT — these are public.
		{"100.63.255.255", true},
		{"100.128.0.1", true},
		// Multicast.
		{"224.0.0.1", false},
		{"239.255.255.255", false},
		{"ff02::1", false},
		// IPv4-mapped IPv6 must not become an SSRF bypass: ::ffff:<v4> still
		// resolves to the v4 range via To4(), so these stay blocked.
		{"::ffff:169.254.169.254", false}, // metadata endpoint, mapped form
		{"::ffff:10.0.0.1", false},        // private, mapped form
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test bug: %q is not a valid IP", tc.ip)
		}
		if got := isPublicIP(ip); got != tc.want {
			t.Errorf("isPublicIP(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// TestValidExternalTarget covers the phase-1 external-upstream rule:
// http://<public-ip>[:port] only. https, hostnames, and any SSRF-reachable IP
// must be rejected.
func TestValidExternalTarget(t *testing.T) {
	cases := []struct {
		target string
		want   bool
	}{
		{"http://8.8.8.8", true},
		{"http://8.8.8.8:8080", true},
		{"http://[2606:4700:4700::1111]:443", true},
		// SSRF-reachable IPs are rejected.
		{"http://127.0.0.1", false},
		{"http://169.254.169.254", false}, // cloud metadata
		{"http://10.0.0.5", false},
		{"http://[::1]", false},
		// Scheme rules: https not accepted in phase 1; missing/other scheme.
		{"https://8.8.8.8", false},
		{"ftp://8.8.8.8", false},
		{"8.8.8.8", false},
		{"http://", false},
		// Hostnames are not accepted yet (IP literals only).
		{"http://example.com", false},
		// Bad port.
		{"http://8.8.8.8:0", false},
		{"http://8.8.8.8:70000", false},
	}
	for _, tc := range cases {
		if got := validExternalTarget(tc.target); got != tc.want {
			t.Errorf("validExternalTarget(%q) = %v, want %v", tc.target, got, tc.want)
		}
	}
}

// TestSplitHostPort verifies host extraction with optional port, IPv6 bracket
// handling, and port-range validation.
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantOK   bool
	}{
		{"1.2.3.4", "1.2.3.4", true},
		{"1.2.3.4:80", "1.2.3.4", true},
		{"example.com", "example.com", true}, // host extraction only; no IP check here
		{"example.com:8080", "example.com", true},
		{"::1", "::1", true},   // bare IPv6, unbracketed
		{"[::1]", "::1", true}, // bare IPv6, bracketed
		{"[2001:db8::1]:8080", "2001:db8::1", true},
		// Invalid ports.
		{"1.2.3.4:0", "", false},
		{"1.2.3.4:65536", "", false},
		{"1.2.3.4:", "", false},
		{"1.2.3.4:abc", "", false},
	}
	for _, tc := range cases {
		host, ok := splitHostPort(tc.in)
		if host != tc.wantHost || ok != tc.wantOK {
			t.Errorf("splitHostPort(%q) = (%q, %v), want (%q, %v)", tc.in, host, ok, tc.wantHost, tc.wantOK)
		}
	}
}

// TestValidRouteHost covers the upstream Host-header override: a bare host
// (DNS name or IP) with an optional port, no scheme/path/userinfo. Unlike
// validExternalTarget it deliberately accepts hostnames and does NOT apply the
// SSRF public-IP guard (Host is only a header value, not the backend selector).
func TestValidRouteHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"api.internal.example.com", true},
		{"example.com:8080", true},
		{"8.8.8.8", true},
		{"8.8.8.8:443", true},
		{"127.0.0.1", true}, // SSRF guard intentionally NOT applied to a Host header
		{"[::1]:80", true},
		// Rejected: empty, scheme, path, userinfo, bad port.
		{"", false},
		{"http://example.com", false},
		{"example.com/path", false},
		{"user@example.com", false},
		{"example.com:0", false},
	}
	for _, tc := range cases {
		if got := validRouteHost(tc.host); got != tc.want {
			t.Errorf("validRouteHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}
