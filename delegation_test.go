package api

import (
	"strings"
	"testing"
)

func TestIsDelegatablePermission(t *testing.T) {
	delegatable := []string{
		// Ordinary resource actions the caller may hold and hand to an agent.
		"deployment.get",
		"deployment.list",
		"deployment.deploy",
		"deployment.logs",
		"dropbox.upload",
		"site.publish",
		"project.get",
		"route.list",
		"registry.push",
		"registry.pull",
		// Non-key service-account actions mint nothing durable.
		"serviceaccount.create",
		"serviceaccount.get",
		"serviceaccount.list",
		"serviceaccount.delete",
		// Fail-open: an ordinary future permission is delegatable, bounded by
		// containment.
		"database.snapshot",
	}
	for _, p := range delegatable {
		if !IsDelegatablePermission(p) {
			t.Errorf("IsDelegatablePermission(%q) = false, want true", p)
		}
	}

	nonDelegatable := []string{
		// Wildcards: never delegatable.
		"*",
		"deployment.*",
		"role.*",
		"serviceaccount.*",
		"serviceaccount.key.*",
		"billing.*",
		"pullsecret.*",
		// Escalation.
		"role.create",
		"role.bind",
		"role.delete",
		// Credentials that outlive the TTL.
		"serviceaccount.key.create",
		"serviceaccount.key.delete",
		// Money (forward-safe).
		"billing.report",
		// Secret exfiltration.
		"pullsecret.get",
	}
	for _, p := range nonDelegatable {
		if IsDelegatablePermission(p) {
			t.Errorf("IsDelegatablePermission(%q) = true, want false", p)
		}
	}
}

// TestIsDelegatablePermissionFailSafeForWildcards asserts the load-bearing
// invariant against the real permission catalog: no wildcard permission is ever
// delegatable, and the dangerous classes (role.*, serviceaccount.key.*,
// pullsecret.get) are excluded even though they appear in the catalog. This is
// the fail-safe guarantee — a new wildcard or dangerous-class permission added
// to the catalog is non-delegatable the day it ships.
func TestIsDelegatablePermissionFailSafeForWildcards(t *testing.T) {
	for _, p := range Permissions() {
		if p == "*" || strings.HasSuffix(p, ".*") {
			if IsDelegatablePermission(p) {
				t.Errorf("wildcard permission %q must not be delegatable", p)
			}
			continue
		}
		if strings.HasPrefix(p, "role.") ||
			strings.HasPrefix(p, "serviceaccount.key.") ||
			strings.HasPrefix(p, "billing.") ||
			p == "pullsecret.get" {
			if IsDelegatablePermission(p) {
				t.Errorf("dangerous-class permission %q must not be delegatable", p)
			}
		}
	}
}

func TestMeGenerateTokenValid(t *testing.T) {
	t.Run("defaults and accepts a delegatable permission", func(t *testing.T) {
		m := &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}}
		if err := m.Valid(); err != nil {
			t.Fatalf("Valid() = %v, want nil", err)
		}
		if m.TTLSeconds != 900 {
			t.Errorf("TTLSeconds default = %d, want 900", m.TTLSeconds)
		}
	})

	t.Run("accepts and trims a label", func(t *testing.T) {
		m := &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, Label: "  claude-code:pr-42  "}
		if err := m.Valid(); err != nil {
			t.Fatalf("Valid() = %v, want nil", err)
		}
		if m.Label != "claude-code:pr-42" {
			t.Errorf("Label = %q, want trimmed", m.Label)
		}
	})

	t.Run("accepts ttl within range", func(t *testing.T) {
		m := &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, TTLSeconds: 300}
		if err := m.Valid(); err != nil {
			t.Fatalf("Valid() = %v, want nil", err)
		}
	})

	invalid := []struct {
		name string
		m    *MeGenerateToken
	}{
		{"empty project", &MeGenerateToken{Permissions: []string{"deployment.get"}}},
		{"empty permissions", &MeGenerateToken{Project: "acme"}},
		{"non-delegatable class", &MeGenerateToken{Project: "acme", Permissions: []string{"role.create"}}},
		{"wildcard", &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.*"}}},
		{"serviceaccount key", &MeGenerateToken{Project: "acme", Permissions: []string{"serviceaccount.key.create"}}},
		{"pullsecret.get", &MeGenerateToken{Project: "acme", Permissions: []string{"pullsecret.get"}}},
		{"ttl too low", &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, TTLSeconds: 30}},
		{"ttl too high", &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, TTLSeconds: 4000}},
		{"label too long", &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, Label: strings.Repeat("a", MaxTokenLabelLength+1)}},
		{"label bad charset", &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, Label: "bad\nlabel"}},
		{"label leading symbol", &MeGenerateToken{Project: "acme", Permissions: []string{"deployment.get"}, Label: ":nope"}},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.m.Valid(); err == nil {
				t.Errorf("Valid() = nil, want error")
			}
		})
	}
}

func TestMeListTokensValid(t *testing.T) {
	if err := (&MeListTokens{}).Valid(); err == nil {
		t.Error("MeListTokens{}.Valid() = nil, want error")
	}
	if err := (&MeListTokens{Project: "acme"}).Valid(); err != nil {
		t.Errorf("MeListTokens{Project}.Valid() = %v, want nil", err)
	}
}

func TestMeRevokeTokenValid(t *testing.T) {
	cases := []struct {
		name string
		m    *MeRevokeToken
		ok   bool
	}{
		{"both set", &MeRevokeToken{Project: "acme", ID: "tok123"}, true},
		{"missing project", &MeRevokeToken{ID: "tok123"}, false},
		{"missing id", &MeRevokeToken{Project: "acme"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.m.Valid()
			if tc.ok && err != nil {
				t.Errorf("Valid() = %v, want nil", err)
			}
			if !tc.ok && err == nil {
				t.Errorf("Valid() = nil, want error")
			}
		})
	}
}
