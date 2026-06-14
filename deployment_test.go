package api

import (
	"strings"
	"testing"
)

// a syntactically valid site:// release reference (64 hex chars after @)
const testSiteRef = "site://deploys-static/test-project/website@" +
	"a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00"

func validStaticDeploy() *DeploymentDeploy {
	return &DeploymentDeploy{
		Project:  "test-project",
		Location: "gke",
		Name:     "website",
		Type:     DeploymentTypeStatic,
		Site:     testSiteRef,
	}
}

func TestDeploymentDeployValid_StaticBaseline(t *testing.T) {
	if err := validStaticDeploy().Valid(); err != nil {
		t.Fatalf("expected a bare static deploy to be valid, got: %v", err)
	}
}

func TestDeploymentDeployValid_StaticRejectsContainerConfig(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*DeploymentDeploy)
		wantMsg string
	}{
		{"env", func(m *DeploymentDeploy) { m.Env = map[string]string{"FOO": "bar"} }, "env not allowed for static"},
		{"addEnv", func(m *DeploymentDeploy) { m.AddEnv = map[string]string{"FOO": "bar"} }, "env not allowed for static"},
		{"removeEnv", func(m *DeploymentDeploy) { m.RemoveEnv = []string{"FOO"} }, "env not allowed for static"},
		{"envGroups", func(m *DeploymentDeploy) { m.EnvGroups = []string{"shared"} }, "envGroups not allowed for static"},
		{"addEnvGroups", func(m *DeploymentDeploy) { m.AddEnvGroups = []string{"shared"} }, "envGroups not allowed for static"},
		{"removeEnvGroups", func(m *DeploymentDeploy) { m.RemoveEnvGroups = []string{"shared"} }, "envGroups not allowed for static"},
		{"mountData", func(m *DeploymentDeploy) { m.MountData = map[string]string{"/etc/conf": "x"} }, "mountData not allowed for static"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := validStaticDeploy()
			tc.mutate(m)
			err := m.Valid()
			if err == nil {
				t.Fatalf("expected validation error for %s on a static deploy, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantMsg) {
				t.Fatalf("expected error to contain %q, got: %v", tc.wantMsg, err)
			}
		})
	}
}

func TestDeploymentDeployValid_NonStaticAllowsContainerConfig(t *testing.T) {
	// the same fields are accepted for a container deployment
	port := 8080
	m := &DeploymentDeploy{
		Project:   "test-project",
		Location:  "gke",
		Name:      "web",
		Type:      DeploymentTypeWebService,
		Image:     "nginx:latest",
		Port:      &port,
		Env:       map[string]string{"FOO": "bar"},
		EnvGroups: []string{"shared"},
		MountData: map[string]string{"/etc/conf": "x"},
	}
	if err := m.Valid(); err != nil {
		t.Fatalf("expected a WebService with env/envGroups/mountData to be valid, got: %v", err)
	}
}
