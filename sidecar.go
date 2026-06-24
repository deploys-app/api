package api

import (
	"fmt"
	"strconv"
)

type Sidecar struct {
	CloudSQLProxy *CloudSQLProxySidecar `json:"cloudSqlProxy" yaml:"cloudSqlProxy"`
}

func (s *Sidecar) Valid() error {
	var n int
	if s.CloudSQLProxy != nil {
		n++
		if err := s.CloudSQLProxy.Valid(); err != nil {
			return fmt.Errorf("cloudSqlProxy: %w", err)
		}
	}
	if n != 1 {
		return fmt.Errorf("only 1 sidecar config per item is allowed")
	}
	return nil
}

func (s *Sidecar) Config() *SidecarConfig {
	switch {
	case s.CloudSQLProxy != nil:
		return s.CloudSQLProxy.config()
	}
	return nil
}

type SidecarConfig struct {
	Name      string
	Image     string
	Env       map[string]string
	Command   []string
	Args      []string
	Port      *int
	MountData map[string]string
}

type CloudSQLProxySidecar struct {
	Instance string `json:"instance" yaml:"instance"`
	Port     int    `json:"port" yaml:"port"`
	// Credentials is an optional service-account JSON for the proxy. Omit it to
	// use the deployment's ambient credentials (bind a workloadIdentity for
	// keyless ADC). Must be empty when AutoIAMAuthn is set.
	Credentials string `json:"credentials" yaml:"credentials"`
	// AutoIAMAuthn makes the proxy authenticate to the database with the caller's
	// IAM principal (--auto-iam-authn) instead of a database password — pair it
	// with a workloadIdentity binding so no key is needed. Mutually exclusive with
	// Credentials.
	AutoIAMAuthn bool `json:"autoIamAuthn" yaml:"autoIamAuthn"`
	// PrivateIP dials the instance's private IP (--private-ip) instead of its
	// public IP.
	PrivateIP bool `json:"privateIp" yaml:"privateIp"`
}

func (s *CloudSQLProxySidecar) Valid() error {
	if s.Instance == "" {
		return fmt.Errorf("instance is required")
	}
	if s.AutoIAMAuthn && s.Credentials != "" {
		// A stale long-lived key in a plaintext ConfigMap while the user believes
		// they are keyless is the worst of both worlds — reject the combination
		// and steer them to a workloadIdentity binding.
		return fmt.Errorf("credentials must be empty when autoIamAuthn is set")
	}
	return nil
}

func (s *CloudSQLProxySidecar) config() *SidecarConfig {
	port := s.Port
	if port <= 0 {
		port = 3300
	}

	cfg := SidecarConfig{
		Name:  "cloudsql-proxy",
		Image: "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.21.2",
		Port:  &port,
		Args: []string{
			s.Instance,
			"-p=" + strconv.Itoa(port),
			"--max-sigterm-delay=30s",
		},
		MountData: map[string]string{},
	}
	if s.AutoIAMAuthn {
		cfg.Args = append(cfg.Args, "--auto-iam-authn")
	}
	if s.PrivateIP {
		cfg.Args = append(cfg.Args, "--private-ip")
	}
	if s.Credentials != "" {
		// cfg.Args = append(cfg.Args, "--json-credentials="+s.Credentials)
		cfg.Args = append(cfg.Args, "--credentials-file=/sidecar/cloudsqlproxy/credentials.json")
		cfg.MountData["/sidecar/cloudsqlproxy/credentials.json"] = s.Credentials
	}

	return &cfg
}
