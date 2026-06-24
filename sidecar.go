package api

import (
	"fmt"
	"strconv"
)

type Sidecar struct {
	CloudSQLProxy *CloudSQLProxySidecar `json:"cloudSqlProxy" yaml:"cloudSqlProxy"`
	AlloyDBProxy  *AlloyDBProxySidecar  `json:"alloyDbProxy" yaml:"alloyDbProxy"`
}

func (s *Sidecar) Valid() error {
	var n int
	if s.CloudSQLProxy != nil {
		n++
		if err := s.CloudSQLProxy.Valid(); err != nil {
			return fmt.Errorf("cloudSqlProxy: %w", err)
		}
	}
	if s.AlloyDBProxy != nil {
		n++
		if err := s.AlloyDBProxy.Valid(); err != nil {
			return fmt.Errorf("alloyDbProxy: %w", err)
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
	case s.AlloyDBProxy != nil:
		return s.AlloyDBProxy.config()
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
	Instance    string `json:"instance" yaml:"instance"`
	Port        int    `json:"port" yaml:"port"`
	Credentials string `json:"credentials" yaml:"credentials"`
}

func (s *CloudSQLProxySidecar) Valid() error {
	if s.Instance == "" {
		return fmt.Errorf("instance is required")
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
	if s.Credentials != "" {
		// cfg.Args = append(cfg.Args, "--json-credentials="+s.Credentials)
		cfg.Args = append(cfg.Args, "--credentials-file=/sidecar/cloudsqlproxy/credentials.json")
		cfg.MountData["/sidecar/cloudsqlproxy/credentials.json"] = s.Credentials
	}

	return &cfg
}

// AlloyDBProxySidecar runs the AlloyDB Auth Proxy alongside the app container,
// mirroring CloudSQLProxySidecar: the platform pins the image and templates the
// args; the user only supplies the instance, an optional local port and optional
// credentials. The app connects to the database at 127.0.0.1:<port>.
type AlloyDBProxySidecar struct {
	// Instance is the AlloyDB instance URI, e.g.
	// projects/<project>/locations/<location>/clusters/<cluster>/instances/<instance>
	Instance string `json:"instance" yaml:"instance"`
	// Port is the local port the proxy listens on (default 5432).
	Port int `json:"port" yaml:"port"`
	// Credentials is an optional service-account JSON for the proxy. Omit it to
	// use the deployment's ambient credentials — bind a workloadIdentity and the
	// proxy authenticates keyless via ADC, so nothing sensitive is materialized.
	Credentials string `json:"credentials" yaml:"credentials"`
}

func (s *AlloyDBProxySidecar) Valid() error {
	if s.Instance == "" {
		return fmt.Errorf("instance is required")
	}
	return nil
}

func (s *AlloyDBProxySidecar) config() *SidecarConfig {
	port := s.Port
	if port <= 0 {
		port = 5432
	}

	cfg := SidecarConfig{
		Name:  "alloydb-proxy",
		Image: "gcr.io/alloydb-connectors/alloydb-auth-proxy:1.13.9",
		Port:  &port,
		Args: []string{
			s.Instance,
			"-p=" + strconv.Itoa(port),
			"--max-sigterm-delay=30s",
		},
		MountData: map[string]string{},
	}
	if s.Credentials != "" {
		cfg.Args = append(cfg.Args, "--credentials-file=/sidecar/alloydbproxy/credentials.json")
		cfg.MountData["/sidecar/alloydbproxy/credentials.json"] = s.Credentials
	}

	return &cfg
}
