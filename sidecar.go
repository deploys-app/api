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
	// HealthCheckPath, when non-empty, is the HTTP path (e.g. "/startup") the
	// sidecar serves an HTTP health check on. The proxy-specific flags that
	// enable that server and bind it to 0.0.0.0 are templated into Args here;
	// the deployer picks a collision-free port (appending --http-port) and turns
	// this into an httpGet startup probe so the app container is held until the
	// proxy is actually serving. The probe must reach the sidecar on the pod IP,
	// so the health server binds 0.0.0.0 even though the proxy itself listens on
	// loopback for the app.
	HealthCheckPath string
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
		Image: "gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.23.0",
		Port:  &port,
		Args: []string{
			s.Instance,
			"-p=" + strconv.Itoa(port),
			"--max-sigterm-delay=30s",
			// Serve health checks on the pod IP so the deployer's startup probe
			// can reach them; the proxy itself still listens on 127.0.0.1 for the
			// app. The deployer appends --http-port to pick a collision-free port.
			"--health-check",
			"--http-address=0.0.0.0",
		},
		HealthCheckPath: "/startup",
		MountData:       map[string]string{},
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
		Image: "gcr.io/alloydb-connectors/alloydb-auth-proxy:1.15.1",
		Port:  &port,
		Args: []string{
			s.Instance,
			"-p=" + strconv.Itoa(port),
			"--max-sigterm-delay=30s",
			// Serve health checks on the pod IP so the deployer's startup probe
			// can reach them; the proxy itself still listens on 127.0.0.1 for the
			// app. The deployer appends --http-port to pick a collision-free port.
			"--health-check",
			"--http-address=0.0.0.0",
		},
		HealthCheckPath: "/startup",
		MountData:       map[string]string{},
	}
	if s.Credentials != "" {
		cfg.Args = append(cfg.Args, "--credentials-file=/sidecar/alloydbproxy/credentials.json")
		cfg.MountData["/sidecar/alloydbproxy/credentials.json"] = s.Credentials
	}

	return &cfg
}
