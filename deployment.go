package api

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/asaskevich/govalidator"
	"github.com/moonrhythm/validator"
)

type Deployment interface {
	// Deploy requires the `deployment.deploy` permission.
	Deploy(ctx context.Context, m *DeploymentDeploy) (*Empty, error)
	// List requires the `deployment.list` permission.
	List(ctx context.Context, m *DeploymentList) (*DeploymentListResult, error)
	// Get requires the `deployment.get` permission.
	Get(ctx context.Context, m *DeploymentGet) (*DeploymentItem, error)
	// Revisions requires the `deployment.get` permission.
	Revisions(ctx context.Context, m *DeploymentRevisions) (*DeploymentRevisionsResult, error)
	// Resume requires the `deployment.deploy` permission.
	Resume(ctx context.Context, m *DeploymentResume) (*Empty, error)
	// Pause requires the `deployment.deploy` permission.
	Pause(ctx context.Context, m *DeploymentPause) (*Empty, error)
	// Restart requires the `deployment.deploy` permission.
	Restart(ctx context.Context, m *DeploymentRestart) (*Empty, error)
	// Rollback requires the `deployment.get` and `deployment.deploy` permissions.
	Rollback(ctx context.Context, m *DeploymentRollback) (*Empty, error)
	// Delete requires the `deployment.delete` permission.
	Delete(ctx context.Context, m *DeploymentDelete) (*Empty, error)
	// Metrics requires the `deployment.get` permission.
	Metrics(ctx context.Context, m *DeploymentMetrics) (*DeploymentMetricsResult, error)
	// Logs requires the `deployment.logs` permission. It returns a bounded
	// snapshot of recent container output (live pod logs, ephemeral — not a
	// history store).
	Logs(ctx context.Context, m *DeploymentLogs) (*DeploymentLogsResult, error)
	// Status requires the `deployment.get` permission. It returns structured pod
	// health (counts + per-pod failure reasons) without any secret-bearing log
	// content.
	Status(ctx context.Context, m *DeploymentStatus) (*DeploymentStatusResult, error)
	// LogsHistory requires the `deployment.logs` permission. It returns a
	// bounded, paginated slice of DURABLE stored container logs over a
	// [Since, Until] window — surviving pod restart, redeploy, and garbage
	// collection — read from object storage rather than live pods. Unlike Logs
	// (live, ephemeral, current pods) it serves history; it lags live output by
	// the capture flush interval and is best-effort. Page forward with Cursor.
	LogsHistory(ctx context.Context, m *DeploymentLogsHistory) (*DeploymentLogsHistoryResult, error)
	// Errors requires the `deployment.logs` permission. It lists detected
	// application error issues — grouped, deduplicated stack traces mined from
	// the durable log stream — filtered by triage Status and paged with Cursor.
	// Scope by Name (one deployment) or omit Name to list every deployment's
	// issues across the project (a project-wide errors view); each issue carries
	// its Deployment + Location. History-backed and best-effort, like LogsHistory.
	Errors(ctx context.Context, m *DeploymentErrors) (*DeploymentErrorsResult, error)
	// ErrorGet requires the `deployment.logs` permission. It returns one error
	// issue with its representative stack trace and recent occurrence pointers
	// (for deep-linking back into LogsHistory).
	ErrorGet(ctx context.Context, m *DeploymentErrorGet) (*DeploymentErrorGetResult, error)
	// ErrorUpdate requires the `deployment.logs` permission. It changes an error
	// issue's triage status: resolve, reopen, or mute.
	ErrorUpdate(ctx context.Context, m *DeploymentErrorUpdate) (*Empty, error)
}

type DeploymentType int

const (
	_ DeploymentType = iota
	DeploymentTypeWebService
	DeploymentTypeWorker
	DeploymentTypeCronJob
	DeploymentTypeTCPService
	DeploymentTypeInternalTCPService
	DeploymentTypeStatic
)

var allDeploymentTypes = []DeploymentType{
	DeploymentTypeWebService,
	DeploymentTypeWorker,
	DeploymentTypeCronJob,
	DeploymentTypeTCPService,
	DeploymentTypeInternalTCPService,
	DeploymentTypeStatic,
}

var validDeploymentType = func() map[DeploymentType]bool {
	m := map[DeploymentType]bool{}
	for _, t := range allDeploymentTypes {
		m[t] = true
	}
	return m
}()

func ParseDeploymentTypeString(s string) DeploymentType {
	for _, t := range allDeploymentTypes {
		if t.String() == s {
			return t
		}
	}
	return 0
}

func (t DeploymentType) String() string {
	switch t {
	case DeploymentTypeWebService:
		return "WebService"
	case DeploymentTypeWorker:
		return "Worker"
	case DeploymentTypeCronJob:
		return "CronJob"
	case DeploymentTypeTCPService:
		return "TCPService"
	case DeploymentTypeInternalTCPService:
		return "InternalTCPService"
	case DeploymentTypeStatic:
		return "Static"
	default:
		return ""
	}
}

func (t DeploymentType) Text() string {
	switch t {
	case DeploymentTypeWebService:
		return "Web Service"
	case DeploymentTypeWorker:
		return "Worker"
	case DeploymentTypeCronJob:
		return "CronJob"
	case DeploymentTypeTCPService:
		return "TCP Service"
	case DeploymentTypeInternalTCPService:
		return "Internal TCP Service"
	case DeploymentTypeStatic:
		return "Static"
	default:
		return ""
	}
}

func (t DeploymentType) Int() int {
	return int(t)
}

func (t DeploymentType) IsZero() bool {
	return t == 0
}

func (t DeploymentType) Valid() bool {
	// zero value is valid
	if t == 0 {
		return true
	}
	return validDeploymentType[t]
}

func (t *DeploymentType) parseString(s string) error {
	if s == "" {
		*t = 0
		return nil
	}
	*t = ParseDeploymentTypeString(s)
	if t.IsZero() {
		return fmt.Errorf("invalid deployment type")
	}
	return nil
}

func (t DeploymentType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *DeploymentType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	return t.parseString(s)
}

func (t DeploymentType) MarshalYAML() (any, error) {
	return t.String(), nil
}

func (t *DeploymentType) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	return t.parseString(s)
}

func (t DeploymentType) HasExternalTCPAddress() bool {
	switch t {
	default:
		return false
	case DeploymentTypeTCPService:
		return true
	}
}

func (t DeploymentType) HasInternalTCPAddress() bool {
	switch t {
	default:
		return false
	case DeploymentTypeWebService:
		return true
	case DeploymentTypeTCPService:
		return true
	case DeploymentTypeInternalTCPService:
		return true
	}
}

type DeploymentProtocol string

const (
	DeploymentProtocolHTTP  = "http"
	DeploymentProtocolHTTPS = "https"
	DeploymentProtocolH2C   = "h2c"
)

var allDeploymentProtocol = []DeploymentProtocol{
	DeploymentProtocolHTTP,
	DeploymentProtocolHTTPS,
	DeploymentProtocolH2C,
}

var validDeploymentProtocol = func() map[DeploymentProtocol]bool {
	m := map[DeploymentProtocol]bool{}
	for _, t := range allDeploymentProtocol {
		m[t] = true
	}
	return m
}()

type ResourceItem struct {
	CPU    string `json:"cpu" yaml:"cpu"`
	Memory string `json:"memory" yaml:"memory"`
}

type DeploymentResource struct {
	Requests ResourceItem `json:"requests" yaml:"requests"`
	Limits   ResourceItem `json:"limits" yaml:"limits"`
}

type DeploymentDeploy struct {
	Project            string                  `json:"project" yaml:"project"`
	Location           string                  `json:"location" yaml:"location"`
	Name               string                  `json:"name" yaml:"name"`
	Image              string                  `json:"image" yaml:"image"`
	Site               string                  `json:"site" yaml:"site"`                             // site://<bucket>/<project>/<name>@<release-sha>, set for Static deployments instead of Image
	SiteManifestDigest string                  `json:"siteManifestDigest" yaml:"siteManifestDigest"` // digest of the static site manifest for the release
	MinReplicas        *int                    `json:"minReplicas" yaml:"minReplicas"`
	MaxReplicas        *int                    `json:"maxReplicas" yaml:"maxReplicas"`
	Type               DeploymentType          `json:"type" yaml:"type"`
	Port               *int                    `json:"port" yaml:"port"`
	Protocol           *DeploymentProtocol     `json:"protocol" yaml:"protocol"`               // protocol for WebService
	Internal           *bool                   `json:"internal" yaml:"internal"`               // run WebService as internal service
	Env                map[string]string       `json:"env" yaml:"env"`                         // override all env
	AddEnv             map[string]string       `json:"addEnv" yaml:"addEnv"`                   // add env to old revision env
	RemoveEnv          []string                `json:"removeEnv" yaml:"removeEnv"`             // remove env from old revision env
	EnvGroups          []string                `json:"envGroups" yaml:"envGroups"`             // override all env groups
	AddEnvGroups       []string                `json:"addEnvGroups" yaml:"addEnvGroups"`       // add env groups to old revision
	RemoveEnvGroups    []string                `json:"removeEnvGroups" yaml:"removeEnvGroups"` // remove env groups from old revision
	Command            []string                `json:"command" yaml:"command"`
	Args               []string                `json:"args" yaml:"args"`
	WorkloadIdentity   *string                 `json:"workloadIdentity" yaml:"workloadIdentity"` // workload identity name
	PullSecret         *string                 `json:"pullSecret" yaml:"pullSecret"`             // pull secret name
	Disk               *DeploymentDisk         `json:"disk" yaml:"disk"`                         // type=Stateful
	Schedule           *string                 `json:"schedule" yaml:"schedule"`                 // type=CronJob
	Resources          *DeploymentResource     `json:"resources" yaml:"resources"`
	MountData          map[string]string       `json:"mountData" yaml:"mountData"`
	Sidecars           []*Sidecar              `json:"sidecars" yaml:"sidecars"`
	TTL                *int64                  `json:"ttl" yaml:"ttl"`       // seconds until auto-delete; nil = no change, 0 = clear TTL, >0 = set TTL
	Access             *DeploymentAccessConfig `json:"access" yaml:"access"` // optional; when nil or RequireGoogleLogin=false the deployment is public
}

type DeploymentDisk struct {
	Name      string `json:"name" yaml:"name"`
	MountPath string `json:"mountPath" yaml:"mountPath"`
	SubPath   string `json:"subPath" yaml:"subPath"`
}

type DeploymentAccessConfig struct {
	RequireGoogleLogin bool     `json:"requireGoogleLogin" yaml:"requireGoogleLogin"`
	AllowedEmails      []string `json:"allowedEmails" yaml:"allowedEmails"`
	AllowedDomains     []string `json:"allowedDomains" yaml:"allowedDomains"`
	// Phase 2 (additive, do not rename above): Groups, PerPath, BypassServiceTokens, AuditLog…
}

func (m *DeploymentDeploy) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Image = strings.ReplaceAll(m.Image, " ", "")  // remove all space in image
	m.Image = strings.ReplaceAll(m.Image, "\t", "") // remove all tab character

	// TODO: autofill location until all user migrate
	if m.Location == "" {
		m.Location = "gke.cluster-rcf2"
	}

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= DeploymentMaxNameLength, "name must have length between %d-%d characters", MinNameLength, DeploymentMaxNameLength)
	}

	if m.Type == DeploymentTypeStatic {
		// Static deployments carry a site:// release reference instead of an image
		// and must not set any container-only field.
		if v.Must(m.Site != "", "site required") {
			v.Must(validSiteRef(m.Site), "site invalid")
		}
		v.Must(m.Image == "", "image not allowed for static")
		v.Must(m.Port == nil || *m.Port == 0, "port not allowed for static")
		v.Must(m.Protocol == nil || *m.Protocol == "", "protocol not allowed for static")
		v.Must(m.MinReplicas == nil || *m.MinReplicas == 0, "minReplicas not allowed for static")
		v.Must(m.MaxReplicas == nil || *m.MaxReplicas == 0, "maxReplicas not allowed for static")
		v.Must(m.Disk == nil || m.Disk.Name == "", "disk not allowed for static")
		v.Must(len(m.Command) == 0, "command not allowed for static")
		v.Must(len(m.Args) == 0, "args not allowed for static")
		v.Must(len(m.Sidecars) == 0, "sidecars not allowed for static")
		v.Must(m.PullSecret == nil || *m.PullSecret == "", "pullSecret not allowed for static")
		v.Must(m.WorkloadIdentity == nil || *m.WorkloadIdentity == "", "workloadIdentity not allowed for static")
		// A Static deployment runs no container, so env vars, env groups and
		// mount data have nothing to read them: the deployer serves the release
		// from the static-gateway and never builds a pod/ConfigMap. Reject them
		// rather than silently storing dead data.
		v.Must(len(m.Env) == 0 && len(m.AddEnv) == 0 && len(m.RemoveEnv) == 0, "env not allowed for static")
		v.Must(len(m.EnvGroups) == 0 && len(m.AddEnvGroups) == 0 && len(m.RemoveEnvGroups) == 0, "envGroups not allowed for static")
		v.Must(len(m.MountData) == 0, "mountData not allowed for static")
	} else {
		v.Must(m.Site == "", "site not allowed")
		if v.Must(m.Image != "", "image required") {
			v.Must(validImage(m.Image), "invalid image")
		}
	}

	// validate replicas if provided
	if m.MinReplicas != nil {
		v.Mustf(*m.MinReplicas >= 0 && *m.MinReplicas <= DeploymentMaxReplicas, "min replicas value must be in range [%d, %d]", 0, DeploymentMaxReplicas)
	}
	if m.MaxReplicas != nil {
		v.Mustf(*m.MaxReplicas >= 0 && *m.MaxReplicas <= DeploymentMaxReplicas, "max replicas value must be in range [%d, %d]", 0, DeploymentMaxReplicas)
	}
	if m.MinReplicas != nil && m.MaxReplicas != nil {
		v.Must(*m.MinReplicas <= *m.MaxReplicas, "max replicas must higher or equal min replicas")
	}

	// feature not support autoscaling
	if m.MinReplicas != nil && m.MaxReplicas != nil && *m.MinReplicas != *m.MaxReplicas {
		if m.Disk != nil {
			v.Mustf(m.Disk.Name == "", "using disk not support auto-scaling")
		}
	}

	// validate disk
	if m.Disk != nil && m.Disk.Name != "" {
		v.Mustf(m.Disk.MountPath != "", "disk mount path required")
		if m.Disk.SubPath != "" {
			v.Mustf(!filepath.IsAbs(m.Disk.SubPath), "disk sub path must be absolute path")
		}
	}

	// validate mount data
	var totalDataSize int
	for path, data := range m.MountData {
		l := len(data)
		v.Must(strings.HasPrefix(path, "/"), "mountData must be absolute path")
		v.Must(l < 10*1024, "mountData value must less than 10KiB")
		totalDataSize += l
	}
	v.Must(totalDataSize < 500*1024, "mountData all values must less than 500KiB")

	// validate type
	if !m.Type.IsZero() {
		v.Must(m.Type.Valid(), "invalid type")

		switch m.Type {
		case DeploymentTypeWebService:
			if v.Must(m.Port != nil, "port required") {
				v.Must(*m.Port > 0, "invalid port")
			}
			if m.Protocol != nil {
				v.Must(validDeploymentProtocol[*m.Protocol], "invalid protocol")
			}
		case DeploymentTypeWorker:
			v.Must(m.Protocol == nil || *m.Protocol == "", "Worker not support custom protocol")
		case DeploymentTypeCronJob:
			v.Must(m.Protocol == nil || *m.Protocol == "", "CronJob not support custom protocol")
			if m.Schedule != nil {
				if v.Must(*m.Schedule != "", "schedule required") {
					v.Must(ReValidSchedule.MatchString(*m.Schedule), "schedule invalid")
				}
			}
		case DeploymentTypeTCPService:
			v.Must(m.Protocol == nil || *m.Protocol == "", "TCPService not support custom protocol")
			if v.Must(m.Port != nil, "port required") {
				v.Must(*m.Port > 0, "invalid port")
			}
		case DeploymentTypeInternalTCPService:
			v.Must(m.Protocol == nil || *m.Protocol == "", "InternalTCPService not support custom protocol")
			if v.Must(m.Port != nil, "port required") {
				v.Must(*m.Port > 0, "invalid port")
			}
		}
	}

	v.Must(validEnvName(m.Env), "invalid env name")
	v.Must(validEnvName(m.AddEnv), "invalid env name")

	v.Must(len(m.Sidecars) <= 2, "sidecars must less than 2")
	for _, s := range m.Sidecars {
		v.Must(s.Valid(), "invalid sidecar")
	}

	if m.TTL != nil {
		v.Must(*m.TTL >= 0, "ttl must not be negative")
	}

	// validate access policy; when nil or RequireGoogleLogin=false the deployment
	// is public and needs no validation.
	if m.Access != nil && m.Access.RequireGoogleLogin {
		// normalize in place so the stored value is canonical
		m.Access.AllowedEmails = normalizeLowerSet(m.Access.AllowedEmails)
		m.Access.AllowedDomains = normalizeLowerSet(m.Access.AllowedDomains)

		for _, email := range m.Access.AllowedEmails {
			v.Must(govalidator.IsEmail(email), "allowedEmails invalid")
		}
		for _, domain := range m.Access.AllowedDomains {
			v.Must(govalidator.IsDNSName(domain), "allowedDomains invalid")
		}
		// empty AllowedEmails AND empty AllowedDomains is valid (any signed-in
		// Google account); the API accepts it, the UI steers against it.
	}

	return WrapValidate(v)
}

// normalizeLowerSet trims, lowercases, drops empties and de-dupes xs,
// preserving first-seen order.
func normalizeLowerSet(xs []string) []string {
	if len(xs) == 0 {
		return xs
	}
	seen := make(map[string]bool, len(xs))
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		x = strings.ToLower(strings.TrimSpace(x))
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

type DeploymentList struct {
	Location string `json:"location" yaml:"location"` // optional
	Project  string `json:"project" yaml:"project"`
}

func (m *DeploymentList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type DeploymentListResult struct {
	Items []*DeploymentItem `json:"items" yaml:"items"`
}

func (m *DeploymentListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "TYPE", "STATUS", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Name,
			x.Type.String(),
			x.Status.Text(),
			age(x.CreatedAt),
		})
	}
	return table
}

type DeploymentItem struct {
	Project            string                  `json:"project" yaml:"project"`
	Location           string                  `json:"location" yaml:"location"`
	Name               string                  `json:"name" yaml:"name"`
	Type               DeploymentType          `json:"type" yaml:"type"`
	Revision           int64                   `json:"revision" yaml:"revision"`
	Image              string                  `json:"image" yaml:"image"`
	Site               string                  `json:"site" yaml:"site"`
	SiteManifestDigest string                  `json:"siteManifestDigest" yaml:"siteManifestDigest"`
	Env                map[string]string       `json:"env" yaml:"env"`
	EnvGroups          []string                `json:"envGroups" yaml:"envGroups"`
	Command            []string                `json:"command" yaml:"command"`
	Args               []string                `json:"args" yaml:"args"`
	WorkloadIdentity   string                  `json:"workloadIdentity" yaml:"workloadIdentity"`
	PullSecret         string                  `json:"pullSecret" yaml:"pullSecret"`
	Disk               *DeploymentDisk         `json:"disk" yaml:"disk"`
	MountData          map[string]string       `json:"mountData" yaml:"mountData"`
	MinReplicas        int                     `json:"minReplicas" yaml:"minReplicas"`
	MaxReplicas        int                     `json:"maxReplicas" yaml:"maxReplicas"`
	Schedule           string                  `json:"schedule" yaml:"schedule"`
	Port               int                     `json:"port" yaml:"port"`
	Protocol           DeploymentProtocol      `json:"protocol" yaml:"protocol"`
	Internal           bool                    `json:"internal" yaml:"internal"`
	NodePort           int                     `json:"nodePort" yaml:"nodePort"`
	Annotations        map[string]string       `json:"annotations" yaml:"annotations"`
	Access             *DeploymentAccessConfig `json:"access" yaml:"access"` // read-only mirror of the request field
	Resources          DeploymentResource      `json:"resources" yaml:"resources"`
	Sidecars           []*Sidecar              `json:"sidecars" yaml:"sidecars"`
	URL                string                  `json:"url" yaml:"url"`
	InternalURL        string                  `json:"internalUrl" yaml:"internalUrl"`
	LogURL             string                  `json:"logUrl" yaml:"logUrl"`
	EventURL           string                  `json:"eventUrl" yaml:"eventUrl"`
	PodsURL            string                  `json:"podsUrl" yaml:"podsUrl"`
	StatusURL          string                  `json:"statusUrl" yaml:"statusUrl"`
	ErrorsURL          string                  `json:"errorsUrl" yaml:"errorsUrl"`
	Address            string                  `json:"address" yaml:"address"`
	InternalAddress    string                  `json:"internalAddress" yaml:"internalAddress"`
	Status             Status                  `json:"status" yaml:"status"`
	Action             DeploymentAction        `json:"action" yaml:"action"`
	AllocatedPrice     float64                 `json:"allocatedPrice" yaml:"allocatedPrice"`
	CreatedAt          time.Time               `json:"createdAt" yaml:"createdAt"`
	CreatedBy          string                  `json:"createdBy" yaml:"createdBy"`
	SuccessAt          time.Time               `json:"successAt" yaml:"successAt"`
	TTL                int64                   `json:"ttl" yaml:"ttl"` // seconds until auto-delete; 0 means no TTL
}

type DeploymentGet struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
	Revision int    `json:"revision" yaml:"revision"` // 0 = latest
}

func (m *DeploymentGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	// TODO: autofill location until all user migrate
	if m.Location == "" {
		m.Location = "gke.cluster-rcf2"
	}

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Revision >= 0, "invalid revision")

	return WrapValidate(v)
}

type DeploymentRevisions struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DeploymentRevisions) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)

	return WrapValidate(v)
}

type DeploymentRevisionsResult struct {
	Items []*DeploymentItem `json:"items" yaml:"items"`
}

type DeploymentResume struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DeploymentResume) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)

	return WrapValidate(v)
}

type DeploymentPause struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DeploymentPause) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)

	return WrapValidate(v)
}

type DeploymentRestart struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DeploymentRestart) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)

	return WrapValidate(v)
}

type DeploymentRollback struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
	Revision int    `json:"revision" yaml:"revision"`
}

func (m *DeploymentRollback) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Revision >= 1, "invalid revision")

	return WrapValidate(v)
}

type DeploymentDelete struct {
	Location string `json:"location" yaml:"location"`
	Project  string `json:"project" yaml:"project"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DeploymentDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)

	return WrapValidate(v)
}

type DeploymentMetricsTimeRange string

const (
	DeploymentMetricsTimeRange1h     = "1h"
	DeploymentMetricsTimeRange6h     = "6h"
	DeploymentMetricsTimeRange12h    = "12h"
	DeploymentMetricsTimeRange1d     = "1d"
	DeploymentMetricsTimeRange1hagg  = "1hagg"
	DeploymentMetricsTimeRange6hagg  = "6hagg"
	DeploymentMetricsTimeRange12hagg = "12hagg"
	DeploymentMetricsTimeRange1dagg  = "1dagg"
	DeploymentMetricsTimeRange2dagg  = "2dagg"
	DeploymentMetricsTimeRange7dagg  = "7dagg"
	DeploymentMetricsTimeRange30dagg = "30dagg"
)

var allDeploymentMetricsTimeRange = []DeploymentMetricsTimeRange{
	DeploymentMetricsTimeRange1h,
	DeploymentMetricsTimeRange6h,
	DeploymentMetricsTimeRange12h,
	DeploymentMetricsTimeRange1d,
	DeploymentMetricsTimeRange1hagg,
	DeploymentMetricsTimeRange6hagg,
	DeploymentMetricsTimeRange12hagg,
	DeploymentMetricsTimeRange1dagg,
	DeploymentMetricsTimeRange2dagg,
	DeploymentMetricsTimeRange7dagg,
	DeploymentMetricsTimeRange30dagg,
}

var validDeploymentMetricsTimeRange = func() map[DeploymentMetricsTimeRange]bool {
	m := map[DeploymentMetricsTimeRange]bool{}
	for _, t := range allDeploymentMetricsTimeRange {
		m[t] = true
	}
	return m
}()

type DeploymentMetrics struct {
	Location  string                     `json:"location" yaml:"location"`
	Project   string                     `json:"project" yaml:"project"`
	Name      string                     `json:"name" yaml:"name"`
	TimeRange DeploymentMetricsTimeRange `json:"timeRange" yaml:"timeRange"`
}

func (m *DeploymentMetrics) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid: "+ReValidNameDesc)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")
	v.Must(validDeploymentMetricsTimeRange[m.TimeRange], "timeRange invalid")

	return WrapValidate(v)
}

type DeploymentMetricsResult struct {
	CPUUsage    []*DeploymentMetricsLine `json:"cpuUsage" yaml:"cpuUsage"`
	CPULimit    []*DeploymentMetricsLine `json:"cpuLimit" yaml:"cpuLimit"`
	MemoryUsage []*DeploymentMetricsLine `json:"memoryUsage" yaml:"memoryUsage"`
	Memory      []*DeploymentMetricsLine `json:"memory" yaml:"memory"`
	MemoryLimit []*DeploymentMetricsLine `json:"memoryLimit" yaml:"memoryLimit"`
	Requests    []*DeploymentMetricsLine `json:"requests" yaml:"requests"`
	Egress      []*DeploymentMetricsLine `json:"egress" yaml:"egress"`
	// Storage is the daily static-web storage gauge (bytes); populated only for
	// Static deployments.
	Storage []*DeploymentMetricsLine `json:"storage" yaml:"storage"`
}

type DeploymentMetricsLine struct {
	Name   string       `json:"name" yaml:"name"`
	Points [][2]float64 `json:"points" yaml:"points"`
}

// DeploymentLogs requests a bounded snapshot of recent container output for a
// deployment. It reads live pod logs (ephemeral — gone once a pod is garbage
// collected); it is not a historical log store. Each call returns once with a
// bounded batch, never an open stream.
type DeploymentLogs struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	// Pod optionally restricts the read to a single pod of the deployment; empty
	// reads all of the deployment's pods.
	Pod string `json:"pod" yaml:"pod"`
	// Previous reads the last-terminated (crashed) container instead of the
	// running one — the crash post-mortem. Best-effort: k8s only retains it
	// until the pod is garbage collected.
	Previous bool `json:"previous" yaml:"previous"`
	// TailLines bounds the number of lines returned per pod. 0 defaults to
	// DeploymentLogsDefaultTailLines; otherwise it is clamped to
	// [1, DeploymentLogsMaxTailLines].
	TailLines int `json:"tailLines" yaml:"tailLines"`
}

func (m *DeploymentLogs) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Pod = strings.TrimSpace(m.Pod)

	switch {
	case m.TailLines == 0:
		m.TailLines = DeploymentLogsDefaultTailLines
	case m.TailLines < 1:
		m.TailLines = 1
	case m.TailLines > DeploymentLogsMaxTailLines:
		m.TailLines = DeploymentLogsMaxTailLines
	}

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type DeploymentLogsResult struct {
	Lines []DeploymentLogLine `json:"lines" yaml:"lines"`
	// CappedByBytes is set when the response hit the server byte budget and the
	// oldest lines were dropped. A single Truncated-against-tailLines flag would
	// mis-report because k8s applies tailLines per pod, so the byte cap is the
	// committed guarantee.
	CappedByBytes bool `json:"cappedByBytes" yaml:"cappedByBytes"`
}

func (m *DeploymentLogsResult) Table() [][]string {
	table := [][]string{
		{"TIME", "POD", "LOG"},
	}
	for _, x := range m.Lines {
		ts := ""
		if !x.Timestamp.IsZero() {
			ts = x.Timestamp.UTC().Format(time.RFC3339)
		}
		table = append(table, []string{ts, x.Pod, x.Log})
	}
	return table
}

type DeploymentLogLine struct {
	Pod       string    `json:"pod" yaml:"pod"`
	Timestamp time.Time `json:"timestamp" yaml:"timestamp"`
	Log       string    `json:"log" yaml:"log"`
}

// DeploymentLogsHistory requests a bounded, paginated slice of DURABLE stored
// container logs for a deployment over a [Since, Until] window. Unlike
// DeploymentLogs (live, ephemeral, current pods) these are read from object
// storage and survive pod restart/redeploy/GC for the retention window
// (DeploymentLogsHistoryRetentionDays). The data lags live output by the
// capture flush interval and is best-effort. Use Cursor to page (oldest-first
// by default, or newest-first with Reverse): ordering is exact within a page
// and approximately chronological across pages, bounded by the capture flush
// window.
type DeploymentLogsHistory struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
	// Pod optionally restricts the read to a single pod of the deployment; empty
	// reads all of the deployment's pods.
	Pod string `json:"pod" yaml:"pod"`
	// Since is the inclusive start of the window (required).
	Since time.Time `json:"since" yaml:"since"`
	// Until is the exclusive end of the window; zero is resolved to now by the
	// server.
	Until time.Time `json:"until" yaml:"until"`
	// Limit bounds the number of lines returned in this page. 0 defaults to
	// DeploymentLogsHistoryDefaultLimit; otherwise it is clamped to
	// [1, DeploymentLogsHistoryMaxLimit].
	Limit int `json:"limit" yaml:"limit"`
	// Cursor pages through the window; empty starts at the first page (the
	// oldest line for forward, the newest for Reverse). It is an opaque,
	// direction-specific server token — pass back the previous response's
	// NextCursor and keep Reverse stable across the sequence.
	Cursor string `json:"cursor" yaml:"cursor"`
	// Reverse returns lines newest-first and pages backward into the past,
	// instead of the default oldest-first forward paging. Use it to show the
	// most recent history first — e.g. backfilling a log view before attaching
	// the live tail.
	Reverse bool `json:"reverse" yaml:"reverse"`
}

func (m *DeploymentLogsHistory) Valid() error {
	m.Name = strings.TrimSpace(m.Name)
	m.Pod = strings.TrimSpace(m.Pod)
	m.Cursor = strings.TrimSpace(m.Cursor)

	switch {
	case m.Limit == 0:
		m.Limit = DeploymentLogsHistoryDefaultLimit
	case m.Limit < 1:
		m.Limit = 1
	case m.Limit > DeploymentLogsHistoryMaxLimit:
		m.Limit = DeploymentLogsHistoryMaxLimit
	}

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")
	v.Must(!m.Since.IsZero(), "since required")
	v.Must(m.Until.IsZero() || m.Until.After(m.Since), "until must be after since")

	return WrapValidate(v)
}

type DeploymentLogsHistoryResult struct {
	Lines []DeploymentLogLine `json:"lines" yaml:"lines"`
	// NextCursor is non-empty when more lines remain in the window; pass it back
	// as Cursor to fetch the next page. Empty means the window is exhausted.
	NextCursor string `json:"nextCursor" yaml:"nextCursor"`
	// CappedByBytes is set when this page hit the server byte budget before
	// reaching Limit (NextCursor is still set so the caller can continue).
	CappedByBytes bool `json:"cappedByBytes" yaml:"cappedByBytes"`
}

func (m *DeploymentLogsHistoryResult) Table() [][]string {
	table := [][]string{
		{"TIME", "POD", "LOG"},
	}
	for _, x := range m.Lines {
		ts := ""
		if !x.Timestamp.IsZero() {
			ts = x.Timestamp.UTC().Format(time.RFC3339)
		}
		table = append(table, []string{ts, x.Pod, x.Log})
	}
	return table
}

// DeploymentStatus requests structured pod health for a deployment: pod counts
// plus per-pod failure reasons. It is authorized by the `deployment.get`
// permission, not `deployment.logs` — status/reasons are not secret-bearing,
// raw stdout is — so a principal can see why something is unhealthy without
// being able to read potentially-secret log content.
type DeploymentStatus struct {
	Project  string `json:"project" yaml:"project"`
	Location string `json:"location" yaml:"location"`
	Name     string `json:"name" yaml:"name"`
}

func (m *DeploymentStatus) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Location != "", "location required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	// allow old spec long name
	v.Mustf(utf8.RuneCountInString(m.Name) <= DeploymentMaxNameLength*2, "name must have length less then %d characters", DeploymentMaxNameLength*2)
	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type DeploymentStatusResult struct {
	// Count/Ready/Succeeded/Failed come from the log /status tally. They and the
	// per-pod rows are read independently of each other, so treat them as a
	// best-effort snapshot, not a strict point-in-time invariant.
	Count     int `json:"count" yaml:"count"`
	Ready     int `json:"ready" yaml:"ready"`
	Succeeded int `json:"succeeded" yaml:"succeeded"`
	Failed    int `json:"failed" yaml:"failed"`
	// Pods carries the non-ready pods (from log /errors) with their raw failure
	// reasons.
	Pods []DeploymentPodStatus `json:"pods" yaml:"pods"`
}

func (m *DeploymentStatusResult) Table() [][]string {
	table := [][]string{
		{"POD", "PHASE", "READY", "RESTARTS", "REASON", "EXITCODE", "MESSAGE"},
	}
	for _, p := range m.Pods {
		reason := p.WaitingReason
		if reason == "" {
			reason = p.TerminatedReason
		}
		if reason == "" {
			reason = p.LastTerminatedReason
		}

		exit := ""
		switch {
		case p.ExitCode != 0:
			exit = strconv.Itoa(p.ExitCode)
		case p.LastExitCode != 0:
			exit = strconv.Itoa(p.LastExitCode)
		}

		table = append(table, []string{
			p.Name,
			p.Phase,
			strconv.FormatBool(p.Ready),
			strconv.Itoa(p.RestartCount),
			reason,
			exit,
			p.Message,
		})
	}
	return table
}

// DeploymentPodStatus mirrors the log /errors projection 1:1 — raw k8s fields,
// no classification enum — so a new k8s waiting/terminated reason needs no
// contract bump; consumers interpret the raw strings.
type DeploymentPodStatus struct {
	Name                 string `json:"name" yaml:"name"`
	Phase                string `json:"phase" yaml:"phase"`
	Ready                bool   `json:"ready" yaml:"ready"`
	Container            string `json:"container" yaml:"container"`
	RestartCount         int    `json:"restartCount" yaml:"restartCount"`
	WaitingReason        string `json:"waitingReason" yaml:"waitingReason"`               // e.g. CrashLoopBackOff, ImagePullBackOff
	TerminatedReason     string `json:"terminatedReason" yaml:"terminatedReason"`         // current container terminated reason
	ExitCode             int    `json:"exitCode" yaml:"exitCode"`                         // current container terminated exit code
	LastTerminatedReason string `json:"lastTerminatedReason" yaml:"lastTerminatedReason"` // e.g. OOMKilled, Error (survives a restart)
	LastExitCode         int    `json:"lastExitCode" yaml:"lastExitCode"`
	Message              string `json:"message" yaml:"message"`
}
