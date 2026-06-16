package api

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/moonrhythm/validator"
)

type EnvGroup interface {
	// Create requires the `envgroup.create` permission.
	Create(ctx context.Context, m *EnvGroupCreate) (*Empty, error)
	// Get requires the `envgroup.get` permission.
	Get(ctx context.Context, m *EnvGroupGet) (*EnvGroupItem, error)
	// List requires the `envgroup.list` permission.
	List(ctx context.Context, m *EnvGroupList) (*EnvGroupListResult, error)
	// Update requires the `envgroup.update` permission.
	Update(ctx context.Context, m *EnvGroupUpdate) (*Empty, error)
	// Delete requires the `envgroup.delete` permission.
	Delete(ctx context.Context, m *EnvGroupDelete) (*Empty, error)
}

type EnvGroupCreate struct {
	Project string            `json:"project" yaml:"project"`
	Name    string            `json:"name" yaml:"name"`
	Env     map[string]string `json:"env" yaml:"env"`
}

func (m *EnvGroupCreate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(validEnvName(m.Env), "invalid env name")

	return WrapValidate(v)
}

type EnvGroupUpdate struct {
	Project   string            `json:"project" yaml:"project"`
	Name      string            `json:"name" yaml:"name"`
	Env       map[string]string `json:"env" yaml:"env"`             // override all env
	AddEnv    map[string]string `json:"addEnv" yaml:"addEnv"`       // add env to existing env
	RemoveEnv []string          `json:"removeEnv" yaml:"removeEnv"` // remove env keys from existing env
	// Redeploy, when true, redeploys (to a new revision) the deployments that
	// reference this group so they pick up the new values; only the currently
	// live ones are touched (paused/being-deleted ones are skipped). It defaults
	// to false: the values are stored and take effect on each deployment's next
	// deploy. Setting it true additionally requires the deployment.deploy
	// permission.
	Redeploy bool `json:"redeploy" yaml:"redeploy"`
}

func (m *EnvGroupUpdate) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}
	v.Must(validEnvName(m.Env), "invalid env name")
	v.Must(validEnvName(m.AddEnv), "invalid env name")

	return WrapValidate(v)
}

type EnvGroupGet struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *EnvGroupGet) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}

	return WrapValidate(v)
}

type EnvGroupDelete struct {
	Project string `json:"project" yaml:"project"`
	Name    string `json:"name" yaml:"name"`
}

func (m *EnvGroupDelete) Valid() error {
	m.Name = strings.TrimSpace(m.Name)

	v := validator.New()

	v.Must(m.Project != "", "project required")
	v.Must(ReValidName.MatchString(m.Name), "name invalid "+ReValidNameStr)
	{
		cnt := utf8.RuneCountInString(m.Name)
		v.Mustf(cnt >= MinNameLength && cnt <= MaxNameLength, "name must have length between %d-%d characters", MinNameLength, MaxNameLength)
	}

	return WrapValidate(v)
}

type EnvGroupList struct {
	Project string `json:"project" yaml:"project"`
}

func (m *EnvGroupList) Valid() error {
	v := validator.New()

	v.Must(m.Project != "", "project required")

	return WrapValidate(v)
}

type EnvGroupListResult struct {
	Project string          `json:"project" yaml:"project"`
	Items   []*EnvGroupItem `json:"items" yaml:"items"`
}

func (m *EnvGroupListResult) Table() [][]string {
	table := [][]string{
		{"NAME", "AGE"},
	}
	for _, x := range m.Items {
		table = append(table, []string{
			x.Name,
			age(x.CreatedAt),
		})
	}
	return table
}

type EnvGroupItem struct {
	Project   string            `json:"project" yaml:"project"`
	Name      string            `json:"name" yaml:"name"`
	Env       map[string]string `json:"env" yaml:"env"`
	CreatedAt time.Time         `json:"createdAt" yaml:"createdAt"`
	CreatedBy string            `json:"createdBy" yaml:"createdBy"`
}

func (m *EnvGroupItem) Table() [][]string {
	table := [][]string{
		{"NAME", "AGE"},
		{
			m.Name,
			age(m.CreatedAt),
		},
	}
	return table
}
