package api

import (
	"encoding/json"
	"strconv"
)

// GitHubTrigger selects which workflow runs a linked repository deploys from.
type GitHubTrigger int

const (
	// GitHubTriggerAll deploys on push to the production branch AND posts a
	// preview on every pull request. It is the zero value and the default.
	GitHubTriggerAll GitHubTrigger = iota // all
	// GitHubTriggerBranch deploys on push to the production branch only — no
	// pull-request previews.
	GitHubTriggerBranch // branch
	// GitHubTriggerPR posts pull-request previews only — no branch ever deploys.
	GitHubTriggerPR // pr
)

var allGitHubTriggers = []GitHubTrigger{
	GitHubTriggerAll,
	GitHubTriggerBranch,
	GitHubTriggerPR,
}

func (t GitHubTrigger) String() string {
	switch t {
	case GitHubTriggerAll:
		return "all"
	case GitHubTriggerBranch:
		return "branch"
	case GitHubTriggerPR:
		return "pr"
	}
	return "GitHubTrigger(" + strconv.Itoa(int(t)) + ")"
}

func (t GitHubTrigger) Valid() bool {
	switch t {
	case GitHubTriggerAll, GitHubTriggerBranch, GitHubTriggerPR:
		return true
	}
	return false
}

// DeploysBranch reports whether this trigger deploys branch pushes (to
// production). True for "all" and "branch".
func (t GitHubTrigger) DeploysBranch() bool {
	return t == GitHubTriggerAll || t == GitHubTriggerBranch
}

// DeploysPR reports whether this trigger posts pull-request previews. True for
// "all" and "pr".
func (t GitHubTrigger) DeploysPR() bool {
	return t == GitHubTriggerAll || t == GitHubTriggerPR
}

// ParseGitHubTriggerString maps "all"/"branch"/"pr" (and "" → all, the default)
// to a GitHubTrigger. An unrecognized non-empty value returns an invalid
// trigger (Valid() == false) so callers can reject it.
func ParseGitHubTriggerString(s string) GitHubTrigger {
	switch s {
	case "", "all":
		return GitHubTriggerAll
	case "branch":
		return GitHubTriggerBranch
	case "pr":
		return GitHubTriggerPR
	}
	return GitHubTrigger(-1)
}

func (t GitHubTrigger) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *GitHubTrigger) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*t = ParseGitHubTriggerString(s)
	return nil
}

func (t GitHubTrigger) MarshalYAML() (any, error) {
	return t.String(), nil
}

func (t *GitHubTrigger) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*t = ParseGitHubTriggerString(s)
	return nil
}
