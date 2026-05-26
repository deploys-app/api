package api

import "encoding/json"

//go:generate stringer -type=WAFAction -linecomment
type WAFAction int

// Mirrors parapet's waf.Action. The zero value is log, so a rule with no
// action is a safe shadow rule (records the match, keeps evaluating).
const (
	WAFActionLog   WAFAction = iota // log
	WAFActionAllow                  // allow
	WAFActionBlock                  // block
)

var allWAFActions = []WAFAction{
	WAFActionLog,
	WAFActionAllow,
	WAFActionBlock,
}

func ParseWAFActionString(s string) WAFAction {
	for _, x := range allWAFActions {
		if x.String() == s {
			return x
		}
	}
	return WAFActionLog
}

func (a WAFAction) Valid() bool {
	switch a {
	case WAFActionLog, WAFActionAllow, WAFActionBlock:
		return true
	default:
		return false
	}
}

func (a WAFAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a *WAFAction) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*a = ParseWAFActionString(s)
	return nil
}

func (a WAFAction) MarshalYAML() (any, error) {
	return a.String(), nil
}

func (a *WAFAction) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	*a = ParseWAFActionString(s)
	return nil
}
