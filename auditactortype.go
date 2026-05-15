package api

import "encoding/json"

//go:generate stringer -type=AuditActorType -linecomment
type AuditActorType int

const (
	_                            AuditActorType = iota
	AuditActorTypeUser                          // User
	AuditActorTypeServiceAccount                // ServiceAccount
)

func (t AuditActorType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *AuditActorType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = parseAuditActorType(s)
	return nil
}

func (t AuditActorType) MarshalYAML() (any, error) {
	return t.String(), nil
}

func (t *AuditActorType) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	*t = parseAuditActorType(s)
	return nil
}

func parseAuditActorType(s string) AuditActorType {
	for _, x := range []AuditActorType{AuditActorTypeUser, AuditActorTypeServiceAccount} {
		if x.String() == s {
			return x
		}
	}
	return AuditActorType(0)
}
