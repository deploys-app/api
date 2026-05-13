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

	*t = AuditActorType(0)

	for _, x := range []AuditActorType{AuditActorTypeUser, AuditActorTypeServiceAccount} {
		if x.String() == s {
			*t = x
			return nil
		}
	}
	return nil
}
