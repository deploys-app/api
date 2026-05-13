package api

import "encoding/json"

//go:generate stringer -type=AuditOutcome -linecomment
type AuditOutcome int

const (
	_                   AuditOutcome = iota
	AuditOutcomeSuccess              // success
	AuditOutcomeFailure              // failure
)

func (a AuditOutcome) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.String())
}

func (a *AuditOutcome) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*a = AuditOutcome(0)

	for _, x := range []AuditOutcome{AuditOutcomeSuccess, AuditOutcomeFailure} {
		if x.String() == s {
			*a = x
			return nil
		}
	}
	return nil
}
