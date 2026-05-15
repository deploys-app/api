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

	*a = parseAuditOutcome(s)
	return nil
}

func (a AuditOutcome) MarshalYAML() (any, error) {
	return a.String(), nil
}

func (a *AuditOutcome) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	*a = parseAuditOutcome(s)
	return nil
}

func parseAuditOutcome(s string) AuditOutcome {
	for _, x := range []AuditOutcome{AuditOutcomeSuccess, AuditOutcomeFailure} {
		if x.String() == s {
			return x
		}
	}
	return AuditOutcome(0)
}
