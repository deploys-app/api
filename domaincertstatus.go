package api

import "encoding/json"

//go:generate stringer -type=DomainCertStatus -linecomment
type DomainCertStatus int

const (
	DomainCertStatusNone          DomainCertStatus = iota // none
	DomainCertStatusPendingCreate                         // pendingCreate
	DomainCertStatusCreated                               // created
	DomainCertStatusPendingDelete                         // pendingDelete
)

var allDomainCertStatus = []DomainCertStatus{
	DomainCertStatusNone,
	DomainCertStatusPendingCreate,
	DomainCertStatusCreated,
	DomainCertStatusPendingDelete,
}

func parseDomainCertStatus(s string) DomainCertStatus {
	for _, x := range allDomainCertStatus {
		if x.String() == s {
			return x
		}
	}
	return DomainCertStatusNone
}

func (s DomainCertStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *DomainCertStatus) UnmarshalJSON(b []byte) error {
	var t string
	err := json.Unmarshal(b, &t)
	if err != nil {
		return err
	}
	*s = parseDomainCertStatus(t)
	return nil
}

func (s DomainCertStatus) MarshalYAML() (any, error) {
	return s.String(), nil
}

func (s *DomainCertStatus) UnmarshalYAML(unmarshal func(any) error) error {
	var t string
	err := unmarshal(&t)
	if err != nil {
		return err
	}
	*s = parseDomainCertStatus(t)
	return nil
}
