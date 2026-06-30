package api

import (
	"encoding/json"
	"fmt"
)

// TransformPhase is the physical mutation seam a transform rule binds to. It is
// the primary axis of a TransformRule (every rule runs in exactly one phase) and
// mirrors WAFAction field-for-field, except that TransformRule.Phase is stored
// as a *pointer* so an omitted phase is a hard validation error rather than a
// silent request-phase default (the zero value is request, and header ops are
// legal in both phases, so a bare int could not distinguish "omitted" from an
// explicit "request").
//
//go:generate stringer -type=TransformPhase -linecomment -output transformphase_string.go
type TransformPhase int

const (
	TransformPhaseRequest  TransformPhase = iota // request
	TransformPhaseResponse                       // response
)

// ParseTransformPhaseString parses the wire form of a phase. The bool reports
// whether s was a known phase; unlike ParseWAFActionString it does NOT default,
// because an unknown phase must be a hard error (see the pointer rationale above).
func ParseTransformPhaseString(s string) (TransformPhase, bool) {
	switch s {
	case "request":
		return TransformPhaseRequest, true
	case "response":
		return TransformPhaseResponse, true
	default:
		return 0, false
	}
}

func (p TransformPhase) Valid() bool {
	return p == TransformPhaseRequest || p == TransformPhaseResponse
}

func (p TransformPhase) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *TransformPhase) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, ok := ParseTransformPhaseString(s)
	if !ok {
		return fmt.Errorf("api: invalid transform phase %q", s)
	}
	*p = v
	return nil
}

func (p TransformPhase) MarshalYAML() (any, error) {
	return p.String(), nil
}

func (p *TransformPhase) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	v, ok := ParseTransformPhaseString(s)
	if !ok {
		return fmt.Errorf("api: invalid transform phase %q", s)
	}
	*p = v
	return nil
}
