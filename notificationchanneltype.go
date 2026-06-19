package api

import "encoding/json"

//go:generate stringer -type=NotificationChannelType -linecomment
type NotificationChannelType int

const (
	_                              NotificationChannelType = iota
	NotificationChannelTypeWebhook                         // webhook
	NotificationChannelTypeDiscord                         // discord
)

func (t NotificationChannelType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *NotificationChannelType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}

	*t = parseNotificationChannelType(s)
	return nil
}

func (t NotificationChannelType) MarshalYAML() (any, error) {
	return t.String(), nil
}

func (t *NotificationChannelType) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	err := unmarshal(&s)
	if err != nil {
		return err
	}
	*t = parseNotificationChannelType(s)
	return nil
}

func parseNotificationChannelType(s string) NotificationChannelType {
	for _, x := range []NotificationChannelType{
		NotificationChannelTypeWebhook,
		NotificationChannelTypeDiscord,
	} {
		if x.String() == s {
			return x
		}
	}
	return NotificationChannelType(0)
}

// Valid reports whether the channel type is a supported delivery type.
func (t NotificationChannelType) Valid() bool {
	switch t {
	case NotificationChannelTypeWebhook, NotificationChannelTypeDiscord:
		return true
	default:
		return false
	}
}
