package client

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/deploys-app/api"
)

// ErrNotificationStreamUnsupported is returned when the endpoint answers 200 but
// not with an event stream — the signature of a server that predates the SSE
// route, whose arpc catch-all returns a 200 JSON "not found" for the unknown
// path. Callers should fall back to the notification.pull RPC.
var ErrNotificationStreamUnsupported = errors.New("notification pull stream: endpoint not supported by server")

// NotificationStreamError is returned by NotificationPullStream when the SSE
// endpoint responds with a non-200 status before streaming starts. StatusCode
// lets a caller distinguish, for example, a 404 from a server that predates the
// SSE endpoint (and fall back to the notification.pull RPC) from a 403/400.
type NotificationStreamError struct {
	StatusCode int
	Body       string
}

func (e *NotificationStreamError) Error() string {
	msg := strings.TrimSpace(e.Body)
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("notification pull stream: http %d: %s", e.StatusCode, msg)
}

// NotificationPullStream opens a pull channel's Server-Sent Events stream and
// invokes fn for each change as it arrives, in order. It is the streaming
// counterpart of Notification().Pull — the same at-least-once contract — but the
// server pushes changes instead of the caller polling on an interval.
//
// id is the change's outbox id: the receiver dedups on it (idempotency key), and
// it is the resume token. NotificationPullStream advances m.Ack to the last id it
// has surfaced — past a change only after fn has handled it (so a failed change is
// redelivered, not skipped), and past a cursor keepalive immediately — so a
// reconnect loop can re-invoke with the same *m to resume exactly where it left
// off:
//
//	for {
//		err := c.NotificationPullStream(ctx, m, handle)
//		if ctx.Err() != nil {
//			return ctx.Err()
//		}
//		// optional backoff, then loop to reconnect from the advanced m.Ack
//	}
//
// It runs a single HTTP connection and returns nil when the server closes the
// stream (its periodic connection cap), or an error when fn fails, the context is
// cancelled, or the transport fails. A non-200 response is a *NotificationStreamError.
func (c *Client) NotificationPullStream(ctx context.Context, m *api.NotificationPull, fn func(id int64, ev api.ChangeEventPayload) error) error {
	if err := m.Valid(); err != nil {
		return err
	}

	q := url.Values{}
	q.Set("project", m.Project)
	q.Set("name", m.Name)
	if m.Ack > 0 {
		q.Set("ack", strconv.FormatInt(m.Ack, 10))
	}
	if m.Limit > 0 {
		q.Set("limit", strconv.Itoa(m.Limit))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint()+"notification/pull/sse?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	if c.Auth != nil {
		c.Auth(req)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return &NotificationStreamError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	// A 200 that isn't an event stream means the SSE route is absent and the
	// request fell through to the arpc catch-all (a 200 JSON error). Detect it so
	// the caller can fall back to the RPC instead of busy-looping on a body that
	// yields no events.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "text/event-stream") {
		return ErrNotificationStreamUnsupported
	}

	return parseNotificationSSE(resp.Body, m, fn)
}

// parseNotificationSSE reads an event stream, dispatching `change` events to fn
// and advancing m.Ack as it goes. It implements just enough of the SSE format for
// this endpoint: `event`/`data`/`id` fields, `:` comment/keepalive lines, and a
// blank line to dispatch.
func parseNotificationSSE(r io.Reader, m *api.NotificationPull, fn func(int64, api.ChangeEventPayload) error) error {
	sc := bufio.NewScanner(r)
	// Change payloads are small (audit-safe fields), but allow generous headroom.
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)

	var (
		eventType string
		data      strings.Builder
		idField   string
		hasData   bool
	)
	reset := func() {
		eventType = ""
		data.Reset()
		idField = ""
		hasData = false
	}

	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")

		if line == "" { // dispatch
			if hasData {
				switch eventType {
				case "", "change":
					var ev api.ChangeEventPayload
					if json.Unmarshal([]byte(data.String()), &ev) == nil {
						id, _ := strconv.ParseInt(idField, 10, 64)
						if err := fn(id, ev); err != nil {
							return err // do not advance m.Ack — redeliver on reconnect
						}
						if id > 0 {
							m.Ack = id
						}
					}
				case "cursor":
					// a keepalive carrying the max scanned id: advance the resume
					// cursor past rows the subscription filtered out.
					if v, err := strconv.ParseInt(idField, 10, 64); err == nil && v > 0 {
						m.Ack = v
					}
				}
			}
			reset()
			continue
		}

		if strings.HasPrefix(line, ":") {
			continue // comment / keepalive
		}

		field, val, ok := strings.Cut(line, ":")
		if !ok {
			field, val = line, ""
		}
		val = strings.TrimPrefix(val, " ")
		switch field {
		case "event":
			eventType = val
		case "data":
			if hasData {
				data.WriteByte('\n')
			}
			data.WriteString(val)
			hasData = true
		case "id":
			idField = val
		}
	}
	return sc.Err()
}
