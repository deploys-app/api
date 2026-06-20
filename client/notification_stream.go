package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/deploys-app/api"
)

// arpcNotFoundMessage is the message the apiserver's arpc catch-all returns for an
// unknown action. A server without the notification.pullStream action answers with
// it (as a 200 {ok:false,error}), which we treat as "endpoint unsupported".
const arpcNotFoundMessage = "api: not found"

// ErrNotificationStreamUnsupported is returned when the server has no
// notification.pullStream action (its arpc catch-all answers "api: not found").
// Callers should fall back to the notification.pull RPC.
var ErrNotificationStreamUnsupported = errors.New("notification pull stream: endpoint not supported by server")

// NotificationStreamError is returned by NotificationPullStream for a
// protocol/transport-level failure — a non-200 response whose body is not a
// recognizable arpc error envelope (application-level errors come back as 200
// {ok:false,error} and are surfaced as typed api errors instead). StatusCode
// carries the HTTP status.
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
// cancelled, or the transport fails. A pre-stream failure is returned as a typed
// error: the same arpc errors notification.pull returns (e.g. forbidden, channel
// not found), ErrNotificationStreamUnsupported when the server lacks the action,
// or a *NotificationStreamError for a protocol/transport-level failure.
//
// The request is the same POST + JSON contract as notification.pull
// (notification.pullStream is a normal arpc action); only the response differs —
// an event stream instead of a single batch.
func (c *Client) NotificationPullStream(ctx context.Context, m *api.NotificationPull, fn func(id int64, ev api.ChangeEventPayload) error) error {
	if err := m.Valid(); err != nil {
		return err
	}

	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(m); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint()+"notification.pullStream", &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Accept", "text/event-stream")
	if c.Auth != nil {
		c.Auth(req)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Success is the only event-stream response; anything else is an error to
	// classify (an arpc {ok:false,error} envelope, or a transport/protocol status).
	ct := resp.Header.Get("Content-Type")
	if resp.StatusCode == http.StatusOK && strings.HasPrefix(strings.ToLower(ct), "text/event-stream") {
		return parseNotificationSSE(resp.Body, m, fn)
	}
	return notificationStreamResponseError(resp)
}

// notificationStreamResponseError classifies a non-stream response. arpc encodes
// every handler error as {ok:false,error:{message}} — at HTTP 200 for the api
// error sentinels (OKError) and 400 for a protocol error — so we decode that
// envelope and map the message back to a typed api error (mirroring invoke). The
// catch-all "api: not found" means the server has no such action.
func notificationStreamResponseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	var env struct {
		OK    bool  `json:"ok"`
		Error Error `json:"error"`
	}
	if json.Unmarshal(body, &env) == nil && !env.OK && env.Error.Message != "" {
		if env.Error.Message == arpcNotFoundMessage {
			return ErrNotificationStreamUnsupported
		}
		return env.Error.apiError()
	}
	if resp.StatusCode != http.StatusOK {
		return &NotificationStreamError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	// 200 with neither a stream nor a recognizable arpc error — treat as unsupported.
	return ErrNotificationStreamUnsupported
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
