package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// dropbox_create_upload_url.go is a client-side helper (like DropboxUpload and
// PublishSite, not an arpc api.Interface method) that mints a signed,
// credential-free upload URL on the dropbox service. The caller hands the
// returned UploadURL to a third party — a browser, a model-built tool, a CI job
// — who PUTs the file straight to dropbox; the bytes never pass through this
// client or the caller's own backend. Once the PUT succeeds the file is
// downloadable at the returned DownloadURL.
//
// The POST carries the client's Auth, which dropbox relays to me.authorized for
// the `dropbox.upload` permission on the project. It pairs with PublishSite the
// same way DropboxUpload does: mint a URL, have someone upload an archive to it,
// then pass the DownloadURL to PublishSite as the archive source.

// DropboxCreateUploadURLOptions configures Client.DropboxCreateUploadURL. Only
// Project is required; the size/type/expiry limits are optional and enforced by
// the dropbox service when the file is PUT.
type DropboxCreateUploadURLOptions struct {
	Project     string `json:"project" yaml:"project"`                   // project sid the upload is authorized and billed against
	Filename    string `json:"filename,omitempty" yaml:"filename"`       // optional filename recorded in Content-Disposition for downloads
	ContentType string `json:"contentType,omitempty" yaml:"contentType"` // optional; when set, the PUT must send this exact Content-Type
	MinSize     int64  `json:"minSize,omitempty" yaml:"minSize"`         // optional min bytes; the server floors it at 1 so empty uploads are refused
	MaxSize     int64  `json:"maxSize,omitempty" yaml:"maxSize"`         // optional max bytes; the server clamps to its cap (default 5 GiB)
	TTLDays     int    `json:"ttl,omitempty" yaml:"ttl"`                 // download lifetime in days, 1-7; 0 -> server default 1
	Expires     int    `json:"expires,omitempty" yaml:"expires"`         // upload-URL validity in seconds, 1-3600; 0 -> server default 900
	Endpoint    string `json:"-" yaml:"-"`                               // optional dropbox base URL override; empty -> DefaultDropboxEndpoint
}

// DropboxCreateUploadURLResult is the outcome of a successful
// DropboxCreateUploadURL.
type DropboxCreateUploadURLResult struct {
	Method          string    `json:"method" yaml:"method"`                     // HTTP method to use against UploadURL (PUT)
	UploadURL       string    `json:"uploadUrl" yaml:"uploadUrl"`               // hand this to the uploader; they PUT the file here, no credential needed
	DownloadURL     string    `json:"downloadUrl" yaml:"downloadUrl"`           // where the file is downloadable after a successful PUT
	ContentType     string    `json:"contentType,omitempty" yaml:"contentType"` // if set, the PUT must send this Content-Type
	MinSize         int64     `json:"minSize" yaml:"minSize"`
	MaxSize         int64     `json:"maxSize" yaml:"maxSize"`
	TTLDays         int       `json:"ttl" yaml:"ttl"`                         // download lifetime the file gets once PUT
	UploadExpiresAt time.Time `json:"uploadExpiresAt" yaml:"uploadExpiresAt"` // when UploadURL stops working
}

func (r *DropboxCreateUploadURLResult) Table() [][]string {
	return [][]string{
		{"UPLOAD URL", "DOWNLOAD URL", "MAX SIZE", "UPLOAD EXPIRES AT"},
		{r.UploadURL, r.DownloadURL, strconv.FormatInt(r.MaxSize, 10), r.UploadExpiresAt.Format(time.RFC3339)},
	}
}

// DropboxCreateUploadURL mints a signed upload URL for opts.Project and returns
// it along with the eventual download URL. The request is authenticated with the
// client's Auth, so the caller needs the dropbox.upload permission on the
// project. No file is uploaded by this call — the holder of UploadURL does that
// with a separate PUT.
func (c *Client) DropboxCreateUploadURL(ctx context.Context, opts *DropboxCreateUploadURLOptions) (*DropboxCreateUploadURLResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("dropbox: options required")
	}
	if opts.Project == "" {
		return nil, fmt.Errorf("dropbox: project required")
	}

	base := strings.TrimSpace(opts.Endpoint)
	if base == "" {
		base = DefaultDropboxEndpoint
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	// POST /uploads takes a JSON body. Send the identifier as `project` (the
	// project sid), matching DropboxUpload and what every caller passes.
	body, err := json.Marshal(struct {
		Project     string `json:"project"`
		Filename    string `json:"filename,omitempty"`
		ContentType string `json:"contentType,omitempty"`
		MinSize     int64  `json:"minSize,omitempty"`
		MaxSize     int64  `json:"maxSize,omitempty"`
		TTL         int    `json:"ttl,omitempty"`
		Expires     int    `json:"expires,omitempty"`
	}{
		Project:     opts.Project,
		Filename:    opts.Filename,
		ContentType: opts.ContentType,
		MinSize:     opts.MinSize,
		MaxSize:     opts.MaxSize,
		TTL:         opts.TTLDays,
		Expires:     opts.Expires,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"uploads", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.Auth != nil {
		c.Auth(req)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	// dropbox answers 200 with {ok:false,error:{message}} on auth/validation
	// failure and {ok:true,result:{...}} on success.
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			Method          string    `json:"method"`
			UploadURL       string    `json:"uploadUrl"`
			DownloadURL     string    `json:"downloadUrl"`
			ContentType     string    `json:"contentType"`
			MinSize         int64     `json:"minSize"`
			MaxSize         int64     `json:"maxSize"`
			TTL             int       `json:"ttl"`
			UploadExpiresAt time.Time `json:"uploadExpiresAt"`
		} `json:"result"`
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &env) != nil || (!env.OK && env.Error.Message == "") {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, fmt.Errorf("dropbox: status %d: %s", resp.StatusCode, msg)
	}
	if !env.OK {
		return nil, (&Error{Message: env.Error.Message}).apiError()
	}
	if env.Result.UploadURL == "" {
		return nil, fmt.Errorf("dropbox: server returned an empty upload URL")
	}

	return &DropboxCreateUploadURLResult{
		Method:          env.Result.Method,
		UploadURL:       env.Result.UploadURL,
		DownloadURL:     env.Result.DownloadURL,
		ContentType:     env.Result.ContentType,
		MinSize:         env.Result.MinSize,
		MaxSize:         env.Result.MaxSize,
		TTLDays:         env.Result.TTL,
		UploadExpiresAt: env.Result.UploadExpiresAt,
	}, nil
}
