package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// dropbox_upload.go is a client-side helper (not an arpc api.Interface method,
// like PublishSite in site.go) that uploads a file to the deploys.app
// temporary-file service and returns a public, short-lived download URL.
//
// Dropbox upload is a raw-HTTP POST on a separate service (dropbox.deploys.app),
// not a JSON-RPC action, so it is absent from the api.Dropbox interface (which
// only has the arpc List/Metrics actions). The POST carries the client's Auth,
// which dropbox relays to me.authorized for the `dropbox.upload` permission.
//
// It pairs with PublishSite: host a static-site archive here, then publish it by
// passing the returned DownloadURL as the archive source.

// DefaultDropboxEndpoint is the public base URL of the deploys.app dropbox
// (temporary file storage) service.
const DefaultDropboxEndpoint = "https://dropbox.deploys.app/"

// DropboxUploadOptions configures Client.DropboxUpload.
type DropboxUploadOptions struct {
	Project  string // project sid the upload is authorized and billed against (requires the dropbox.upload permission)
	Content  []byte // the file bytes to upload
	Filename string // optional filename recorded in Content-Disposition, e.g. "site.tar.gz"
	TTLDays  int    // download lifetime in days, 1-7; out-of-range or 0 defaults to 1 (server-side)
	Endpoint string // optional dropbox base URL override; empty -> DefaultDropboxEndpoint
}

// DropboxUploadResult is the outcome of a successful DropboxUpload.
type DropboxUploadResult struct {
	DownloadURL string    `json:"downloadUrl" yaml:"downloadUrl"` // public, signed, short-lived URL; pass to PublishSite as the archive source
	ExpiresAt   time.Time `json:"expiresAt" yaml:"expiresAt"`     // when DownloadURL stops working
	Size        int       `json:"size" yaml:"size"`               // bytes uploaded
}

func (r *DropboxUploadResult) Table() [][]string {
	return [][]string{
		{"DOWNLOAD URL", "EXPIRES AT", "SIZE"},
		{r.DownloadURL, r.ExpiresAt.Format(time.RFC3339), strconv.Itoa(r.Size)},
	}
}

// DropboxUpload uploads opts.Content to the dropbox service and returns the
// resulting public download URL. The request is authenticated with the client's
// Auth (the same identity used for every other call), so the caller needs the
// dropbox.upload permission on opts.Project.
func (c *Client) DropboxUpload(ctx context.Context, opts *DropboxUploadOptions) (*DropboxUploadResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("dropbox: options required")
	}
	if opts.Project == "" {
		return nil, fmt.Errorf("dropbox: project required")
	}
	if len(opts.Content) == 0 {
		return nil, fmt.Errorf("dropbox: content required")
	}

	base := strings.TrimSpace(opts.Endpoint)
	if base == "" {
		base = DefaultDropboxEndpoint
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}

	q := url.Values{}
	// Send the identifier as `project` (the project sid). The dropbox
	// service's `projectId` param is strictly the numeric project ID, which
	// the api's me.authorized rejects when handed a non-numeric sid — and a
	// sid is what every caller (CLI, MCP, this client) actually passes.
	q.Set("project", opts.Project)
	if opts.TTLDays >= 1 && opts.TTLDays <= 7 {
		q.Set("ttl", strconv.Itoa(opts.TTLDays))
	}
	if opts.Filename != "" {
		q.Set("filename", opts.Filename)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"?"+q.Encode(), bytes.NewReader(opts.Content))
	if err != nil {
		return nil, err
	}
	// dropbox rejects an empty body via ContentLength==0; bytes.Reader sets it,
	// but be explicit so an intermediary can't drop it.
	req.ContentLength = int64(len(opts.Content))
	req.Header.Set("Content-Type", "application/octet-stream")
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
	// failure and {ok:true,result:{downloadUrl,expiresAt}} on success.
	var env struct {
		OK     bool `json:"ok"`
		Result struct {
			DownloadURL string    `json:"downloadUrl"`
			ExpiresAt   time.Time `json:"expiresAt"`
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
	if env.Result.DownloadURL == "" {
		return nil, fmt.Errorf("dropbox: server returned an empty download URL")
	}

	return &DropboxUploadResult{
		DownloadURL: env.Result.DownloadURL,
		ExpiresAt:   env.Result.ExpiresAt,
		Size:        len(opts.Content),
	}, nil
}
