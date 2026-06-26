package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// site.go is a client-side helper (not an arpc api.Interface method) that
// publishes a local directory as a static-web release. It drives the raw-HTTP
// publish endpoints the apiserver mounts beside arpc:
//
//	POST /sites/{project}/{name}/uploads        -> open an upload session
//	PUT  /sites/{project}/{name}/blobs/{sha256} -> upload one content-addressed blob
//	PUT  /sites/{project}/{name}/releases/{sha} -> commit the manifest (release)
//
// The committed release is referenced by a Static deployment via
// DeploymentDeploy.Site (site://<bucket>/<project>/<name>@<release-sha>). The
// upload requires the `site.publish` permission and active billing, enforced by
// the server. Blobs are content-addressed (sha256), so re-publishing an
// unchanged site re-uploads nothing.

// SitePublishOptions configures Client.PublishSite.
type SitePublishOptions struct {
	Project     string // project id that owns the deployment
	Name        string // deployment name to publish the release under
	Dir         string // local directory whose contents form the static site
	Environment string // "production" (default) or "pr-<n>"
	SPA         bool   // serve index.html for unmatched paths (single-page app)
	NotFound    string // custom 404 document path, e.g. "404.html"

	// Progress, when non-nil, is called as the upload proceeds so callers can
	// render a progress bar. It is invoked once up front with Done == 0 and the
	// final Total/BytesTotal (Path empty), then once after each file is
	// processed. It is called synchronously on the calling goroutine, so keep it
	// fast and non-blocking.
	Progress func(SitePublishProgress)
}

// SitePublishProgress is a single progress update emitted during PublishSite.
// Done/Total count files; Uploaded+Skipped count blobs actually checked against
// the server (duplicate content within the run is neither uploaded nor skipped,
// so Uploaded+Skipped can trail Done).
type SitePublishProgress struct {
	Done       int    // files processed so far
	Total      int    // total regular files in the release
	Uploaded   int    // blobs newly uploaded so far
	Skipped    int    // blobs already present on the server (dedup) so far
	BytesDone  int64  // bytes of processed files so far
	BytesTotal int64  // total bytes across all files
	Path       string // request path of the file just processed (e.g. "/index.html"); empty on the initial announcement
}

// SitePublishResult is the outcome of a successful PublishSite.
type SitePublishResult struct {
	SiteRef    string `json:"siteRef" yaml:"siteRef"`       // site://<bucket>/<project>/<name>@<release-sha>; pass to a Static deployment's Site
	ReleaseSHA string `json:"releaseSha" yaml:"releaseSha"` // sha256 of the release manifest (== the @ suffix of SiteRef)
	Files      int    `json:"files" yaml:"files"`           // files in the release
	Uploaded   int    `json:"uploaded" yaml:"uploaded"`     // blobs newly uploaded
	Skipped    int    `json:"skipped" yaml:"skipped"`       // blobs already present (content-addressed dedup)
}

func (r *SitePublishResult) Table() [][]string {
	return [][]string{
		{"SITE REF", "RELEASE", "FILES", "UPLOADED", "SKIPPED"},
		{
			r.SiteRef,
			shortReleaseSHA(r.ReleaseSHA),
			strconv.Itoa(r.Files),
			strconv.Itoa(r.Uploaded),
			strconv.Itoa(r.Skipped),
		},
	}
}

// siteManifestEntry / siteManifest mirror the apiserver's release manifest JSON
// shape. The release-sha the server content-addresses against is sha256 of the
// exact manifest bytes we PUT; encoding/json sorts map keys, so the bytes are
// deterministic for a given input.
type siteManifestEntry struct {
	Blob  string `json:"blob"`
	CT    string `json:"ct"`
	Cache string `json:"cache"`
}

type siteManifest struct {
	Release     string                       `json:"release"` // always "" in the body; the server verifies sha256(body) == URL release-sha
	CreatedAt   string                       `json:"createdAt"`
	Environment string                       `json:"environment"`
	SPA         bool                         `json:"spa"`
	NotFound    string                       `json:"notFound"`
	Files       map[string]siteManifestEntry `json:"files"`
}

// PublishSite uploads opts.Dir as a static-web release for opts.Project /
// opts.Name and returns the committed site ref. It opens an upload session,
// content-addresses and uploads every regular file as a blob (skipping any the
// server already has), then commits a release manifest. The returned
// SiteRef/ReleaseSHA can be deployed with a Static deployment:
//
//	c.Deployment().Deploy(ctx, &api.DeploymentDeploy{
//		Project: ..., Location: ..., Name: ...,
//		Type:    api.DeploymentTypeStatic,
//		Site:    res.SiteRef,
//	})
func (c *Client) PublishSite(ctx context.Context, opts *SitePublishOptions) (*SitePublishResult, error) {
	if opts == nil {
		return nil, fmt.Errorf("site: options required")
	}
	if opts.Project == "" {
		return nil, fmt.Errorf("site: project required")
	}
	if opts.Name == "" {
		return nil, fmt.Errorf("site: name required")
	}
	if opts.Dir == "" {
		return nil, fmt.Errorf("site: dir required")
	}
	info, err := os.Stat(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("site: dir: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("site: dir %q is not a directory", opts.Dir)
	}

	environment := opts.Environment
	if environment == "" {
		environment = "production"
	}

	base := "sites/" + url.PathEscape(opts.Project) + "/" + url.PathEscape(opts.Name)

	// 1. walk the directory once to collect the regular files (and their sizes)
	// that form the release. Doing this before opening a session lets us reject an
	// empty publish without a server round-trip and gives Progress a real Total.
	type fileItem struct {
		reqPath string // manifest key / request path, e.g. "/index.html"
		abs     string // absolute path on disk to read
		size    int64
	}
	var (
		items      []fileItem
		bytesTotal int64
	)
	err = filepath.WalkDir(opts.Dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil // skip dirs, symlinks, sockets, etc.
		}
		rel, err := filepath.Rel(opts.Dir, p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		items = append(items, fileItem{
			reqPath: "/" + filepath.ToSlash(rel),
			abs:     p,
			size:    info.Size(),
		})
		bytesTotal += info.Size()
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("site: %w", err)
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("site: no files to publish in %q", opts.Dir)
	}

	// 2. open an upload session.
	var session struct {
		Session string `json:"session"`
	}
	if err := c.siteDo(ctx, http.MethodPost, base+"/uploads", nil, nil, "", &session); err != nil {
		return nil, fmt.Errorf("site: open session: %w", err)
	}
	if session.Session == "" {
		return nil, fmt.Errorf("site: server returned an empty session id")
	}

	// 3. upload each regular file as a content-addressed blob (skipping any sha
	// already PUT this run) and build the manifest files map keyed by request
	// path. Progress, if set, is announced up front (Done 0 of Total) and once
	// after each file is processed.
	progress := opts.Progress
	if progress == nil {
		progress = func(SitePublishProgress) {}
	}
	res := &SitePublishResult{Files: len(items)}
	prog := SitePublishProgress{Total: len(items), BytesTotal: bytesTotal}
	progress(prog)

	files := map[string]siteManifestEntry{}
	uploaded := map[string]bool{} // blob shas PUT this run (content dedup)
	for _, it := range items {
		body, err := os.ReadFile(it.abs)
		if err != nil {
			return nil, fmt.Errorf("site: %w", err)
		}
		sha := sha256Hex(body)
		ct := siteContentType(it.reqPath)
		cache := siteCacheClass(it.reqPath)
		files[it.reqPath] = siteManifestEntry{Blob: sha, CT: ct, Cache: cache}

		if !uploaded[sha] {
			uploaded[sha] = true

			q := url.Values{}
			q.Set("session", session.Session)
			q.Set("ct", ct)
			q.Set("cache", cache)
			var blob struct {
				SHA256  string `json:"sha256"`
				Existed bool   `json:"existed"`
			}
			if err := c.siteDo(ctx, http.MethodPut, base+"/blobs/"+sha, q, body, ct, &blob); err != nil {
				return nil, fmt.Errorf("site: upload %s: %w", it.reqPath, err)
			}
			if blob.Existed {
				res.Skipped++
			} else {
				res.Uploaded++
			}
		}

		prog.Done++
		prog.BytesDone += it.size
		prog.Uploaded = res.Uploaded
		prog.Skipped = res.Skipped
		prog.Path = it.reqPath
		progress(prog)
	}

	// 4. assemble the manifest, content-address it, and commit the release. The
	// release-sha is sha256 of the exact bytes we PUT (see siteManifest.Release).
	manifestBody, err := json.Marshal(siteManifest{
		Release:     "",
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		Environment: environment,
		SPA:         opts.SPA,
		NotFound:    opts.NotFound,
		Files:       files,
	})
	if err != nil {
		return nil, fmt.Errorf("site: encode manifest: %w", err)
	}
	releaseSHA := sha256Hex(manifestBody)

	q := url.Values{}
	q.Set("session", session.Session)
	var release struct {
		SiteRef string `json:"siteRef"`
	}
	if err := c.siteDo(ctx, http.MethodPut, base+"/releases/"+releaseSHA, q, manifestBody, "application/json", &release); err != nil {
		return nil, fmt.Errorf("site: commit release: %w", err)
	}

	res.SiteRef = release.SiteRef
	res.ReleaseSHA = releaseSHA
	return res, nil
}

// siteDo performs one raw-HTTP publish call and decodes the {ok,result,error}
// envelope into result. It reuses the client's endpoint/auth/HTTPClient. Unlike
// invoke, the body is arbitrary bytes (not JSON-encoded) and some failure paths
// return a plain-text body, which it surfaces verbatim.
func (c *Client) siteDo(ctx context.Context, method, p string, q url.Values, body []byte, contentType string, result any) error {
	u := c.endpoint() + p
	if len(q) > 0 {
		u += "?" + q.Encode()
	}

	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, r)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	if c.Auth != nil {
		c.Auth(req)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body)

	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}

	// The {ok,result,error} envelope is used on success and on resolve/auth
	// failures; other guard failures (bad session, sha mismatch) return a
	// plain-text body via http.Error.
	var env struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &env) == nil && (env.OK || env.Error.Message != "") {
		if !env.OK {
			return (&Error{Message: env.Error.Message}).apiError()
		}
		if result != nil && len(env.Result) > 0 {
			return json.Unmarshal(env.Result, result)
		}
		return nil
	}

	// Not an envelope: a transport/guard error with a plain-text (or empty) body.
	msg := string(bytes.TrimSpace(data))
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("status %d: %s", resp.StatusCode, msg)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func shortReleaseSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// siteExtContentType mirrors the apiserver's canonical extension table
// (server/site.go) plus the action's extra entries (.map/.pdf/.mp4). The client
// stamps Content-Type via the ?ct= query param, which the server trusts.
var siteExtContentType = map[string]string{
	".html":  "text/html; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".js":    "text/javascript; charset=utf-8",
	".mjs":   "text/javascript; charset=utf-8",
	".json":  "application/json; charset=utf-8",
	".map":   "application/json; charset=utf-8",
	".svg":   "image/svg+xml",
	".xml":   "application/xml; charset=utf-8",
	".txt":   "text/plain; charset=utf-8",
	".png":   "image/png",
	".jpg":   "image/jpeg",
	".jpeg":  "image/jpeg",
	".webp":  "image/webp",
	".gif":   "image/gif",
	".ico":   "image/x-icon",
	".avif":  "image/avif",
	".woff2": "font/woff2",
	".woff":  "font/woff",
	".ttf":   "font/ttf",
	".wasm":  "application/wasm",
	".pdf":   "application/pdf",
	".mp4":   "video/mp4",
}

func siteContentType(reqPath string) string {
	if ct, ok := siteExtContentType[ext(reqPath)]; ok {
		return ct
	}
	return "application/octet-stream"
}

// siteCacheClass mirrors the server's cache classes: HTML-class (revalidate)
// for documents the gateway must re-check, immutable for fingerprinted assets.
func siteCacheClass(reqPath string) string {
	switch ext(reqPath) {
	case ".html", ".json", ".xml", ".txt", ".map":
		return "html"
	default:
		return "immutable"
	}
}

func ext(p string) string {
	return path.Ext(strings.ToLower(p))
}
