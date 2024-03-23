// Package vfm provides an interface to Veno File Manager.
package vfm

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/vfm/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/pacer"
	"github.com/rclone/rclone/lib/rest"
	"golang.org/x/net/html"
	"hg.sr.ht/~dchapes/humanize"
)

const (
	minSleep      = 10 * time.Millisecond
	maxSleep      = 2 * time.Second
	decayConstant = 2 // bigger for slower decay, exponential
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "vfm",
		Description: "Veno File Manager",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "url",
			Help:     "URL of Veno File Manager instance (eg. https://veno.es/filemanager/).",
			Required: true,
		}, {
			Name:      "cookie",
			Sensitive: true,
			Examples: []fs.OptionExample{{
				Value: "vfm_809731232=ioshagaepee6ief9uosh",
			}},
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	URL    string `config:"url"`
	Cookie string `config:"cookie"`
}

// ItemMeta defines metadata we cache for each Item ID
type ItemMeta struct {
	SequenceID int64  // the most recent event processed for this item
	ParentID   string // ID of the parent directory of this item
	Name       string // leaf name of this item
}

// Fs represents a remote vfm
type Fs struct {
	name     string       // name of this remote
	root     string       // the path we are working on
	opt      Options      // parsed options
	features *fs.Features // optional features
	srv      *rest.Client // the connection to the server
	pacer    *fs.Pacer    // pacer for API calls
}

type Object struct {
	fs      *Fs       // what this object is part of
	remote  string    // The remote path
	size    int64     // size of the object
	modTime time.Time // modification time of the object
	href    string
}

// ------------------------------------------------------------

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("vfm root '%s'", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// parsePath parses a box 'url'
func parsePath(path string) (root string) {
	root = strings.Trim(path, "/")
	return
}

// retryErrorCodes is a slice of error codes that we will retry
var retryErrorCodes = []int{
	429, // Too Many Requests.
	500, // Internal Server Error
	502, // Bad Gateway
	503, // Service Unavailable
	504, // Gateway Timeout
	509, // Bandwidth Limit Exceeded
}

// shouldRetry returns a boolean as to whether this resp and err
// deserve to be retried.  It returns the err as a convenience
func shouldRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	return false, err

	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	authRetry := false

	if resp != nil && resp.StatusCode == 401 && strings.Contains(resp.Header.Get("Www-Authenticate"), "expired_token") {
		authRetry = true
		fs.Debugf(nil, "Should retry: %v", err)
	}

	// Box API errors which should be retries
	if apiErr, ok := err.(*api.Error); ok && apiErr.Code == "operation_blocked_temporary" {
		fs.Debugf(nil, "Retrying API error %v", err)
		return true, err
	}

	return authRetry || fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

// errorHandler parses a non 2xx error response into an error
func errorHandler(resp *http.Response) error {
	fs.Errorf(nil, "rest error: %v", resp)
	panic(resp)
	// // Decode error response
	// errResponse := new(api.Error)
	// err := rest.DecodeJSON(resp, &errResponse)
	// if err != nil {
	// 	fs.Debugf(nil, "Couldn't decode error response: %v", err)
	// }
	// if errResponse.Code == "" {
	// 	errResponse.Code = resp.Status
	// }
	// if errResponse.Status == 0 {
	// 	errResponse.Status = resp.StatusCode
	// }
	// return errResponse
}

// NewFs constructs an Fs from the path, container:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	fs.Debugf(nil, "NewFs(name = %q, root = %q)", name, root)

	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	client := fshttp.NewClient(ctx)

	f := &Fs{
		name: name,
		// root:  root,
		opt:   *opt,
		srv:   rest.NewClient(client).SetRoot(opt.URL).SetHeader("x-requested-with", "XMLHttpRequest").SetHeader("Accept-Encoding", "plain"),
		pacer: fs.NewPacer(ctx, pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
	}
	f.features = (&fs.Features{
		CaseInsensitive:         true,
		CanHaveEmptyDirectories: true,
		BucketBased:             true,
	}).Fill(ctx, f)
	f.srv.SetErrorHandler(errorHandler)

	// TODO: use rest.Client.SetCookie?
	if f.opt.Cookie != "" {
		f.srv.SetHeader("Cookie", f.opt.Cookie)
	}

	// Check if file
	entries, err := f.list(ctx, "", path.Dir(root))
	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		if e.Remote() == root {
			if _, ok := e.(fs.Directory); ok {
				fs.Debugf(nil, "root is directory")
				f.root = root
				return f, nil
			} else {
				fs.Debugf(nil, "root is file")
				f.root = path.Dir(root)
				return f, fs.ErrorIsFile
			}
		}
	}

	// Check if directory
	entries, err = f.list(ctx, "", root)
	if err != nil {
		return nil, err
	}

	if len(entries) != 0 {
		f.root = root
		return f, nil
	}

	return nil, fs.ErrorDirNotFound
}

func (f *Fs) rootSlash() string {
	if f.root == "" {
		return f.root
	} else if strings.HasSuffix(f.root, "/") {
		return f.root
	} else {
		return f.root + "/"
	}
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	fs.Debugf(nil, "NewObject(%q)", remote)

	entries, err := f.list(ctx, f.rootSlash(), path.Dir(remote))
	if err != nil {
		return nil, err
	}

	var object fs.Object
	for _, e := range entries {
		if e.Remote() == remote {
			object = e.(fs.Object)
			break
		}
	}

	if object == nil {
		return nil, fs.ErrorObjectNotFound
	}

	return object, nil
}

func htmlAttr(htmlBody string, element string, attr string) (string, error) {
	doc, err := html.Parse(bytes.NewBufferString(htmlBody))
	if err != nil {
		return "", err
	}
	var value string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == element {
			for _, a := range n.Attr {
				if a.Key == attr {
					value = a.Val
					break
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return value, nil
}

func htmlText(htmlBody string) (string, error) {
	z := html.NewTokenizer(bytes.NewBufferString(htmlBody))

	var value bytes.Buffer
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if z.Err() == io.EOF {
				break
			}
			return "", z.Err()
		} else if tt == html.TextToken {
			value.Write(z.Text())
		}
	}
	return value.String(), nil
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	fs.Debugf(nil, "List(%q)", dir)
	return f.list(ctx, f.rootSlash(), dir)
}

func (f *Fs) list(ctx context.Context, root string, dir string) (entries fs.DirEntries, err error) {
	opts := rest.Opts{
		Method:     "GET",
		Path:       "vfm-admin/ajax/get-dirs.php",
		Parameters: url.Values{},
	}
	opts.Parameters.Set("dir_b64", base64.StdEncoding.EncodeToString([]byte(root+dir)))
	opts.Parameters.Set("draw", "1")
	opts.Parameters.Set("length", "-1")
	var resp *http.Response
	var dirs struct {
		RecordsTotal int64 `json:"recordsTotal"`
		Data         []struct {
			FolderName string `json:"folder_name"`
			LastChange string `json:"last_change"`
		} `json:"data"`
	}
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &dirs)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		fs.Errorf(nil, "resp: %v", resp)
		body, _ := io.ReadAll(resp.Body)
		fs.Errorf(nil, "body: %v", body)
		return nil, err
	}

	fs.Infof(nil, "get-dirs: %+v", dirs)

	for _, dir := range dirs.Data {
		href, err := htmlAttr(dir.FolderName, "a", "href")
		if err != nil {
			return nil, err
		}
		fs.Infof(nil, "folder href %v", href)

		u, err := url.Parse(href)
		if err != nil {
			return nil, err
		}

		path := u.Query().Get("dir")

		name, found := strings.CutPrefix(path, root)
		if !found {
			return nil, fmt.Errorf("get-dirs response did not contain root: %+q", dir)
		}

		mtime, err := time.Parse("02/01/2006 - 15:04", dir.LastChange)
		if err != nil {
			return nil, err
		}

		entries = append(entries, fs.NewDir(name, mtime))
	}

	// get-files
	opts = rest.Opts{
		Method:     "GET",
		Path:       "vfm-admin/ajax/get-files.php",
		Parameters: url.Values{},
	}
	opts.Parameters.Set("dir_b64", base64.StdEncoding.EncodeToString([]byte(root+dir)))
	opts.Parameters.Set("draw", "1")
	opts.Parameters.Set("length", "-1")
	var files struct {
		RecordsTotal int64 `json:"recordsTotal"`
		Data         []struct {
			FileName   string `json:"file_name"`
			LastChange string `json:"last_change"`
			Size       string `json:"size"`
		} `json:"data"`
	}
	err = f.pacer.Call(func() (bool, error) {
		resp, err = f.srv.CallJSON(ctx, &opts, nil, &files)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		fs.Errorf(nil, "resp: %v", resp)
		body, _ := io.ReadAll(resp.Body)
		fs.Errorf(nil, "body: %v", body)
		return nil, err
	}

	fs.Infof(nil, "get-files: %+v", files)

	for _, file := range files.Data {
		name, err := htmlAttr(file.FileName, "a", "data-name")
		if err != nil {
			return nil, err
		}
		fs.Infof(nil, "file name %v", name)

		lastChange, err := htmlText(file.LastChange)
		if err != nil {
			return nil, err
		}

		mtime, err := time.Parse("02/01/2006 - 15:04", lastChange)
		if err != nil {
			return nil, err
		}

		sizeText, err := htmlText(file.Size)
		if err != nil {
			return nil, err
		}

		size, err := humanize.Parse(strings.ReplaceAll(sizeText, "B", ""), humanize.Bytes)
		if err != nil {
			return nil, err
		}

		href, err := htmlAttr(file.FileName, "a", "href")
		if err != nil {
			return nil, err
		}

		entry := &Object{
			fs:      f,
			remote:  path.Join(dir, name),
			size:    int64(size),
			modTime: mtime,
			href:    href,
		}
		fs.Debugf(nil, "file entry %#v", entry)
		entries = append(entries, entry)
	}

	return entries, nil
}

func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}

func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}

func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return nil, fs.ErrorNotImplemented
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return fs.ErrorNotImplemented
}

// Precision return the precision of this Fs
func (f *Fs) Precision() time.Duration {
	return time.Minute
}

// Shutdown shutdown the fs
func (f *Fs) Shutdown(ctx context.Context) error {
	return nil
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the SHA-1 of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.size
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorNotImplemented
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	if o.href == "" {
		return nil, fmt.Errorf("can't download - no href: %#v", o)
	}
	var resp *http.Response
	opts := rest.Opts{
		Method:  "GET",
		Path:    o.href,
		Options: options,
	}
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.Call(ctx, &opts)
		return shouldRetry(ctx, resp, err)
	})
	if err != nil {
		return nil, err
	}
	o.size = resp.ContentLength
	return resp.Body, err
}

func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (err error) {
	return fs.ErrorNotImplemented
}

func (o *Object) Remove(ctx context.Context) error {
	return fs.ErrorNotImplemented
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return ""
}

// Check the interfaces are satisfied
var (
	_ fs.Fs     = (*Fs)(nil)
	_ fs.Object = (*Object)(nil)
	_ fs.IDer   = (*Object)(nil)
)
