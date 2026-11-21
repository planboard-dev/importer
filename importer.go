package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jedib0t/go-pretty/v6/progress"
)

// maxAnswer bounds how much of an answer is read, findings included.
const maxAnswer = 16 << 20

// manifestAttempts is how many manifests one run sends when another run
// replaces its generation meanwhile.
const manifestAttempts = 3

type options struct {
	url   string
	dir   string
	token string
	check bool
	out   io.Writer
	// terminal shows progress bars on out.
	terminal bool
}

// file is one entry of the manifest, with where it is on disk.
type file struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`

	local string
}

type manifestAnswer struct {
	Generation int64    `json:"generation"`
	Expires    string   `json:"expires"`
	Held       []string `json:"held"`
}

type landAnswer struct {
	Landed bool   `json:"landed"`
	Commit string `json:"commit"`
	Files  int    `json:"files"`
}

// refusal is an answer outside 2xx, as the protocol writes it.
type refusal struct {
	Status   int    `json:"-"`
	Message  string `json:"error"`
	Code     string `json:"code"`
	Problems []struct {
		Path    string `json:"path"`
		Message string `json:"message"`
	} `json:"problems"`
	Missing []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"missing"`
	Findings []struct {
		Path    string `json:"path"`
		Line    int    `json:"line"`
		Message string `json:"message"`
	} `json:"findings"`
}

func (r *refusal) Error() string {
	if r.Message != "" {
		return r.Message
	}

	return fmt.Sprintf("the service answered %d %s", r.Status, http.StatusText(r.Status))
}

type importer struct {
	options

	base   string
	client *http.Client
}

// run imports the root and writes what happened, the last line saying whether
// the root landed. It is true only when the root landed, or with check when it
// would land.
func run(ctx context.Context, opts options) bool {
	// There is no timeout on a whole request, since a PUT of 20 MiB on a slow
	// link takes a while; a service that never connects, never finishes the
	// handshake or never answers is given up on.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 30 * time.Second
	transport.ResponseHeaderTimeout = 5 * time.Minute

	im := &importer{
		options: opts,
		client: &http.Client{
			Transport: transport,
			// A redirect is answered as it is, never followed with the token.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	outcome, err := im.importRoot(ctx)
	if err != nil {
		var refused *refusal
		if errors.As(err, &refused) {
			im.printRefusal(refused)
		}

		fmt.Fprintf(im.out, "The root did not land: %s\n", clean(err.Error()))

		return false
	}

	fmt.Fprintln(im.out, outcome)

	return true
}

func (im *importer) importRoot(ctx context.Context) (string, error) {
	base, err := importURL(im.url)
	if err != nil {
		return "", err
	}
	im.base = base

	im.token = strings.TrimSpace(im.token)
	if im.token == "" {
		return "", fmt.Errorf("%s is not set, copy the command the accounts pages showed", tokenVariable)
	}

	root, err := resolveRoot(im.dir)
	if err != nil {
		return "", err
	}

	files, err := im.walk(root)
	if err != nil {
		return "", err
	}

	err = im.hash(files)
	if err != nil {
		return "", err
	}

	// A 409 generation from a PUT or the land means another run sent a
	// manifest meanwhile, so the manifest is sent again and the run carries on
	// from its answer.
	var landed landAnswer

	for attempt := 1; ; attempt++ {
		landed, err = im.send(ctx, files)

		var refused *refusal
		if errors.As(err, &refused) && refused.Code == "generation" && attempt < manifestAttempts {
			fmt.Fprintln(im.out, "Another run sent a manifest meanwhile, sending it again")
			continue
		}

		// Where sending stopped is said only once the run gives up.
		var stop *stopped
		if errors.As(err, &stop) {
			fmt.Fprintf(im.out, "Stopped after sending %d of %d files (%s of %s); a rerun sends only what the service does not hold yet.\n",
				stop.sent, stop.files, progress.FormatBytes(stop.sentBytes), progress.FormatBytes(stop.totalBytes))
		}
		if err != nil {
			return "", err
		}

		break
	}

	switch {
	case im.check:
		return fmt.Sprintf("The root would land: %d files, nothing landed since --check was given", landed.Files), nil
	case landed.Landed:
		return fmt.Sprintf("The root landed: %d files in commit %s", landed.Files, clean(landed.Commit)), nil
	default:
		return "", errors.New("the service answered the land without landing")
	}
}

// send sends the manifest, the files the service does not hold and the land.
func (im *importer) send(ctx context.Context, files []file) (landAnswer, error) {
	var answer manifestAnswer
	var landed landAnswer

	err := im.call(ctx, http.MethodPost, "/manifest", "application/json", map[string]any{"files": files}, &answer)
	if err != nil {
		return landed, err
	}

	sent, err := im.sendFiles(ctx, answer, files)
	if err != nil {
		return landed, err
	}

	fmt.Fprintf(im.out, "Files sent: %d, held by the service already: %d\n", sent, len(answer.Held))

	err = im.call(ctx, http.MethodPost, "/land", "application/json", map[string]bool{"check": im.check}, &landed)

	return landed, err
}

// stopped is a PUT that failed part way, with how far sending got.
type stopped struct {
	err        error
	sent       int
	files      int
	sentBytes  int64
	totalBytes int64
}

func (s *stopped) Error() string { return s.err.Error() }

func (s *stopped) Unwrap() error { return s.err }

// sendFiles sends every content the manifest names that the service does not
// hold, once for each sha256 however many paths share it.
func (im *importer) sendFiles(ctx context.Context, answer manifestAnswer, files []file) (int, error) {
	held := make(map[string]bool, len(answer.Held))
	for _, sum := range answer.Held {
		held[sum] = true
	}

	var pending []file
	var total int64

	for _, f := range files {
		if held[f.SHA256] {
			continue
		}
		held[f.SHA256] = true

		pending = append(pending, f)
		total += f.Size
	}

	if len(pending) == 0 {
		return 0, nil
	}

	m := im.startMeter("", total)

	var sentBytes int64

	for i, f := range pending {
		err := im.put(ctx, answer.Generation, f, m)
		if err != nil {
			m.stop(false)

			return i, &stopped{err: err, sent: i, files: len(pending), sentBytes: sentBytes, totalBytes: total}
		}

		sentBytes += f.Size
	}

	m.stop(true)

	return len(pending), nil
}

// put sends one file's content, checking first that it is still what was
// hashed.
func (im *importer) put(ctx context.Context, generation int64, f file, m *meter) error {
	content, err := os.ReadFile(f.local)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(content)
	if int64(len(content)) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
		return fmt.Errorf("%s changed while it was sent, run the import again", clean(f.Path))
	}

	path := "/files/" + strconv.FormatInt(generation, 10) + "/" + f.SHA256

	return im.call(ctx, http.MethodPut, path, "application/octet-stream", upload{content: content, m: m}, nil)
}

// upload is a body sent as it is, feeding a meter as it goes.
type upload struct {
	content []byte
	m       *meter
}

// call sends one request below the import URL. An upload is sent as it is and
// anything else as JSON. A 2xx answer is decoded into into when it is not nil,
// and any other answer is returned as a refusal.
func (im *importer) call(ctx context.Context, method, path, contentType string, body any, into any) error {
	sending, ok := body.(upload)
	if !ok {
		content, err := json.Marshal(body)
		if err != nil {
			return err
		}

		sending = upload{content: content}
	}

	req, err := http.NewRequestWithContext(ctx, method, im.base+path, &countingReader{r: bytes.NewReader(sending.content), m: sending.m})
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(sending.content))

	req.Header.Set("Authorization", "Bearer "+im.token)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "planboard-importer/"+version)

	resp, err := im.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach the service: %w", err)
	}
	defer resp.Body.Close()

	answer, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
	if err != nil {
		return fmt.Errorf("could not read the service's answer: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		refused := &refusal{}
		if json.Unmarshal(answer, refused) != nil {
			refused = &refusal{}
		}
		refused.Status = resp.StatusCode

		return refused
	}

	if into == nil {
		return nil
	}

	err = json.Unmarshal(answer, into)
	if err != nil {
		return fmt.Errorf("the service answered %d with a body that is not the protocol's JSON", resp.StatusCode)
	}

	return nil
}

// printRefusal writes the problems, missing files and findings a refusal
// carries, one a line.
func (im *importer) printRefusal(r *refusal) {
	for _, p := range r.Problems {
		if p.Path == "" {
			fmt.Fprintln(im.out, clean(p.Message))
		} else {
			fmt.Fprintf(im.out, "%s: %s\n", clean(p.Path), clean(p.Message))
		}
	}

	for _, m := range r.Missing {
		fmt.Fprintf(im.out, "%s: has not arrived\n", clean(m.Path))
	}

	for _, f := range r.Findings {
		if f.Line > 0 {
			fmt.Fprintf(im.out, "%s:%d: %s\n", clean(f.Path), f.Line, clean(f.Message))
		} else {
			fmt.Fprintf(im.out, "%s: %s\n", clean(f.Path), clean(f.Message))
		}
	}
}

// walk lists the regular files below root without following links, skipping
// dotfiles, dot-directories, symlinks and anything else that is not a regular
// file, and writes what it skipped, a directory once.
func (im *importer) walk(root string) ([]file, error) {
	var files []file

	err := filepath.WalkDir(root, func(local string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if local == root {
			return nil
		}

		rel, err := filepath.Rel(root, local)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		switch {
		case !utf8.ValidString(rel):
			// JSON would replace the bytes, so the path would not be the file's.
			im.skipped(rel, "is not valid UTF-8")
			if d.IsDir() {
				return fs.SkipDir
			}
		case strings.HasPrefix(d.Name(), ".") && d.IsDir():
			im.skipped(rel+"/", "starts with a dot")
			return fs.SkipDir
		case strings.HasPrefix(d.Name(), "."):
			im.skipped(rel, "starts with a dot")
		case d.Type()&fs.ModeSymlink != 0:
			im.skipped(rel, "is a symlink")
		case d.IsDir():
		case !d.Type().IsRegular():
			im.skipped(rel, "is not a regular file")
		default:
			info, err := d.Info()
			if err != nil {
				return err
			}

			files = append(files, file{Path: rel, Size: info.Size(), local: local})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return files, nil
}

func (im *importer) skipped(path, why string) {
	fmt.Fprintf(im.out, "Skipped %s: %s\n", clean(path), why)
}

// hash sets the size and sha256 of every file from its content.
func (im *importer) hash(files []file) error {
	var total int64
	for _, f := range files {
		total += f.Size
	}

	m := im.startMeter(fmt.Sprintf("Hashing %d files", len(files)), total)

	for i := range files {
		err := hashFile(&files[i], m)
		if err != nil {
			m.stop(false)
			return err
		}
	}

	m.stop(true)

	return nil
}

func hashFile(f *file, m *meter) error {
	content, err := os.Open(f.local)
	if err != nil {
		return err
	}
	defer content.Close()

	h := sha256.New()

	size, err := io.Copy(io.MultiWriter(h, m), content)
	if err != nil {
		return err
	}

	f.Size = size
	f.SHA256 = hex.EncodeToString(h.Sum(nil))

	return nil
}

// resolveRoot resolves a start directory that is a symlink, since the walk does
// not descend one.
func resolveRoot(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}

	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s is not a directory", clean(dir))
	}

	return resolved, nil
}

// importURL checks the import URL and returns it without a trailing slash. It
// is not echoed back in an error, in case a token was pasted into it.
func importURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("the import URL is not an http or https URL")
	}

	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("the import URL takes no user, query or fragment, give it as the accounts pages showed it")
	}

	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return "", errors.New("the import URL has to be https, since the token goes with every call")
	}

	return strings.TrimRight(u.String(), "/"), nil
}

func loopback(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// clean strips control characters from text that came from the network or the
// file system before it is written to a terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, strings.ToValidUTF8(s, "?"))
}
