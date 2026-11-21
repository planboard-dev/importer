package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jedib0t/go-pretty/v6/progress"
)

const testToken = "dGhpcyBpcyBhIHRlc3QgdG9rZW4gb2YgNDMgY2hhcnM"

type finding struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// fakeService answers the import protocol for one board, roadmap, and records
// what the client sent.
type fakeService struct {
	t *testing.T

	mu         sync.Mutex
	generation int64
	manifest   []file
	held       map[string][]byte
	landed     bool

	// findings are answered by a land that is not a check.
	findings []finding
	// problems are answered by the next manifest.
	problems []map[string]string
	// staleOnce answers the next PUT with 409 generation.
	staleOnce bool
	// staleFrom answers every PUT from that number on, from 1, with 409
	// generation.
	staleFrom int
	// staleLandOnce answers the next land with 409 generation, and
	// staleLandAlways every land.
	staleLandOnce   bool
	staleLandAlways bool
	// replacedAt answers the PUT of that number, from 1, with 409 replaced,
	// as when Show command issued a new token meanwhile.
	replacedAt int
	putCalls   int

	urls  []string
	puts  []string
	lands []bool
}

func newFake(t *testing.T) (*fakeService, string) {
	t.Helper()

	f := &fakeService{t: t, held: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)

	return f, srv.URL + "/import/roadmap"
}

func (f *fakeService) refuse(w http.ResponseWriter, status int, code string, extra map[string]any) {
	body := map[string]any{"error": "refused with " + code, "code": code}
	for k, v := range extra {
		body[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (f *fakeService) answer(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

func (f *fakeService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.urls = append(f.urls, r.URL.String()+" "+r.RequestURI)

	if r.Header.Get("Authorization") != "Bearer "+testToken {
		f.refuse(w, http.StatusUnauthorized, "token", nil)
		return
	}

	if f.landed {
		f.refuse(w, http.StatusGone, "landed", nil)
		return
	}

	rest, ok := strings.CutPrefix(r.URL.Path, "/import/roadmap/")
	if !ok {
		f.refuse(w, http.StatusNotFound, "route", nil)
		return
	}

	parts := strings.Split(rest, "/")

	switch {
	case r.Method == http.MethodPost && rest == "manifest":
		f.serveManifest(w, r)
	case r.Method == http.MethodPut && len(parts) == 3 && parts[0] == "files":
		f.servePut(w, r, parts[1], parts[2])
	case r.Method == http.MethodPost && rest == "land":
		f.serveLand(w, r)
	default:
		f.refuse(w, http.StatusNotFound, "route", nil)
	}
}

func (f *fakeService) serveManifest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Files []file `json:"files"`
	}

	err := json.NewDecoder(r.Body).Decode(&body)
	if err != nil {
		f.refuse(w, http.StatusBadRequest, "malformed", nil)
		return
	}

	var problems []map[string]string
	for _, fl := range body.Files {
		for _, part := range strings.Split(fl.Path, "/") {
			if strings.HasPrefix(part, ".") {
				problems = append(problems, map[string]string{"path": fl.Path, "message": "starts with a dot"})
			}
		}
	}
	problems = append(problems, f.problems...)
	f.problems = nil

	if len(problems) > 0 {
		f.refuse(w, http.StatusUnprocessableEntity, "manifest", map[string]any{"problems": problems})
		return
	}

	f.generation++
	f.manifest = body.Files

	named := map[string]bool{}
	for _, fl := range body.Files {
		named[fl.SHA256] = true
	}

	held := []string{}
	for sum := range f.held {
		if named[sum] {
			held = append(held, sum)
		} else {
			delete(f.held, sum)
		}
	}

	f.answer(w, http.StatusOK, map[string]any{"generation": f.generation, "expires": "2026-11-22T10:15:00Z", "held": held})
}

func (f *fakeService) servePut(w http.ResponseWriter, r *http.Request, generation, sum string) {
	f.putCalls++
	if f.putCalls == f.replacedAt {
		f.refuse(w, http.StatusConflict, "replaced", nil)
		return
	}

	if f.staleOnce || (f.staleFrom > 0 && f.putCalls >= f.staleFrom) {
		f.staleOnce = false
		f.generation++
		f.refuse(w, http.StatusConflict, "generation", nil)
		return
	}

	if generation != strconv.FormatInt(f.generation, 10) {
		f.refuse(w, http.StatusConflict, "generation", nil)
		return
	}

	size := int64(-1)
	for _, fl := range f.manifest {
		if fl.SHA256 == sum {
			size = fl.Size
		}
	}
	if size < 0 {
		f.refuse(w, http.StatusConflict, "not_named", nil)
		return
	}

	if r.ContentLength < 0 {
		f.refuse(w, http.StatusLengthRequired, "length", nil)
		return
	}
	if r.ContentLength != size {
		f.refuse(w, http.StatusUnprocessableEntity, "size", nil)
		return
	}

	content, _ := io.ReadAll(io.LimitReader(r.Body, size))
	got := sha256.Sum256(content)
	if hex.EncodeToString(got[:]) != sum {
		f.refuse(w, http.StatusUnprocessableEntity, "hash", nil)
		return
	}

	f.held[sum] = content
	f.puts = append(f.puts, sum)

	f.answer(w, http.StatusCreated, map[string]any{"sha256": sum, "held": true})
}

func (f *fakeService) serveLand(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Check bool `json:"check"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	f.lands = append(f.lands, body.Check)

	if f.staleLandOnce || f.staleLandAlways {
		f.staleLandOnce = false
		f.generation++
		f.refuse(w, http.StatusConflict, "generation", nil)
		return
	}

	var missing []map[string]string
	for _, fl := range f.manifest {
		if _, ok := f.held[fl.SHA256]; !ok {
			missing = append(missing, map[string]string{"path": fl.Path, "sha256": fl.SHA256})
		}
	}
	if len(missing) > 0 {
		f.refuse(w, http.StatusConflict, "missing", map[string]any{"missing": missing})
		return
	}

	if len(f.findings) > 0 {
		f.refuse(w, http.StatusUnprocessableEntity, "findings", map[string]any{"findings": f.findings})
		return
	}

	if body.Check {
		f.answer(w, http.StatusOK, map[string]any{"landed": false, "files": len(f.manifest)})
		return
	}

	f.landed = true
	f.answer(w, http.StatusOK, map[string]any{"landed": true, "commit": "3b18e512dba79e4c8300dd08aeb37f8e728b8dad", "files": len(f.manifest)})
}

// paths lists the paths of the last manifest.
func (f *fakeService) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var paths []string
	for _, fl := range f.manifest {
		paths = append(paths, fl.Path)
	}

	return paths
}

// checkToken fails the test when the token was in any URL the fake saw or in
// the output.
func (f *fakeService) checkToken(out string) {
	f.t.Helper()

	f.mu.Lock()
	defer f.mu.Unlock()

	for _, u := range f.urls {
		if strings.Contains(u, testToken) {
			f.t.Fatalf("the token was in the URL %q", u)
		}
	}

	if strings.Contains(out, testToken) {
		f.t.Fatalf("the token was in the output:\n%s", out)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	err := os.MkdirAll(filepath.Dir(path), 0o755)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(path, []byte(content), 0o644)
	if err != nil {
		t.Fatal(err)
	}
}

// makeRoot writes a small planning root and returns its directory.
func makeRoot(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "planboard.yaml"), "tenant: acme\n")
	writeFile(t, filepath.Join(dir, "Roadmap", "project.md"), "---\ntitle: Roadmap\n---\n")
	writeFile(t, filepath.Join(dir, "Roadmap", "items", "login.md"), "---\ntitle: Login\n---\n")
	writeFile(t, filepath.Join(dir, "Roadmap", "items", "copy.md"), "---\ntitle: Login\n---\n")

	return dir
}

func runImport(t *testing.T, base, dir string, check bool) (bool, string, string) {
	t.Helper()

	var out bytes.Buffer

	ok := run(context.Background(), options{url: base, dir: dir, token: testToken, check: check, out: &out})
	text := out.String()
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")

	return ok, text, lines[len(lines)-1]
}

func TestImportLands(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	ok, out, last := runImport(t, base, dir, false)
	if !ok {
		t.Fatalf("the import did not land:\n%s", out)
	}
	if !strings.HasPrefix(last, "The root landed: 4 files in commit 3b18e512") {
		t.Fatalf("unexpected last line %q", last)
	}

	want := []string{"Roadmap/items/copy.md", "Roadmap/items/login.md", "Roadmap/project.md", "planboard.yaml"}
	got := fake.paths()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("the manifest named %v, want %v", got, want)
	}

	// copy.md and login.md share a content, sent once.
	if len(fake.puts) != 3 {
		t.Fatalf("sent %d contents, want 3", len(fake.puts))
	}

	fake.checkToken(out)
}

func TestImportSkipsDotfilesAndSymlinks(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	writeFile(t, filepath.Join(dir, ".git", "config"), "[core]\n")
	writeFile(t, filepath.Join(dir, ".git", "objects", "ab", "cdef"), "object")
	writeFile(t, filepath.Join(dir, ".lock"), "")
	writeFile(t, filepath.Join(dir, "Roadmap", ".DS_Store"), "junk")

	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.md"), "secret")

	for link, target := range map[string]string{
		filepath.Join(dir, "Roadmap", "items", "link.md"): filepath.Join(dir, "Roadmap", "project.md"),
		filepath.Join(dir, "Roadmap", "elsewhere"):        outside,
	} {
		err := os.Symlink(target, link)
		if err != nil {
			t.Fatal(err)
		}
	}

	ok, out, _ := runImport(t, base, dir, false)
	if !ok {
		t.Fatalf("the import did not land:\n%s", out)
	}

	want := []string{"Roadmap/items/copy.md", "Roadmap/items/login.md", "Roadmap/project.md", "planboard.yaml"}
	got := fake.paths()
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("the manifest named %v, want %v", got, want)
	}

	for _, want := range []string{
		"Skipped .git/: starts with a dot\n",
		"Skipped .lock: starts with a dot\n",
		"Skipped Roadmap/.DS_Store: starts with a dot\n",
		"Skipped Roadmap/items/link.md: is a symlink\n",
		"Skipped Roadmap/elsewhere: is a symlink\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output lacks %q:\n%s", want, out)
		}
	}

	if strings.Contains(out, "config") || strings.Contains(out, "objects") {
		t.Fatalf("a skipped directory's files were reported:\n%s", out)
	}

	fake.checkToken(out)
}

func TestImportSymlinkedStartDirectory(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	link := filepath.Join(t.TempDir(), "Dropbox-root")
	err := os.Symlink(dir, link)
	if err != nil {
		t.Fatal(err)
	}

	ok, out, _ := runImport(t, base, link, false)
	if !ok {
		t.Fatalf("the import did not land:\n%s", out)
	}
	if len(fake.paths()) != 4 {
		t.Fatalf("the manifest named %v", fake.paths())
	}

	fake.checkToken(out)
}

func TestImportRerunSendsOnlyChanged(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	fake.findings = []finding{{Path: "Roadmap/items/login.md", Line: 2, Message: "title is wrong"}}

	ok, out, _ := runImport(t, base, dir, false)
	if ok {
		t.Fatalf("the import landed despite findings:\n%s", out)
	}
	if len(fake.puts) != 3 {
		t.Fatalf("the first run sent %d contents, want 3", len(fake.puts))
	}

	writeFile(t, filepath.Join(dir, "Roadmap", "items", "login.md"), "---\ntitle: Login fixed\n---\n")
	fake.findings = nil
	fake.puts = nil

	ok, out, last := runImport(t, base, dir, false)
	if !ok {
		t.Fatalf("the rerun did not land:\n%s", out)
	}

	sum := sha256.Sum256([]byte("---\ntitle: Login fixed\n---\n"))
	if !slices.Equal(fake.puts, []string{hex.EncodeToString(sum[:])}) {
		t.Fatalf("the rerun sent %v, want only the changed file", fake.puts)
	}
	// The old content of login.md is still named, as copy.md.
	if !strings.Contains(out, "Files sent: 1, held by the service already: 3") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if !strings.HasPrefix(last, "The root landed:") {
		t.Fatalf("unexpected last line %q", last)
	}

	fake.checkToken(out)
}

func TestImportFindingsExitNonzero(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	fake.findings = []finding{
		{Path: "Roadmap/items/login.md", Line: 3, Message: "status: \"later\" is not \x1b[31mone\x1b[0m of them\x07"},
		{Path: "Roadmap/\x1b]0;title\x07project.md", Line: 0, Message: "whole\nfile"},
	}

	ok, out, last := runImport(t, base, dir, false)
	if ok {
		t.Fatalf("the import landed despite findings:\n%s", out)
	}

	for _, want := range []string{
		"Roadmap/items/login.md:3: status: \"later\" is not [31mone[0m of them\n",
		"Roadmap/]0;titleproject.md: whole file\n",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output lacks %q:\n%s", want, out)
		}
	}

	for _, r := range out {
		if r != '\n' && (r < 0x20 || r == 0x7f) {
			t.Fatalf("the output holds the control character %q:\n%q", r, out)
		}
	}

	if last != "The root did not land: refused with findings" {
		t.Fatalf("unexpected last line %q", last)
	}

	fake.checkToken(out)
}

func TestImportManifestProblems(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	fake.problems = []map[string]string{
		{"path": "", "message": "the manifest names no project.md"},
		{"path": "Roadmap/notes.txt", "message": "not a path the board holds"},
	}

	ok, out, last := runImport(t, base, dir, false)
	if ok {
		t.Fatalf("the import landed despite problems:\n%s", out)
	}

	for _, want := range []string{"the manifest names no project.md\n", "Roadmap/notes.txt: not a path the board holds\n"} {
		if !strings.Contains(out, want) {
			t.Fatalf("the output lacks %q:\n%s", want, out)
		}
	}
	if last != "The root did not land: refused with manifest" {
		t.Fatalf("unexpected last line %q", last)
	}
	if len(fake.puts) != 0 || len(fake.lands) != 0 {
		t.Fatalf("a refused manifest went on to send %v and land %v", fake.puts, fake.lands)
	}
}

func TestImportCheck(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	ok, out, last := runImport(t, base, dir, true)
	if !ok {
		t.Fatalf("the check failed:\n%s", out)
	}
	if !slices.Equal(fake.lands, []bool{true}) || fake.landed {
		t.Fatalf("the land was called with %v, landed %v", fake.lands, fake.landed)
	}
	if !strings.HasPrefix(last, "The root would land: 4 files") {
		t.Fatalf("unexpected last line %q", last)
	}

	fake.findings = []finding{{Path: "Roadmap/project.md", Line: 1, Message: "bad"}}

	ok, out, _ = runImport(t, base, dir, true)
	if ok {
		t.Fatalf("a check with findings passed:\n%s", out)
	}

	fake.checkToken(out)
}

func TestImportResendsManifestOnGeneration(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	fake.staleOnce = true

	ok, out, _ := runImport(t, base, dir, false)
	if !ok {
		t.Fatalf("the import did not land:\n%s", out)
	}
	if !strings.Contains(out, "Another run sent a manifest meanwhile, sending it again\n") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if fake.generation != 3 {
		t.Fatalf("generation is %d, want 3", fake.generation)
	}
	if strings.Contains(out, "Stopped after") {
		t.Fatalf("a retry that landed said it stopped:\n%s", out)
	}

	fake.checkToken(out)
}

func TestImportStopLineOnlyWhenGivingUp(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	// The first attempt sends copy.md and is refused at project.md; the
	// next two are refused at their first PUT, of project.md and
	// planboard.yaml.
	fake.staleFrom = 2

	ok, out, last := runImport(t, base, dir, false)
	if ok {
		t.Fatalf("the import landed:\n%s", out)
	}

	want := "Stopped after sending 0 of 2 files (" + progress.FormatBytes(0) + " of " + progress.FormatBytes(36) + "); a rerun sends only what the service does not hold yet.\n"
	if strings.Count(out, "Stopped after") != 1 || !strings.Contains(out, want) {
		t.Fatalf("the output lacks %q once, from the last attempt:\n%s", want, out)
	}
	if strings.Count(out, "Another run sent a manifest meanwhile") != manifestAttempts-1 {
		t.Fatalf("unexpected retries:\n%s", out)
	}
	if last != "The root did not land: refused with generation" {
		t.Fatalf("unexpected last line %q", last)
	}
}

func TestImportResendsManifestOnLandGeneration(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	fake.staleLandOnce = true

	ok, out, last := runImport(t, base, dir, false)
	if !ok {
		t.Fatalf("the import did not land:\n%s", out)
	}
	if !strings.Contains(out, "Another run sent a manifest meanwhile, sending it again\n") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	if !strings.Contains(out, "Files sent: 0, held by the service already: 3\n") {
		t.Fatalf("the second manifest did not find every file held:\n%s", out)
	}
	if fake.generation != 3 || len(fake.lands) != 2 {
		t.Fatalf("generation is %d with %d lands, want 3 and 2", fake.generation, len(fake.lands))
	}
	if !strings.HasPrefix(last, "The root landed:") {
		t.Fatalf("unexpected last line %q", last)
	}

	fake.checkToken(out)
}

func TestImportGivesUpOnGeneration(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	fake.staleLandAlways = true

	ok, out, last := runImport(t, base, dir, false)
	if ok {
		t.Fatalf("the import landed:\n%s", out)
	}
	if len(fake.lands) != manifestAttempts {
		t.Fatalf("landed %d times, want %d", len(fake.lands), manifestAttempts)
	}
	if last != "The root did not land: refused with generation" {
		t.Fatalf("unexpected last line %q", last)
	}
}

func TestImportSkipsInvalidUTF8Names(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)

	bad := filepath.Join(dir, "Roadmap", "items", "bad\xff.md")

	err := os.WriteFile(bad, []byte("bad"), 0o644)
	if err != nil {
		t.Skipf("this file system takes no name that is not valid UTF-8: %v", err)
	}

	ok, out, _ := runImport(t, base, dir, false)
	if !ok {
		t.Fatalf("the import did not land:\n%s", out)
	}
	if !strings.Contains(out, "Skipped Roadmap/items/bad?.md: is not valid UTF-8\n") {
		t.Fatalf("the output lacks the skip:\n%s", out)
	}
	if len(fake.paths()) != 4 {
		t.Fatalf("the manifest named %v", fake.paths())
	}
}

func TestImportProgressKeepsLinesWhole(t *testing.T) {
	fake, base := newFake(t)
	dir := makeRoot(t)
	writeFile(t, filepath.Join(dir, ".lock"), "")

	fake.findings = []finding{{Path: "Roadmap/items/login.md", Line: 2, Message: "title is wrong"}}

	var out bytes.Buffer

	ok := run(context.Background(), options{url: base, dir: dir, token: testToken, out: &out, terminal: true})
	if ok {
		t.Fatalf("the import landed despite findings:\n%s", out.String())
	}

	text := out.String()
	if !strings.Contains(text, "Hashing 4 files ... done!") || !strings.Contains(text, "\ndone! [57B") {
		t.Fatalf("the output has no progress bars:\n%q", text)
	}
	if !strings.HasPrefix(text, "Skipped .lock: starts with a dot\n") {
		t.Fatalf("the skip is not the first line:\n%q", text)
	}
	if !strings.Contains(text, "\nFiles sent: 3, held by the service already: 0\n") {
		t.Fatalf("the sent line is not whole:\n%q", text)
	}
	if !strings.HasSuffix(text, "\nRoadmap/items/login.md:2: title is wrong\nThe root did not land: refused with findings\n") {
		t.Fatalf("the finding and the outcome are not the last lines:\n%q", text)
	}
}

func TestImportSaysWhereSendingStopped(t *testing.T) {
	fake, base := newFake(t)
	dir := t.TempDir()

	for i, name := range []string{"a", "b", "c", "d", "e"} {
		writeFile(t, filepath.Join(dir, "Roadmap", "items", name+".md"), strings.Repeat(name, 1000*(i+1)))
	}

	fake.replacedAt = 3

	ok, out, last := runImport(t, base, dir, false)
	if ok {
		t.Fatalf("the import landed:\n%s", out)
	}

	want := "Stopped after sending 2 of 5 files (" + progress.FormatBytes(3000) + " of " + progress.FormatBytes(15000) + "); a rerun sends only what the service does not hold yet.\n"
	if !strings.Contains(out, want) {
		t.Fatalf("the output lacks %q:\n%s", want, out)
	}
	if !strings.Contains(out, "(3.00KB of 15.00KB)") {
		t.Fatalf("the sizes are not as the bar shows them:\n%s", out)
	}
	if last != "The root did not land: refused with replaced" {
		t.Fatalf("unexpected last line %q", last)
	}
	if len(fake.puts) != 2 || len(fake.lands) != 0 {
		t.Fatalf("stored %d files and landed %d times, want 2 and 0", len(fake.puts), len(fake.lands))
	}
}

func TestImportRefusesWithoutToken(t *testing.T) {
	fake, base := newFake(t)

	var out bytes.Buffer

	ok := run(context.Background(), options{url: base, dir: makeRoot(t), out: &out})
	if ok || !strings.Contains(out.String(), tokenVariable+" is not set") {
		t.Fatalf("ran without a token:\n%s", out.String())
	}
	if len(fake.urls) != 0 {
		t.Fatalf("called the service without a token: %v", fake.urls)
	}
}

func TestImportURL(t *testing.T) {
	for raw, valid := range map[string]bool{
		"https://acme.planboard.example/import/roadmap":                        true,
		"https://acme.planboard.example/import/roadmap/":                       true,
		"http://127.0.0.1:8080/import/roadmap":                                 true,
		"http://localhost/import/roadmap":                                      true,
		"http://acme.localhost:8080/import/roadmap":                            true,
		"http://ACME.Localhost/import/roadmap":                                 true,
		"http://[::1]:8080/import/roadmap":                                     true,
		"http://acmelocalhost/import/roadmap":                                  false,
		"http://localhost.planboard.example/import/roadmap":                    false,
		"http://acme.planboard.example/import/roadmap":                         false,
		"https://acme.planboard.example/import/roadmap?token=" + testToken:     false,
		"https://user:" + testToken + "@acme.planboard.example/import/roadmap": false,
		"ftp://acme.planboard.example/import/roadmap":                          false,
		"acme.planboard.example/import/roadmap":                                false,
	} {
		got, err := importURL(raw)
		if (err == nil) != valid {
			t.Fatalf("importURL(%q) answered %q, %v", raw, got, err)
		}
		if err != nil && strings.Contains(err.Error(), testToken) {
			t.Fatalf("the error echoed the token: %v", err)
		}
		if err == nil && strings.HasSuffix(got, "/") {
			t.Fatalf("importURL(%q) kept a trailing slash", raw)
		}
	}
}
