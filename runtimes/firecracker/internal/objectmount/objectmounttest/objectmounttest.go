// Package objectmounttest serves the object mount protocol (api.Mount) from
// memory, for tests of object mounts.
package objectmounttest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jaredfolkins/vmcp/api"
)

// Upstream keeps objects in memory below Prefix, such as "/root". With a
// Token it refuses a request without that bearer token.
type Upstream struct {
	Prefix string
	Token  string

	mu       sync.Mutex
	objects  map[string][]byte
	modified map[string]time.Time
	chunked  map[string]bool
}

// New returns an empty upstream.
func New(prefix, token string) *Upstream {
	return &Upstream{Prefix: prefix, Token: token, objects: map[string][]byte{}, modified: map[string]time.Time{}, chunked: map[string]bool{}}
}

// Put stores an object.
func (u *Upstream) Put(rel string, data []byte) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.objects[rel] = data
	u.modified[rel] = time.Now()
}

// Object returns an object and whether its write was chunked.
func (u *Upstream) Object(rel string) (data []byte, ok, chunked bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	data, ok = u.objects[rel]
	return data, ok, u.chunked[rel]
}

type entry struct {
	Name   string `json:"name"`
	Folder bool   `json:"folder"`
	Size   int64  `json:"size"`
}

func (u *Upstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if u.Token != "" && r.Header.Get("Authorization") != "Bearer "+u.Token {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rel, ok := strings.CutPrefix(r.URL.Path, u.Prefix+"/")
	if !ok && r.URL.Path != u.Prefix {
		http.NotFound(w, r)
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Query().Has("list"):
		u.list(w, rel)
	case r.Method == http.MethodHead:
		data, ok := u.objects[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("Last-Modified", u.modified[rel].UTC().Format(http.TimeFormat))
	case r.Method == http.MethodGet:
		data, ok := u.objects[rel]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if spec := r.Header.Get("Range"); spec != "" {
			var first, last int
			if _, err := fmt.Sscanf(spec, "bytes=%d-%d", &first, &last); err != nil || first >= len(data) {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			last = min(last, len(data)-1)
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", first, last, len(data)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(data[first : last+1])
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	case r.Method == http.MethodPut:
		limit := r.ContentLength
		if limit < 0 {
			parsed, err := strconv.ParseInt(r.Header.Get(api.ObjectMountMaxBytesHeader), 10, 64)
			if err != nil {
				w.WriteHeader(http.StatusLengthRequired)
				return
			}
			limit = parsed
		}
		data, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil || int64(len(data)) > limit {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		u.objects[rel] = data
		u.modified[rel] = time.Now()
		u.chunked[rel] = r.ContentLength < 0
		w.WriteHeader(http.StatusCreated)
	case r.Method == http.MethodDelete:
		if _, ok := u.objects[rel]; !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(u.objects, rel)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (u *Upstream) list(w http.ResponseWriter, folder string) {
	seen := map[string]bool{}
	entries := []entry{}
	for key, data := range u.objects {
		rest, ok := strings.CutPrefix(key, folder)
		if !ok || rest == "" {
			continue
		}
		if name, _, nested := strings.Cut(rest, "/"); nested {
			if !seen[name] {
				seen[name] = true
				entries = append(entries, entry{Name: name + "/", Folder: true})
			}
			continue
		}
		entries = append(entries, entry{Name: rest, Size: int64(len(data))})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	_ = json.NewEncoder(w).Encode(map[string]any{"entries": entries, "next": ""})
}
