// Package server is the HTTP server of the vmcp API.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
)

const maxJSONBody = 96 << 20

// Service is what the server needs from the machine manager.
type Service interface {
	Status() api.Status
	CreateImage(ctx context.Context, req api.ImageRequest) (api.Image, error)
	Image(id string) (api.Image, error)
	Images() []api.Image
	DeleteImage(id string) error
	CreateMachine(ctx context.Context, spec api.MachineSpec) (api.Machine, error)
	Machine(id string) (api.Machine, error)
	Machines(labels map[string]string) []api.Machine
	StartMachine(ctx context.Context, id string) (api.Machine, error)
	StopMachine(id string) (api.Machine, error)
	DeleteMachine(ctx context.Context, id string) (api.Machine, error)
	PutDrive(id, name string, r io.Reader) error
	GetDrive(id, name string) (*os.File, error)
	Events(ctx context.Context, id string, after uint64, follow bool, fn func(api.Event) error) error
	SelfTest(ctx context.Context) (api.SelfTestResult, error)
}

// Config holds the server dependencies.
type Config struct {
	// Credential is the bearer credential of the one caller.
	Credential []byte
	Service    Service
	Logger     *slog.Logger
}

type server struct {
	credentialSum [sha256.Size]byte
	svc           Service
	log           *slog.Logger
}

// New returns the API handler. Only RouteHealth works without the
// credential. A route that is not implemented answers not_found after
// authentication.
func New(cfg Config) http.Handler {
	s := &server{credentialSum: sha256.Sum256(cfg.Credential), svc: cfg.Service, log: cfg.Logger}
	mux := http.NewServeMux()
	mux.HandleFunc(api.RouteHealth, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	routes := map[string]http.HandlerFunc{
		api.RouteStatus:      func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.svc.Status()) },
		api.RouteCreateImage: s.createImage,
		api.RouteListImages:  func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.svc.Images()) },
		api.RouteGetImage: func(w http.ResponseWriter, r *http.Request) {
			s.reply(w, http.StatusOK)(s.svc.Image(r.PathValue("id")))
		},
		api.RouteDeleteImage:   s.deleteImage,
		api.RouteCreateMachine: s.createMachine,
		api.RouteListMachines:  s.listMachines,
		api.RouteGetMachine: func(w http.ResponseWriter, r *http.Request) {
			s.reply(w, http.StatusOK)(s.svc.Machine(r.PathValue("id")))
		},
		api.RouteStartMachine: func(w http.ResponseWriter, r *http.Request) {
			s.reply(w, http.StatusOK)(s.svc.StartMachine(r.Context(), r.PathValue("id")))
		},
		api.RouteStopMachine: func(w http.ResponseWriter, r *http.Request) {
			s.reply(w, http.StatusOK)(s.svc.StopMachine(r.PathValue("id")))
		},
		api.RouteDeleteMachine: func(w http.ResponseWriter, r *http.Request) {
			s.reply(w, http.StatusOK)(s.svc.DeleteMachine(r.Context(), r.PathValue("id")))
		},
		api.RoutePutDrive:      s.putDrive,
		api.RouteGetDrive:      s.getDrive,
		api.RouteMachineEvents: s.events,
		api.RouteSelfTest:      func(w http.ResponseWriter, r *http.Request) { s.reply(w, http.StatusOK)(s.svc.SelfTest(r.Context())) },
	}
	for pattern, h := range routes {
		mux.Handle(pattern, s.authenticate(h))
	}
	mux.Handle("/", s.authenticate(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, api.ErrNotFound, "route not found")
	})))
	return mux
}

func (s *server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(token))
		if !ok || subtle.ConstantTimeCompare(sum[:], s.credentialSum[:]) != 1 {
			s.log.Warn("api request rejected", "code", api.ErrUnauthorized, "method", r.Method, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, api.ErrUnauthorized, "a valid bearer credential is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// reply returns a function that writes a value or the error.
func (s *server) reply(w http.ResponseWriter, status int) func(any, error) {
	return func(v any, err error) {
		if err != nil {
			s.writeErr(w, err)
			return
		}
		writeJSON(w, status, v)
	}
}

func (s *server) createImage(w http.ResponseWriter, r *http.Request) {
	var req api.ImageRequest
	if !s.decode(w, r, &req) {
		return
	}
	s.reply(w, http.StatusCreated)(s.svc.CreateImage(r.Context(), req))
}

func (s *server) deleteImage(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.DeleteImage(r.PathValue("id")); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) createMachine(w http.ResponseWriter, r *http.Request) {
	var spec api.MachineSpec
	if !s.decode(w, r, &spec) {
		return
	}
	s.reply(w, http.StatusCreated)(s.svc.CreateMachine(r.Context(), spec))
}

func (s *server) listMachines(w http.ResponseWriter, r *http.Request) {
	labels := map[string]string{}
	for _, kv := range r.URL.Query()["label"] {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			writeError(w, http.StatusBadRequest, api.ErrInvalidRequest, "label filters use key=value")
			return
		}
		labels[k] = v
	}
	writeJSON(w, http.StatusOK, s.svc.Machines(labels))
}

func (s *server) putDrive(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.PutDrive(r.PathValue("id"), r.PathValue("name"), r.Body); err != nil {
		s.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getDrive(w http.ResponseWriter, r *http.Request) {
	f, err := s.svc.GetDrive(r.PathValue("id"), r.PathValue("name"))
	if err != nil {
		s.writeErr(w, err)
		return
	}
	defer func() { _ = f.Close() }()
	w.Header().Set("Content-Type", "application/x-tar")
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	_, _ = io.Copy(w, f)
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	after, err := strconv.ParseUint(q.Get("after"), 10, 64)
	if q.Get("after") == "" {
		after, err = 0, nil
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, api.ErrInvalidRequest, "after must be a sequence number")
		return
	}
	id := r.PathValue("id")
	if _, err := s.svc.Machine(id); err != nil {
		s.writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	enc := json.NewEncoder(w)
	_ = s.svc.Events(r.Context(), id, after, q.Get("follow") == "true", func(ev api.Event) error {
		if err := enc.Encode(ev); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	})
}

func (s *server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, api.ErrInvalidRequest, "request body is not valid JSON for this route")
		return false
	}
	return true
}

func (s *server) writeErr(w http.ResponseWriter, err error) {
	var me *machine.Error
	if !errors.As(err, &me) {
		s.log.Error("api request failed", "code", api.ErrInternal)
		writeError(w, http.StatusInternalServerError, api.ErrInternal, "internal error")
		return
	}
	status := map[api.ErrorCode]int{
		api.ErrInvalidRequest: http.StatusBadRequest,
		api.ErrNotFound:       http.StatusNotFound,
		api.ErrConflict:       http.StatusConflict,
		api.ErrCapacity:       http.StatusTooManyRequests,
		api.ErrUnavailable:    http.StatusServiceUnavailable,
	}[me.Code]
	if status == 0 {
		status = http.StatusInternalServerError
	}
	writeError(w, status, me.Code, me.Message)
}

func writeError(w http.ResponseWriter, status int, code api.ErrorCode, message string) {
	writeJSON(w, status, api.ErrorResponse{Error: api.Error{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
