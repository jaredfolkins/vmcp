// Package server is the HTTP server of the vmcp API.
package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jaredfolkins/vmcp/api"
)

// Config holds the server dependencies.
type Config struct {
	// Credential is the bearer credential of the one caller.
	Credential []byte
	// Status reports the backend status.
	Status func() api.Status
	Logger *slog.Logger
}

type server struct {
	credentialSum [sha256.Size]byte
	status        func() api.Status
	log           *slog.Logger
}

// New returns the API handler. Only RouteHealth works without the
// credential. A route that is not implemented answers not_found after
// authentication.
func New(cfg Config) http.Handler {
	s := &server{
		credentialSum: sha256.Sum256(cfg.Credential),
		status:        cfg.Status,
		log:           cfg.Logger,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(api.RouteHealth, s.health)
	mux.Handle(api.RouteStatus, s.authenticate(http.HandlerFunc(s.getStatus)))
	mux.Handle("/", s.authenticate(http.HandlerFunc(s.notFound)))
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

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.status())
}

func (s *server) notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, http.StatusNotFound, api.ErrNotFound, "route not found")
}

func writeError(w http.ResponseWriter, status int, code api.ErrorCode, message string) {
	writeJSON(w, status, api.ErrorResponse{Error: api.Error{Code: code, Message: message}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
