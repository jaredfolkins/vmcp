// Command vmcp runs the VM control plane.
//
// Usage:
//
//	vmcp serve [flags]
//	vmcp healthcheck [--url URL]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/internal/server"
	"github.com/jaredfolkins/vmcp/internal/trace"
)

const (
	defaultHealthURL = "http://127.0.0.1:8080/health"
	shutdownTimeout  = 10 * time.Second
)

func main() {
	level := new(slog.LevelVar)
	log := slog.New(trace.NewHandler(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	if err := run(os.Args[1:], log, level); err != nil {
		log.Error("vmcp failed", "code", "vmcp_failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger, level *slog.LevelVar) error {
	if len(args) == 0 {
		return errors.New("usage: vmcp serve|healthcheck [flags]")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], log, level)
	case "healthcheck":
		return healthcheck(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string, log *slog.Logger, level *slog.LevelVar) error {
	var rf runtimeFlags
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	logLevel := fs.String("log-level", "info", "minimum log level: debug, info, warn, or error")
	listen := fs.String("listen", ":8080", "listen address on the private service network")
	credentialFile := fs.String("credential-file", "/run/secrets/vmcp-credential", "owner-private file with the caller bearer credential")
	maxMachines := fs.Int("max-machines", 16, "machines that may hold a slot at once")
	rf.register(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		return fmt.Errorf("log-level %q: use debug, info, warn, or error", *logLevel)
	}
	log.Info("vmcp starting", append([]any{"log_level", level.Level().String(), "listen", *listen,
		"max_machines", *maxMachines}, rf.attrs()...)...)
	if err := requireNoNewPrivs(); err != nil {
		return err
	}
	credential, err := server.LoadCredential(*credentialFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	rt, stateRoot, err := newRuntime(ctx, rf, log)
	if err != nil {
		return err
	}
	mgr, err := machine.New(ctx, rt, machine.Config{Dir: stateRoot, MaxMachines: *maxMachines, Logger: log})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           server.New(server.Config{Credential: credential, Service: mgr, Logger: log}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	st := mgr.Status()
	log.Info("vmcp serving", "listen", *listen, "runtime", st.Runtime, "release", st.Release, "ready", st.Ready)
	select {
	case err := <-errc:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	log.Info("vmcp stopped")
	return nil
}

// requireNoNewPrivs refuses to run unless no_new_privs is set. Every
// jailer and VMM process inherits it. Run the container with
// no-new-privileges.
func requireNoNewPrivs() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("read process status: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "NoNewPrivs:"); ok && strings.TrimSpace(v) == "1" {
			return nil
		}
	}
	return errors.New("vmcp needs no_new_privs; run it with the no-new-privileges security option")
}

// healthcheck exits with an error unless the health route answers 204.
func healthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	url := fs.String("url", defaultHealthURL, "health URL")
	if err := fs.Parse(args); err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(*url)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("health status %d", resp.StatusCode)
	}
	return nil
}
