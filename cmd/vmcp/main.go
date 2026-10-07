// Command vmcp runs the VM control plane.
//
// Usage:
//
//	vmcp serve --listen ADDR --credential-file PATH
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
	"syscall"
	"time"

	"github.com/jaredfolkins/vmcp/internal/server"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker"
)

const (
	defaultListen         = ":8080"
	defaultCredentialFile = "/run/secrets/vmcp-credential"
	defaultHealthURL      = "http://127.0.0.1:8080/healthz"
	shutdownTimeout       = 10 * time.Second
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(os.Args[1:], log); err != nil {
		log.Error("vmcp failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string, log *slog.Logger) error {
	if len(args) == 0 {
		return errors.New("usage: vmcp serve|healthcheck [flags]")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], log)
	case "healthcheck":
		return healthcheck(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(args []string, log *slog.Logger) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", defaultListen, "listen address on the service network")
	credentialFile := fs.String("credential-file", defaultCredentialFile, "owner-private file with the caller bearer credential")
	if err := fs.Parse(args); err != nil {
		return err
	}
	credential, err := server.LoadCredential(*credentialFile)
	if err != nil {
		return err
	}
	host := firecracker.DefaultHost
	srv := &http.Server{
		Addr:              *listen,
		Handler:           server.New(server.Config{Credential: credential, Status: host.Status, Logger: log}),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	st := host.Status()
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
