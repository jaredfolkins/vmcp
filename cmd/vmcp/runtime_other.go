//go:build !linux

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"

	"github.com/jaredfolkins/vmcp/internal/machine"
)

type runtimeFlags struct{}

func (f *runtimeFlags) register(*flag.FlagSet) {}

func (f *runtimeFlags) attrs() []any { return nil }

func checkProcess() error { return nil }

func newRuntime(context.Context, runtimeFlags, *slog.Logger) (machine.Runtime, string, error) {
	return nil, "", errors.New("vmcp has no runtime for this operating system yet")
}

func hostCommand(context.Context, []string, io.Writer, *slog.Logger) error {
	return errors.New("vmcp has no host commands for this operating system yet")
}
