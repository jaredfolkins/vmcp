//go:build !linux

package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"

	"github.com/jaredfolkins/vmcp/internal/machine"
)

type runtimeFlags struct{}

func (f *runtimeFlags) register(*flag.FlagSet) {}

func newRuntime(context.Context, runtimeFlags, *slog.Logger) (machine.Runtime, string, error) {
	return nil, "", errors.New("vmcp has no runtime for this operating system yet")
}
