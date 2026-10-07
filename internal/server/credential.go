package server

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	minCredentialBytes = 32
	maxCredentialBytes = 4096
)

// LoadCredential reads the caller bearer credential. The file must be one
// owner-private regular file that is not a symlink. One trailing newline is
// ignored.
func LoadCredential(path string) ([]byte, error) {
	path = filepath.Clean(path)
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect credential file: %w", err)
	}
	if !ownerPrivateFile(before) {
		return nil, errors.New("credential file must be one owner-private regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open credential file: %w", err)
	}
	defer func() { _ = f.Close() }()
	after, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened credential file: %w", err)
	}
	if !os.SameFile(before, after) || !ownerPrivateFile(after) {
		return nil, errors.New("credential file changed during secure open")
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}
	raw = bytes.TrimSuffix(raw, []byte("\n"))
	if len(raw) < minCredentialBytes || len(raw) > maxCredentialBytes {
		return nil, fmt.Errorf("credential must have %d to %d bytes", minCredentialBytes, maxCredentialBytes)
	}
	if bytes.ContainsAny(raw, " \t\r\n") {
		return nil, errors.New("credential must not contain whitespace")
	}
	return raw, nil
}

func ownerPrivateFile(fi os.FileInfo) bool {
	return fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 == 0
}
