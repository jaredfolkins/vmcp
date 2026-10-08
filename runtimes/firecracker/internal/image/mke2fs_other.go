//go:build !linux

package image

import "syscall"

// mke2fsAttr adds nothing outside Linux.
func mke2fsAttr() *syscall.SysProcAttr { return nil }
