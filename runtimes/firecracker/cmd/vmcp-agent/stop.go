//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

// errLineTooLong is the error for a host message longer than its bound.
var errLineTooLong = errors.New("host message exceeds its size limit")

// readLine reads one newline-terminated line of at most limit bytes.
func readLine(r *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			clear(line)
			return nil, errLineTooLong
		}
		line = append(line, chunk...)
		if err == nil {
			return line, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

// readHostMessages reads the host messages after Secrets until the
// connection ends. A stop request goes to stop and a connect request to
// ports; other types are ignored.
func (e *events) readHostMessages(stop *stopper, ports *porter) {
	defer close(e.gone)
	acked := false
	for {
		line, err := readLine(e.r, agentproto.MaxLineBytes)
		if err != nil {
			return
		}
		var m agentproto.Message
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.Type {
		case agentproto.TypeStop:
			stop.request(time.Duration(max(m.GraceMS, 0)) * time.Millisecond)
		case agentproto.TypeConnect:
			go ports.connect(m.ConnID, m.Port)
		case agentproto.TypeDoneAck:
			if !acked {
				acked = true
				close(e.acked)
			}
		}
	}
}

// stopper delivers a host stop request to the process group: SIGTERM at
// once, and SIGKILL when the process still runs after the grace period. A
// request that arrives before the process starts applies when it starts.
// The process runs in its own session, so its process group ID is its PID.
type stopper struct {
	mu        sync.Mutex
	pid       int
	ended     bool
	requested bool
	grace     time.Duration
	// onStop runs once at the first stop request, before the signal.
	onStop []func()
}

// whenStopped runs fn at the first stop request, or now when one came.
func (s *stopper) whenStopped(fn func()) {
	s.mu.Lock()
	requested := s.requested
	if !requested {
		s.onStop = append(s.onStop, fn)
	}
	s.mu.Unlock()
	if requested {
		fn()
	}
}

// request records the first stop request and signals a running process.
func (s *stopper) request(grace time.Duration) {
	s.mu.Lock()
	if s.requested {
		s.mu.Unlock()
		return
	}
	s.requested, s.grace = true, grace
	pid, ended := s.pid, s.ended
	onStop := s.onStop
	s.onStop = nil
	s.mu.Unlock()
	for _, fn := range onStop {
		fn()
	}
	if pid > 0 && !ended {
		s.signal(pid, grace)
	}
}

// started records the process and applies an earlier request.
func (s *stopper) started(pid int) {
	s.mu.Lock()
	s.pid = pid
	requested, grace := s.requested, s.grace
	s.mu.Unlock()
	if requested {
		s.signal(pid, grace)
	}
}

// exited records that the process ended, so that a pending SIGKILL is not
// sent to a reused process group ID.
func (s *stopper) exited() {
	s.mu.Lock()
	s.ended = true
	s.mu.Unlock()
}

func (s *stopper) signal(pid int, grace time.Duration) {
	_ = unix.Kill(-pid, unix.SIGTERM)
	time.AfterFunc(grace, func() {
		s.mu.Lock()
		ended := s.ended
		s.mu.Unlock()
		if !ended {
			_ = unix.Kill(-pid, unix.SIGKILL)
		}
	})
}
