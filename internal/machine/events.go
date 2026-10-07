package machine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jaredfolkins/vmcp/api"
)

// eventLog is the ordered, durable event log of one machine. It keeps the
// events in memory and appends each one to a file.
type eventLog struct {
	mu     sync.Mutex
	path   string
	events []api.Event
	closed bool
	notify chan struct{}
}

func newEventLog(path string) *eventLog {
	return &eventLog{path: path, notify: make(chan struct{})}
}

// loadEventLog reads a log written by an earlier process.
func loadEventLog(path string) (*eventLog, error) {
	l := newEventLog(path)
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		var ev api.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			l.events = append(l.events, ev)
		}
	}
	return l, nil
}

// append assigns the next sequence number and the time, then stores the
// event.
func (l *eventLog) append(ev api.Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return fmt.Errorf("event log is closed")
	}
	ev.Seq = uint64(len(l.events)) + 1
	ev.Time = time.Now().UTC()
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(b, '\n'))
	cerr := f.Close()
	if werr != nil || cerr != nil {
		return fmt.Errorf("append event: %w", werr)
	}
	l.events = append(l.events, ev)
	close(l.notify)
	l.notify = make(chan struct{})
	return nil
}

// close marks the log complete. Followers stop after the last event.
func (l *eventLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.closed {
		l.closed = true
		close(l.notify)
	}
}

// follow calls fn for each event after seq. With wait, it waits for new
// events until the log is closed or ctx ends.
func (l *eventLog) follow(ctx context.Context, after uint64, wait bool, fn func(api.Event) error) error {
	next := after
	for {
		l.mu.Lock()
		pending := append([]api.Event(nil), l.events[min(int(next), len(l.events)):]...)
		closed, notify := l.closed, l.notify
		l.mu.Unlock()
		for _, ev := range pending {
			if err := fn(ev); err != nil {
				return err
			}
			next = ev.Seq
		}
		if !wait || (closed && len(pending) == 0) {
			return nil
		}
		if closed {
			continue
		}
		select {
		case <-notify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
