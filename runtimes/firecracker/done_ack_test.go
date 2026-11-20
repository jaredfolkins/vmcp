//go:build linux

package firecracker

import (
	"bufio"
	"flag"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

var doneAckConfig = flag.String("vmcp-done-ack-config", "testdata/done-ack.hujson", "HuJSON file with the done answer case")

// TestHostAnswersTheDoneMessage proves that the host answers the done
// message of the agent after it recorded the exit. The agent restarts the
// guest only after this answer, so a restart cannot lose the exit report.
// A failure here detects a host that sends no answer, which makes each
// guest wait for the answer limit, or an answer before the exit is read.
func TestHostAnswersTheDoneMessage(t *testing.T) {
	var in struct {
		Lines      string `json:"lines"`
		WantCode   int    `json:"want_code"`
		WantAnswer string `json:"want_answer"`
	}
	readHuJSON(t, *doneAckConfig, &in)
	if in.Lines == "" || in.WantAnswer == "" {
		t.Fatal("done answer input is incomplete")
	}
	m := &Machine{log: slog.New(slog.DiscardHandler)}
	host, guest := net.Pipe()
	done := make(chan struct{})
	go func() {
		m.readEvents(host)
		close(done)
	}()
	if err := guest.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = io.WriteString(guest, in.Lines) }()
	answer, err := bufio.NewReader(guest).ReadString('\n')
	if err != nil || answer != in.WantAnswer {
		t.Fatalf("host answer = %q, %v; want %q", answer, err, in.WantAnswer)
	}
	// The answer comes after the exit line, so the exit is recorded now.
	m.mu.Lock()
	exit := m.exit
	m.mu.Unlock()
	if exit == nil || exit.Code != in.WantCode {
		t.Errorf("exit at the answer = %+v, want code %d", exit, in.WantCode)
	}
	_ = guest.Close()
	<-done
}
