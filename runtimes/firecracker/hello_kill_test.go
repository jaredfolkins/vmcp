//go:build linux

package firecracker

import (
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

var killBeforeHelloConfig = flag.String("vmcp-kill-before-hello-config", "testdata/kill-before-hello.hujson", "HuJSON file with the kill before hello case")

// TestHelloKillsAMachineKilledBeforeItsCgroup proves that a machine that
// was killed before the jailer created its cgroup is killed when its agent
// says hello, and gets no secrets. The first kill found no process, so the
// guest booted and ran its process although the caller had stopped it.
func TestHelloKillsAMachineKilledBeforeItsCgroup(t *testing.T) {
	var in struct {
		KillReason        string `json:"kill_reason"`
		Hello             string `json:"hello"`
		SecretEnv         string `json:"secret_env"`
		EventsUnpopulated string `json:"events_unpopulated"`
	}
	readHuJSON(t, *killBeforeHelloConfig, &in)
	if in.KillReason == "" || in.Hello == "" || in.SecretEnv == "" || in.EventsUnpopulated == "" {
		t.Fatal("kill before hello input is incomplete")
	}
	cg := filepath.Join(t.TempDir(), "machine")
	if err := os.Mkdir(cg, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"cgroup.kill": "", "cgroup.events": in.EventsUnpopulated} {
		if err := os.WriteFile(filepath.Join(cg, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	m := &Machine{cgroup: cg, killReason: in.KillReason, log: slog.New(slog.DiscardHandler),
		secrets: &agentproto.Secrets{Env: []string{in.SecretEnv}}}
	host, guest := net.Pipe()
	done := make(chan struct{})
	go func() {
		m.readEvents(host)
		close(done)
	}()
	if err := guest.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(guest, in.Hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	got, err := io.ReadAll(guest)
	if err != nil {
		t.Fatalf("read after hello: %v", err)
	}
	<-done

	if strings.Contains(string(got), in.SecretEnv) || len(got) != 0 {
		t.Errorf("host sent %q after hello, want nothing", got)
	}
	if kill, err := os.ReadFile(filepath.Join(cg, "cgroup.kill")); err != nil || string(kill) != "1" {
		t.Errorf("cgroup.kill = %q, %v; want 1", kill, err)
	}
}
