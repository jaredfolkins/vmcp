//go:build linux

// Command vmcp-agent is PID 1 in every vmcp Firecracker guest.
//
// It reads its configuration from the config drive, builds a writable
// overlay root over the read-only image on the machine scratch disk, mounts
// the spec drives, writes the spec files, and runs the process as the image
// user. It streams output and its exit to the host over vsock, sends the tar
// of each writable drive, and then reboots, which stops the VM.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
)

const (
	upperMount  = "/.vmcp/upper"
	mergedRoot  = "/.vmcp/merged"
	chunkBytes  = 16 << 10
	connectWait = 10 * time.Second
	defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "selftest" && os.Getpid() != 1 {
		os.Exit(selfTest())
	}
	console := openConsole()
	ev, err := dialHost(agentproto.EventPort)
	if err != nil {
		_, _ = fmt.Fprintln(console, "vmcp-agent: event channel:", err)
		halt()
	}
	code, runErr := run(ev)
	if runErr != nil {
		ev.send(agentproto.Message{Type: agentproto.TypeStep, Step: "agent", Status: "failed", Detail: runErr.Error()})
		code = 127
	}
	ev.send(agentproto.Message{Type: agentproto.TypeExit, Code: code})
	ev.send(agentproto.Message{Type: agentproto.TypeDone})
	ev.close()
	halt()
}

func run(ev *events) (int, error) {
	if err := mountBase(); err != nil {
		return 0, err
	}
	ev.send(agentproto.Message{Type: agentproto.TypeHello, Version: agentproto.Version})
	secrets, err := ev.readSecrets()
	if err != nil {
		return 0, err
	}
	defer secrets.Clear()
	cfg, err := readConfig()
	if err != nil {
		return 0, err
	}
	if err := buildRoot(cfg, secrets); err != nil {
		return 0, err
	}
	// Secret entries come last, so they replace a same-named entry.
	cfg.Env = append(cfg.Env, secrets.Env...)
	ev.send(agentproto.Message{Type: agentproto.TypeStep, Step: "start-process", Status: "running"})
	code, err := runProcess(cfg, ev)
	if err != nil {
		return 0, err
	}
	ev.send(agentproto.Message{Type: agentproto.TypeStep, Step: "start-process", Status: "completed"})
	for _, d := range cfg.Drives {
		if !d.Writable {
			continue
		}
		if err := sendDrive(d); err != nil {
			return 0, fmt.Errorf("send drive %s: %w", d.Name, err)
		}
	}
	return code, nil
}

func openConsole() io.Writer {
	_ = unix.Mount("devtmpfs", "/dev", "devtmpfs", unix.MS_NOSUID, "")
	f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return io.Discard
	}
	return f
}

func mountBase() error {
	for _, m := range []struct{ src, dst, fstype string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
	} {
		if err := mountAt(m.src, m.dst, m.fstype, unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
			return err
		}
	}
	return nil
}

func readConfig() (agentproto.Config, error) {
	f, err := os.Open(agentproto.ConfigDevice)
	if err != nil {
		return agentproto.Config{}, fmt.Errorf("open config drive: %w", err)
	}
	defer func() { _ = f.Close() }()
	return agentproto.DecodeConfig(bufio.NewReader(f))
}

// buildRoot mounts the overlay root, the secret tmpfs, the spec drives, the
// spec files, and the secret files.
func buildRoot(cfg agentproto.Config, secrets *agentproto.Secrets) error {
	if err := mountAt(agentproto.UpperDevice, upperMount, "ext4", unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	for _, d := range []string{"upper", "work"} {
		if err := os.MkdirAll(filepath.Join(upperMount, d), 0o755); err != nil {
			return fmt.Errorf("create overlay %s: %w", d, err)
		}
	}
	opts := fmt.Sprintf("lowerdir=/,upperdir=%s/upper,workdir=%s/work", upperMount, upperMount)
	if err := mountAt("overlay", mergedRoot, "overlay", 0, opts); err != nil {
		return err
	}
	for _, m := range []struct {
		src, dst, fstype, data string
		flags                  uintptr
	}{
		{"proc", "proc", "proc", "", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{"sysfs", "sys", "sysfs", "", unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_RDONLY},
		{"devtmpfs", "dev", "devtmpfs", "", unix.MS_NOSUID},
		{"devpts", "dev/pts", "devpts", "newinstance,ptmxmode=0666", unix.MS_NOSUID | unix.MS_NOEXEC},
		{"tmpfs", "dev/shm", "tmpfs", "mode=1777", unix.MS_NOSUID | unix.MS_NODEV},
		// Secret files live only in guest memory, never in the upper disk.
		{"tmpfs", strings.TrimPrefix(agentproto.SecretRoot, "/"), "tmpfs", "mode=0755", unix.MS_NOSUID | unix.MS_NODEV},
	} {
		if err := mountAt(m.src, filepath.Join(mergedRoot, m.dst), m.fstype, m.flags, m.data); err != nil {
			return err
		}
	}
	for _, d := range cfg.Drives {
		target, err := guestPath(d.GuestPath)
		if err != nil {
			return err
		}
		flags := uintptr(unix.MS_NOSUID | unix.MS_NODEV)
		if !d.Writable {
			flags |= unix.MS_RDONLY
		}
		if err := mountAt(d.Device, target, "ext4", flags, ""); err != nil {
			return err
		}
	}
	for i := range cfg.Files {
		if err := writeFile(cfg.Files[i]); err != nil {
			return err
		}
		clear(cfg.Files[i].Body)
	}
	for i := range secrets.Files {
		if !strings.HasPrefix(secrets.Files[i].GuestPath, agentproto.SecretRoot+"/") {
			return fmt.Errorf("secret file %q is outside %s", secrets.Files[i].GuestPath, agentproto.SecretRoot)
		}
		if err := writeFile(secrets.Files[i]); err != nil {
			return err
		}
		clear(secrets.Files[i].Body)
	}
	if cfg.DNS != "" {
		if err := os.WriteFile(filepath.Join(mergedRoot, "etc/resolv.conf"), []byte("nameserver "+cfg.DNS+"\n"), 0o644); err != nil {
			return fmt.Errorf("write resolv.conf: %w", err)
		}
	}
	return nil
}

func writeFile(f agentproto.File) error {
	target, err := guestPath(f.GuestPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create directory for %s: %w", f.GuestPath, err)
	}
	mode := os.FileMode(f.Mode & 0o777)
	if mode == 0 {
		mode = 0o400
	}
	if err := os.WriteFile(target, f.Body, mode); err != nil {
		return fmt.Errorf("write %s: %w", f.GuestPath, err)
	}
	return os.Chmod(target, mode)
}

// guestPath maps an absolute guest path to its path under the merged root.
func guestPath(p string) (string, error) {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return "", fmt.Errorf("guest path %q must be a clean absolute path", p)
	}
	return filepath.Join(mergedRoot, p), nil
}

func mountAt(src, dst, fstype string, flags uintptr, data string) error {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return fmt.Errorf("create mount point %s: %w", dst, err)
	}
	if err := unix.Mount(src, dst, fstype, flags, data); err != nil {
		return fmt.Errorf("mount %s on %s: %w", fstype, dst, err)
	}
	return nil
}

// runProcess starts the process in the merged root and reaps every child
// until the process exits. It returns the process exit code.
func runProcess(cfg agentproto.Config, ev *events) (int, error) {
	if len(cfg.Args) == 0 {
		return 0, errors.New("process has no arguments")
	}
	uid, gid, groups, err := lookupUser(cfg.User)
	if err != nil {
		return 0, err
	}
	// The process user owns the root of each writable drive.
	for _, d := range cfg.Drives {
		if !d.Writable {
			continue
		}
		target, err := guestPath(d.GuestPath)
		if err != nil {
			return 0, err
		}
		if err := os.Chown(target, int(uid), int(gid)); err != nil {
			return 0, fmt.Errorf("give drive %s to the process user: %w", d.Name, err)
		}
	}
	env := cfg.Env
	path, err := lookPath(cfg.Args[0], env)
	if err != nil {
		return 0, err
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		return 0, err
	}
	dir := cfg.Dir
	if dir == "" {
		dir = "/"
	}
	attr := &os.ProcAttr{
		Dir:   dir,
		Env:   env,
		Files: []*os.File{nil, stdoutW, stderrW},
		Sys: &syscall.SysProcAttr{
			Chroot:     mergedRoot,
			Setsid:     true,
			Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: groups},
		},
	}
	proc, err := os.StartProcess(path, cfg.Args, attr)
	_ = stdoutW.Close()
	_ = stderrW.Close()
	if err != nil {
		return 0, fmt.Errorf("start process: %w", err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go stream(&wg, stdoutR, agentproto.TypeStdout, ev)
	go stream(&wg, stderrR, agentproto.TypeStderr, ev)
	code := reap(proc.Pid)
	wg.Wait()
	return code, nil
}

// reap waits for every child and returns the exit code of pid.
func reap(pid int) int {
	for {
		var ws unix.WaitStatus
		got, err := unix.Wait4(-1, &ws, 0, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 127
		}
		if got != pid {
			continue
		}
		switch {
		case ws.Exited():
			return ws.ExitStatus()
		case ws.Signaled():
			return 128 + int(ws.Signal())
		}
	}
}

func stream(wg *sync.WaitGroup, r *os.File, t agentproto.MessageType, ev *events) {
	defer wg.Done()
	defer func() { _ = r.Close() }()
	buf := make([]byte, chunkBytes)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			ev.send(agentproto.Message{Type: t, Data: append([]byte(nil), buf[:n]...)})
		}
		if err != nil {
			return
		}
	}
}

// lookPath finds the program inside the merged root and returns its path
// relative to that root.
func lookPath(name string, env []string) (string, error) {
	if strings.Contains(name, "/") {
		return name, nil
	}
	pathEnv := defaultPath
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathEnv = v
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Stat(filepath.Join(mergedRoot, p))
		if err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("program %q is not in PATH", name)
}

// lookupUser resolves "uid", "uid:gid", "name", or "name:group" with the
// merged root /etc/passwd and /etc/group.
func lookupUser(spec string) (uid, gid uint32, groups []uint32, err error) {
	if spec == "" {
		return 0, 0, nil, nil
	}
	userPart, groupPart, hasGroup := strings.Cut(spec, ":")
	passwd := readColonFile(filepath.Join(mergedRoot, "etc/passwd"))
	group := readColonFile(filepath.Join(mergedRoot, "etc/group"))
	name := userPart
	if n, ok := parseID(userPart); ok {
		uid = n
		for _, f := range passwd {
			if len(f) > 3 && f[2] == userPart {
				name = f[0]
				gid, _ = parseID(f[3])
				break
			}
		}
	} else {
		found := false
		for _, f := range passwd {
			if len(f) > 3 && f[0] == userPart {
				uid, _ = parseID(f[2])
				gid, _ = parseID(f[3])
				found = true
				break
			}
		}
		if !found {
			return 0, 0, nil, fmt.Errorf("user %q is not in the image", userPart)
		}
	}
	if hasGroup {
		if n, ok := parseID(groupPart); ok {
			gid = n
		} else {
			found := false
			for _, f := range group {
				if len(f) > 2 && f[0] == groupPart {
					gid, _ = parseID(f[2])
					found = true
					break
				}
			}
			if !found {
				return 0, 0, nil, fmt.Errorf("group %q is not in the image", groupPart)
			}
		}
	}
	for _, f := range group {
		if len(f) < 4 || f[3] == "" {
			continue
		}
		for _, member := range strings.Split(f[3], ",") {
			if member == name {
				if g, ok := parseID(f[2]); ok {
					groups = append(groups, g)
				}
			}
		}
	}
	return uid, gid, groups, nil
}

func parseID(s string) (uint32, bool) {
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil
}

func readColonFile(path string) [][]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out [][]string
	for _, line := range strings.Split(string(b), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Split(line, ":"))
	}
	return out
}

// events is the ordered message channel to the host.
type events struct {
	mu   sync.Mutex
	conn *os.File
	enc  *json.Encoder
}

// readSecrets reads the one Secrets message that the host sends after
// Hello.
func (e *events) readSecrets() (*agentproto.Secrets, error) {
	line, err := bufio.NewReaderSize(io.LimitReader(e.conn, agentproto.MaxSecretsBytes), 64<<10).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read secrets: %w", err)
	}
	defer clear(line)
	var m agentproto.Message
	if err := json.Unmarshal(line, &m); err != nil || m.Type != agentproto.TypeSecrets {
		return nil, errors.New("the host did not send secrets after hello")
	}
	if m.Secrets == nil {
		return &agentproto.Secrets{}, nil
	}
	return m.Secrets, nil
}

func (e *events) send(m agentproto.Message) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.enc.Encode(m)
}

func (e *events) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.conn.Close()
}

func dialHost(port uint32) (*events, error) {
	conn, err := dialVsock(port)
	if err != nil {
		return nil, err
	}
	return &events{conn: conn, enc: json.NewEncoder(conn)}, nil
}

// dialVsock connects to the host CID. It retries while the host listener
// starts. Go's net package cannot wrap a vsock socket, so the connection is
// an *os.File.
func dialVsock(port uint32) (*os.File, error) {
	deadline := time.Now().Add(connectWait)
	for {
		fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, fmt.Errorf("vsock socket: %w", err)
		}
		err = unix.Connect(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_HOST, Port: port})
		if err == nil {
			return os.NewFile(uintptr(fd), "vsock"), nil
		}
		_ = unix.Close(fd)
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("vsock connect port %d: %w", port, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func halt() {
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_RESTART)
	select {}
}
