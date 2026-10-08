//go:build linux

package firecracker

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jaredfolkins/vmcp/api"
	"github.com/jaredfolkins/vmcp/internal/machine"
	"github.com/jaredfolkins/vmcp/internal/trace"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/agentproto"
	"github.com/jaredfolkins/vmcp/runtimes/firecracker/internal/image"
)

const (
	serialLogLimit  = 1 << 20
	memoryOverhead  = 128
	defaultDiskMiB  = 1024
	killWait        = 5 * time.Second
	driveSlackBytes = 16 << 20
)

var upstreamNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

// Machine is one provisioned Firecracker guest.
type Machine struct {
	r        *Runtime
	spec     machine.Launch
	jailID   string
	uid      int
	jailRoot string
	cgroup   string
	tag      string
	net      *guestNet
	brokers  *brokers
	imgMeta  image.Meta
	lns      []net.Listener
	listenWG sync.WaitGroup
	// log is the machine logger. traceCtx carries the trace of the request
	// that provisioned or booted the machine. Lines about the machine log
	// with it.
	log       *slog.Logger
	traceCtx  context.Context
	bootStart time.Time
	// secrets go to the guest once, after its Hello, and are then cleared.
	// They are never written to disk.
	secrets *agentproto.Secrets

	mu         sync.Mutex
	booted     bool
	finished   bool
	killReason string
	exit       *api.Exit
	posture    map[string]any
	done       chan struct{}
	result     machine.Result
}

// Provision builds the jail, drives, network, and brokers of a machine. It
// does not boot the guest.
func (r *Runtime) Provision(ctx context.Context, ls machine.Launch) (inst machine.Instance, err error) {
	id := strings.TrimPrefix(ls.ID, "m-")
	if len(id) < 10 {
		return nil, fmt.Errorf("machine ID %q is too short", ls.ID)
	}
	m := &Machine{
		r:        r,
		spec:     ls,
		jailID:   "vmcp-" + id[:10],
		uid:      r.cfg.UIDBase + ls.Slot,
		tag:      fmt.Sprintf("vmcp:%s:%s", r.cfg.InstallID, ls.ID),
		done:     make(chan struct{}),
		log:      ls.Logger,
		traceCtx: trace.Detach(ctx),
	}
	if m.log == nil {
		m.log = r.cfg.Logger.With("machine", ls.ID)
	}
	m.secrets = launchSecrets(ls)
	m.jailRoot = filepath.Join(r.cfg.JailBase, "firecracker", m.jailID, "root")
	m.cgroup = filepath.Join(r.cgroupParent(), m.jailID)
	if m.imgMeta, err = image.ReadMeta(r.ImageDir(ls.ImageID)); err != nil {
		return nil, fmt.Errorf("read image: %w", err)
	}
	if !r.enf.healthy() {
		return nil, errors.New("the enforcer is not running")
	}
	if _, err := os.Lstat(filepath.Dir(m.jailRoot)); err == nil {
		return nil, fmt.Errorf("jail %s already exists", m.jailID)
	}
	r.enf.add(m)
	defer func() {
		if err != nil {
			m.teardown(context.Background())
		}
	}()
	steps := []struct {
		name string
		run  func(context.Context) error
	}{
		{"provision.jail", func(context.Context) error {
			if err := os.MkdirAll(m.jailRoot, 0o700); err != nil {
				return fmt.Errorf("create jail: %w", err)
			}
			r.enf.watch(m.jailRoot)
			return writeMarker(filepath.Dir(m.jailRoot), r.cfg.InstallID)
		}},
		{"provision.drives", m.stageFiles},
		{"provision.network", func(ctx context.Context) error {
			if !needsNetwork(ls.Spec.Network) {
				return nil
			}
			return m.startNetwork(ctx)
		}},
		{"provision.config", func(context.Context) error { return m.writeConfigs() }},
		{"provision.vsock", func(context.Context) error { return m.listen() }},
	}
	for _, step := range steps {
		sctx, span := trace.Start(ctx, m.log, step.name)
		err := step.run(sctx)
		span.End(err)
		if err != nil {
			return nil, err
		}
	}
	m.log.DebugContext(ctx, "machine provisioned", "jail", m.jailID, "uid", m.uid, "cgroup", m.cgroup, "network", m.net != nil)
	return m, nil
}

func needsNetwork(n api.Network) bool {
	return n.DNS || n.PublicEgress || len(n.Upstreams) > 0
}

// stageFiles places the kernel, root, scratch, and spec drives in the jail.
func (m *Machine) stageFiles(ctx context.Context) error {
	if err := os.Link(m.r.kernelPath(), filepath.Join(m.jailRoot, "vmlinux")); err != nil {
		return fmt.Errorf("link kernel: %w", err)
	}
	if err := os.Link(filepath.Join(m.r.ImageDir(m.spec.ImageID), image.RootFSName), filepath.Join(m.jailRoot, "rootfs.ext4")); err != nil {
		return fmt.Errorf("link image: %w", err)
	}
	disk := m.spec.Spec.Resources.DiskMiB
	if disk <= 0 {
		disk = defaultDiskMiB
	}
	if err := m.makeDrive(ctx, "", "upper.ext4", int64(disk)<<20); err != nil {
		return err
	}
	for i, d := range m.spec.Spec.Drives {
		src := filepath.Join(m.spec.Dir, "in", d.Name)
		if _, err := os.Stat(src); err != nil {
			src = ""
		}
		if err := m.makeDrive(ctx, src, fmt.Sprintf("drive-%d.ext4", i), int64(d.SizeMiB)<<20); err != nil {
			return err
		}
	}
	return nil
}

func (m *Machine) makeDrive(ctx context.Context, src, name string, size int64) error {
	p := filepath.Join(m.jailRoot, name)
	if err := image.MakeExt4(ctx, src, p, size, "vmcp-data"); err != nil {
		return fmt.Errorf("make %s: %w", name, err)
	}
	return os.Chown(p, m.uid, m.uid)
}

func (m *Machine) startNetwork(ctx context.Context) error {
	g, err := netForSlot(m.r.cfg.Pool, m.spec.Slot, m.spec.ID)
	if err != nil {
		return err
	}
	for _, u := range m.spec.Spec.Network.Upstreams {
		if !upstreamNameRE.MatchString(u.Name) {
			return fmt.Errorf("upstream name %q is invalid", u.Name)
		}
	}
	g.Allowed, _ = plannedPorts(m.spec.Spec.Network, g.Host)
	m.mu.Lock()
	m.net = &g
	m.mu.Unlock()
	if err := addTap(ctx, g, m.uid, m.tag); err != nil {
		return fmt.Errorf("add tap: %w", err)
	}
	b, err := startBrokers(m.spec.Spec.Network, g.Host, brokerConfig{
		DNSUpstreams: m.r.cfg.DNSUpstreams,
		Deny:         append(append([]netip.Prefix(nil), DefaultDenyPrefixes...), m.r.cfg.Deny...),
		Log:          m.log,
		TraceCtx:     m.traceCtx,
	})
	if err != nil {
		return err
	}
	m.brokers = b
	return nil
}

// writeConfigs writes the agent config drive and the Firecracker config.
func (m *Machine) writeConfigs() error {
	cfg := agentproto.Config{
		Version: agentproto.Version,
		Args:    m.spec.Args,
		Env:     append([]string(nil), m.spec.Env...),
		Dir:     m.spec.WorkDir,
		User:    m.spec.User,
	}
	for i, d := range m.spec.Spec.Drives {
		cfg.Drives = append(cfg.Drives, agentproto.Drive{
			Name: d.Name, Device: fmt.Sprintf("/dev/vd%c", 'a'+agentproto.FirstDriveIndex+i),
			GuestPath: d.GuestPath, Writable: d.Writable,
		})
	}
	for _, f := range m.spec.Spec.Files {
		if f.Secret {
			continue
		}
		cfg.Files = append(cfg.Files, agentproto.File{GuestPath: f.GuestPath, Mode: f.Mode, Body: f.Body})
	}
	n := m.spec.Spec.Network
	if m.net != nil {
		host := m.net.Host.String()
		if n.DNS {
			cfg.DNS = host
		}
		if n.PublicEgress {
			proxy := "http://" + net.JoinHostPort(host, strconv.Itoa(PortEgress))
			for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
				cfg.Env = append(cfg.Env, k+"="+proxy)
			}
			noProxy := "localhost,127.0.0.1,::1," + host
			cfg.Env = append(cfg.Env, "NO_PROXY="+noProxy, "no_proxy="+noProxy)
		}
		_, urls := plannedPorts(n, m.net.Host)
		for name, u := range urls {
			cfg.Env = append(cfg.Env, "VMCP_UPSTREAM_"+strings.ToUpper(name)+"="+u)
		}
	}
	raw, err := agentproto.EncodeConfig(cfg)
	for i := range cfg.Files {
		clear(cfg.Files[i].Body)
	}
	if err != nil {
		return err
	}
	if err := m.writeJailFile("config.bin", raw, 0o400); err != nil {
		return err
	}
	clear(raw)

	bootArgs := "console=ttyS0 reboot=k panic=1 pci=off init=" + agentproto.InitPath
	if m.net != nil {
		bootArgs += " " + m.net.kernelIPArg()
	}
	drives := []map[string]any{
		{"drive_id": "rootfs", "path_on_host": "/rootfs.ext4", "is_root_device": true, "is_read_only": true},
		{"drive_id": "config", "path_on_host": "/config.bin", "is_root_device": false, "is_read_only": true},
		{"drive_id": "upper", "path_on_host": "/upper.ext4", "is_root_device": false, "is_read_only": false},
	}
	for i, d := range m.spec.Spec.Drives {
		drives = append(drives, map[string]any{
			"drive_id": fmt.Sprintf("drive%d", i), "path_on_host": fmt.Sprintf("/drive-%d.ext4", i),
			"is_root_device": false, "is_read_only": !d.Writable,
		})
	}
	for _, d := range drives {
		d["rate_limiter"] = rateLimiter(32<<20, 2000)
	}
	res := m.spec.Spec.Resources
	fc := map[string]any{
		"boot-source":    map[string]any{"kernel_image_path": "/vmlinux", "boot_args": bootArgs},
		"drives":         drives,
		"machine-config": map[string]any{"vcpu_count": max(res.VCPUs, 1), "mem_size_mib": max(res.MemoryMiB, 128), "smt": false},
		"vsock":          map[string]any{"guest_cid": 3, "uds_path": "/v.sock"},
	}
	if m.net != nil {
		fc["network-interfaces"] = []map[string]any{{
			"iface_id": "eth0", "guest_mac": m.net.MAC, "host_dev_name": m.net.Tap,
			"rx_rate_limiter": rateLimiter(16<<20, 2000), "tx_rate_limiter": rateLimiter(16<<20, 2000),
		}}
	}
	b, err := json.Marshal(fc)
	if err != nil {
		return err
	}
	return m.writeJailFile("config.json", b, 0o400)
}

func rateLimiter(bytesPerSec, ops int) map[string]any {
	return map[string]any{
		"bandwidth": map[string]any{"size": bytesPerSec, "refill_time": 1000},
		"ops":       map[string]any{"size": ops, "refill_time": 1000},
	}
}

func (m *Machine) writeJailFile(name string, b []byte, mode os.FileMode) error {
	p := filepath.Join(m.jailRoot, name)
	if err := os.WriteFile(p, b, mode); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}
	if err := os.Chmod(p, mode); err != nil {
		return err
	}
	return os.Chown(p, m.uid, m.uid)
}

// listen creates the vsock host sockets that the guest connects to.
func (m *Machine) listen() error {
	for _, port := range []int{agentproto.EventPort, agentproto.DrivePort} {
		p := filepath.Join(m.jailRoot, fmt.Sprintf("v.sock_%d", port))
		ln, err := net.Listen("unix", p)
		if err != nil {
			return fmt.Errorf("listen %s: %w", filepath.Base(p), err)
		}
		m.lns = append(m.lns, ln)
		if err := os.Chown(p, m.uid, m.uid); err != nil {
			return err
		}
	}
	m.listenWG.Add(2)
	go m.acceptEvents(m.lns[0])
	go m.acceptDrives(m.lns[1])
	return nil
}

// Boot starts the jailer. Firecracker boots from the config file.
func (m *Machine) Boot(ctx context.Context) error {
	m.mu.Lock()
	if m.booted || m.finished {
		m.mu.Unlock()
		return errors.New("machine was already started")
	}
	m.booted = true
	m.traceCtx = trace.Detach(ctx)
	m.bootStart = time.Now()
	m.mu.Unlock()
	res := m.spec.Spec.Resources
	mem := int64(max(res.MemoryMiB, 128)+memoryOverhead) << 20
	quota := max(res.VCPUs, 1) * 100000
	fsize := int64(1) << 30
	for _, d := range m.spec.Spec.Drives {
		fsize = max(fsize, int64(d.SizeMiB)<<20+driveSlackBytes)
	}
	args := []string{
		"--id", m.jailID,
		"--exec-file", m.r.firecracker,
		"--uid", strconv.Itoa(m.uid), "--gid", strconv.Itoa(m.uid),
		"--chroot-base-dir", m.r.cfg.JailBase,
		"--cgroup-version", "2",
		"--parent-cgroup", m.r.cfg.CgroupParent,
		"--cgroup", fmt.Sprintf("memory.max=%d", mem),
		"--cgroup", fmt.Sprintf("cpu.max=%d 100000", quota),
		"--cgroup", "pids.max=64",
		"--resource-limit", fmt.Sprintf("fsize=%d", fsize),
		"--resource-limit", "no-file=1024",
		"--new-pid-ns",
		"--", "--config-file", "/config.json", "--api-sock", "/fc.sock",
	}
	serial, err := os.OpenFile(filepath.Join(m.spec.Dir, "serial.log"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cmd := exec.Command(m.r.jailer, args...)
	cmd.Env = []string{toolPath}
	out := &limitWriter{w: serial, n: serialLogLimit}
	cmd.Stdout, cmd.Stderr = out, out
	// No ambient capabilities: the jailer gets jailerCaps from its file.
	// Ambient capabilities would pass through the jailer to Firecracker.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = serial.Close()
		m.finish(context.Background(), "boot-failed")
		return fmt.Errorf("start jailer: %w", err)
	}
	m.event(api.Event{Kind: api.EventStep, Step: "boot", Status: "running"})
	m.log.DebugContext(ctx, "jailer started", "pid", cmd.Process.Pid, "jail", m.jailID, "uid", m.uid)
	go func() {
		_ = cmd.Wait()
		_ = serial.Close()
		m.finish(context.Background(), "")
	}()
	return nil
}

// Kill stops the guest at once. It is safe to call more than once.
func (m *Machine) Kill(reason string) {
	m.mu.Lock()
	first := m.killReason == ""
	if first {
		m.killReason = reason
	}
	logCtx := m.traceCtx
	m.mu.Unlock()
	if first {
		m.log.DebugContext(logCtx, "machine kill", "reason", reason)
	}
	_ = killCgroup(m.cgroup)
}

// Done is closed after the machine ended and every resource was removed.
func (m *Machine) Done() <-chan struct{} { return m.done }

// Result returns the result after Done is closed.
func (m *Machine) Result() machine.Result {
	<-m.done
	return m.result
}

// Destroy removes a machine that never booted, or kills a booted machine
// and waits for its teardown.
func (m *Machine) Destroy(ctx context.Context, reason string) machine.Result {
	m.mu.Lock()
	booted := m.booted
	m.mu.Unlock()
	if booted {
		m.Kill(reason)
		select {
		case <-m.done:
		case <-ctx.Done():
		}
		return m.result
	}
	m.finish(ctx, reason)
	return m.result
}

// finish runs teardown once and records the result.
func (m *Machine) finish(ctx context.Context, reason string) {
	m.mu.Lock()
	if m.finished {
		m.mu.Unlock()
		return
	}
	m.finished = true
	if m.killReason == "" {
		m.killReason = reason
	}
	m.mu.Unlock()
	status := m.teardown(ctx)
	m.mu.Lock()
	destroyReason := m.killReason
	if destroyReason == "" {
		destroyReason = "exited"
	}
	detail := map[string]any{"jail_id": m.jailID, "uid": m.uid, "cgroup": m.cgroup}
	if m.net != nil {
		detail["tap"] = m.net.Tap
		detail["guest_ip"] = m.net.Guest.String()
		detail["host_ip"] = m.net.Host.String()
	}
	if m.posture != nil {
		detail["posture"] = m.posture
	}
	m.result = machine.Result{
		Exit: m.exit,
		Proof: api.Proof{
			MachineID:         m.spec.ID,
			Runtime:           Name,
			Release:           m.r.release,
			ImageDigest:       m.imgMeta.ImageDigest,
			NetworkPolicyHash: m.policyHash(),
			DestroyReason:     destroyReason,
			Destroyed:         status == "destroyed",
			TeardownStatus:    status,
			Detail:            detail,
		},
	}
	m.mu.Unlock()
	close(m.done)
}

func (m *Machine) policyHash() string {
	if m.net == nil {
		return "no-network"
	}
	sum := sha256.Sum256([]byte(tableRuleset() + m.net.elements(m.tag)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// teardown removes every resource of the machine and checks each removal.
// It returns "destroyed" when nothing remains.
func (m *Machine) teardown(ctx context.Context) string {
	m.mu.Lock()
	logCtx := m.traceCtx
	m.mu.Unlock()
	_, span := trace.Start(logCtx, m.log, "teardown")
	m.mu.Lock()
	m.secrets.Clear()
	m.secrets = nil
	m.mu.Unlock()
	ok := true
	step := func(name string, err error) {
		if err != nil {
			ok = false
			m.log.WarnContext(logCtx, "teardown step failed", "code", "teardown_step_failed", "step", name,
				"error", trace.BoundedError(err))
		}
	}
	step("kill-cgroup", killCgroup(m.cgroup))
	step("remove-cgroup", removeCgroup(m.cgroup))
	for _, ln := range m.lns {
		_ = ln.Close()
	}
	m.listenWG.Wait()
	m.brokers.close()
	if m.net != nil {
		step("remove-tap", removeTap(ctx, *m.net, m.tag))
	}
	jail := filepath.Dir(m.jailRoot)
	step("remove-jail", os.RemoveAll(jail))
	if _, err := os.Lstat(jail); err == nil {
		step("verify-jail", fmt.Errorf("jail %s remains", m.jailID))
	}
	if _, err := os.Lstat(m.cgroup); err == nil {
		step("verify-cgroup", fmt.Errorf("cgroup %s remains", filepath.Base(m.cgroup)))
	}
	m.r.enf.remove(m)
	status := "partial"
	if ok {
		status = "destroyed"
	}
	span.End(nil, "status", status)
	return status
}

// postureChecked reports whether the boot posture check passed. The
// enforcer audits a machine only after that baseline.
func (m *Machine) postureChecked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	ok, _ := m.posture["ok"].(bool)
	return ok
}

// netInfo returns the machine network, or nil.
func (m *Machine) netInfo() *guestNet {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.net
}

func (m *Machine) event(ev api.Event) {
	if m.spec.Sink != nil {
		m.spec.Sink.Event(ev)
	}
}

// acceptEvents reads the guest agent messages. The guest is untrusted:
// every line is bounded and unknown types are ignored.
func (m *Machine) acceptEvents(ln net.Listener) {
	defer m.listenWG.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		m.readEvents(c)
	}
}

func (m *Machine) readEvents(c net.Conn) {
	defer func() { _ = c.Close() }()
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 64<<10), agentproto.MaxLineBytes*2)
	for sc.Scan() {
		var msg agentproto.Message
		if json.Unmarshal(sc.Bytes(), &msg) != nil {
			continue
		}
		switch msg.Type {
		case agentproto.TypeHello:
			m.sendSecrets(c)
			m.mu.Lock()
			logCtx, bootStart := m.traceCtx, m.bootStart
			m.mu.Unlock()
			m.log.InfoContext(logCtx, "guest agent connected", "boot_ms", trace.Millis(time.Since(bootStart)))
			m.event(api.Event{Kind: api.EventStep, Step: "guest-agent", Status: "running"})
			m.checkPosture()
		case agentproto.TypeStep:
			m.event(api.Event{Kind: api.EventStep, Step: bounded(msg.Step, 64), Status: bounded(msg.Status, 32),
				Detail: bounded(msg.Detail, 512)})
		case agentproto.TypeStdout:
			m.event(api.Event{Kind: api.EventStdout, Data: msg.Data})
		case agentproto.TypeStderr:
			m.event(api.Event{Kind: api.EventStderr, Data: msg.Data})
		case agentproto.TypeExit:
			m.mu.Lock()
			if m.exit == nil {
				m.exit = &api.Exit{Code: msg.Code, Reason: api.ExitCompleted}
			}
			m.mu.Unlock()
		}
	}
}

// launchSecrets copies the secret entries and files of a launch. The
// manager clears its copy after Provision returns.
func launchSecrets(ls machine.Launch) *agentproto.Secrets {
	s := &agentproto.Secrets{Env: append([]string(nil), ls.SecretEnv...)}
	for _, f := range ls.Spec.Files {
		if f.Secret {
			s.Files = append(s.Files, agentproto.File{GuestPath: f.GuestPath, Mode: f.Mode, Body: append([]byte(nil), f.Body...)})
		}
	}
	return s
}

// sendSecrets writes the one Secrets message on the event connection and
// clears the host copy. A second Hello gets no secrets.
func (m *Machine) sendSecrets(c net.Conn) {
	m.mu.Lock()
	secrets := m.secrets
	m.secrets = nil
	logCtx := m.traceCtx
	m.mu.Unlock()
	if secrets == nil {
		secrets = &agentproto.Secrets{}
	}
	defer secrets.Clear()
	raw, err := json.Marshal(agentproto.Message{Type: agentproto.TypeSecrets, Secrets: secrets})
	if err == nil {
		raw = append(raw, '\n')
		_, err = c.Write(raw)
	}
	clear(raw)
	if err != nil {
		m.log.WarnContext(logCtx, "secrets not delivered", "code", "secrets_delivery_failed", "error", trace.BoundedError(err))
		return
	}
	m.log.DebugContext(logCtx, "secrets delivered", "entries", len(secrets.Env), "files", len(secrets.Files))
}

func bounded(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// acceptDrives receives the tar of each writable drive.
func (m *Machine) acceptDrives(ln net.Listener) {
	defer m.listenWG.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		if err := m.receiveDrive(c); err != nil {
			m.mu.Lock()
			logCtx := m.traceCtx
			m.mu.Unlock()
			m.log.WarnContext(logCtx, "drive receive failed", "code", "drive_receive_failed", "error", trace.BoundedError(err))
		}
	}
}

func (m *Machine) receiveDrive(c net.Conn) error {
	defer func() { _ = c.Close() }()
	br := bufio.NewReaderSize(c, 4096)
	line, err := br.ReadSlice('\n')
	if err != nil {
		return err
	}
	var hdr agentproto.DriveHeader
	if err := json.Unmarshal(line, &hdr); err != nil {
		return err
	}
	var limit int64 = -1
	for _, d := range m.spec.Spec.Drives {
		if d.Name == hdr.Name && d.Writable {
			limit = int64(d.SizeMiB)<<20 + driveSlackBytes
		}
	}
	if limit < 0 {
		// The name is guest text. Keep it out of the error, which is logged.
		return errors.New("the drive header names no writable spec drive")
	}
	outDir := filepath.Join(m.spec.Dir, "out")
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(outDir, hdr.Name+".tar.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(br, limit+1))
	cerr := f.Close()
	if err != nil || cerr != nil || n > limit {
		_ = os.Remove(tmp)
		return errors.Join(err, cerr, fmt.Errorf("drive %q tar has %d bytes, limit %d", hdr.Name, n, limit))
	}
	return os.Rename(tmp, filepath.Join(outDir, hdr.Name+".tar"))
}

// limitWriter keeps the first n bytes and drops the rest.
type limitWriter struct {
	w io.Writer
	n int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(int64(len(p)), l.n)
		_, _ = l.w.Write(p[:k])
		l.n -= k
	}
	return len(p), nil
}
