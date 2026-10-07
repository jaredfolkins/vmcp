package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// UnpackerVersion changes when the unpack or injection rules change. It is
// part of the image compatibility.
const UnpackerVersion = "vmcp-unpacker-v1"

const (
	// RootFSName is the image file in an image directory.
	RootFSName = "rootfs.ext4"
	metaName   = "image.json"
	agentPath  = ".vmcp/init"
)

// mountPoints are the directories that the agent needs in every root.
var mountPoints = []string{"proc", "sys", "dev", "etc", "tmp", ".vmcp/upper", ".vmcp/merged"}

// Request selects the image to prepare.
type Request struct {
	Ref           string
	Registry      string
	RegistryToken string
	Platform      Platform
	// AgentPath is the host path of the static guest agent binary.
	AgentPath string
	// MaxBytes bounds the expanded regular-file bytes of all layers.
	MaxBytes int64
}

// Meta describes a prepared image.
type Meta struct {
	Ref           string `json:"ref"`
	ImageDigest   string `json:"image_digest"`
	Compatibility string `json:"compatibility"`
	SizeBytes     int64  `json:"size_bytes"`
	Process       Config `json:"process"`
}

// Compatibility identifies the inputs that shape a prepared image.
func Compatibility(agentSHA256 string) string {
	sum := sha256.Sum256([]byte(UnpackerVersion + "\n" + agentSHA256))
	return "vmcp-rootfs-v1:" + hex.EncodeToString(sum[:8])
}

// Prepare builds the image into dir, which must not exist. On failure it
// removes dir.
func Prepare(ctx context.Context, hc *http.Client, dir string, req Request) (meta Meta, err error) {
	ref, err := ParseReference(req.Ref, req.Registry)
	if err != nil {
		return Meta{}, err
	}
	agentSum, err := fileSHA256(req.AgentPath)
	if err != nil {
		return Meta{}, fmt.Errorf("hash guest agent: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Meta{}, fmt.Errorf("create image directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		return Meta{}, err
	}
	reg := &registry{ref: ref, token: req.RegistryToken, http: hc}
	m, err := reg.resolve(ctx, req.Platform)
	if err != nil {
		return Meta{}, err
	}
	var cfg imageConfig
	if _, err := reg.fetchJSON(ctx, "blobs", m.Config.Digest, "", maxConfigBytes, &cfg); err != nil {
		return Meta{}, err
	}
	if cfg.OS != "" && cfg.OS != req.Platform.OS || cfg.Architecture != "" && cfg.Architecture != req.Platform.Architecture {
		return Meta{}, fmt.Errorf("image is %s/%s, want %s/%s", cfg.OS, cfg.Architecture, req.Platform.OS, req.Platform.Architecture)
	}
	u := &unpacker{root: root, maxBytes: req.MaxBytes}
	for _, layer := range m.Layers {
		if err := applyLayer(ctx, reg, u, layer); err != nil {
			return Meta{}, err
		}
	}
	if err := u.finish(); err != nil {
		return Meta{}, err
	}
	if err := inject(root, req.AgentPath); err != nil {
		return Meta{}, err
	}
	img := filepath.Join(dir, RootFSName)
	size, err := buildExt4(ctx, root, img)
	if err != nil {
		return Meta{}, err
	}
	if err := os.Chmod(img, 0o444); err != nil {
		return Meta{}, err
	}
	if err := os.RemoveAll(root); err != nil {
		return Meta{}, fmt.Errorf("remove unpacked root: %w", err)
	}
	meta = Meta{
		Ref:           req.Ref,
		ImageDigest:   ref.Digest,
		Compatibility: Compatibility(agentSum),
		SizeBytes:     size,
		Process:       cfg.Config,
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return Meta{}, err
	}
	if err := os.WriteFile(filepath.Join(dir, metaName), b, 0o600); err != nil {
		return Meta{}, fmt.Errorf("write image metadata: %w", err)
	}
	return meta, nil
}

// PrepareSelfTest builds the self-test image: an empty root with only the
// guest agent, which runs its own self-test mode.
func PrepareSelfTest(ctx context.Context, dir, agentPath string) (meta Meta, err error) {
	agentSum, err := fileSHA256(agentPath)
	if err != nil {
		return Meta{}, fmt.Errorf("hash guest agent: %w", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return Meta{}, fmt.Errorf("create image directory: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dir)
		}
	}()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o755); err != nil {
		return Meta{}, err
	}
	if err := inject(root, agentPath); err != nil {
		return Meta{}, err
	}
	img := filepath.Join(dir, RootFSName)
	size, err := buildExt4(ctx, root, img)
	if err != nil {
		return Meta{}, err
	}
	if err := os.Chmod(img, 0o444); err != nil {
		return Meta{}, err
	}
	if err := os.RemoveAll(root); err != nil {
		return Meta{}, err
	}
	meta = Meta{
		Ref:           "vmcp-selftest",
		ImageDigest:   "sha256:" + agentSum,
		Compatibility: Compatibility(agentSum),
		SizeBytes:     size,
		Process:       Config{Cmd: []string{"/" + agentPath0, "selftest"}},
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return Meta{}, err
	}
	return meta, os.WriteFile(filepath.Join(dir, metaName), b, 0o600)
}

// agentPath0 is the agent path inside a prepared root.
const agentPath0 = agentPath

// ReadMeta reads the metadata of a prepared image.
func ReadMeta(dir string) (Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, metaName))
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("decode image metadata: %w", err)
	}
	return m, nil
}

func applyLayer(ctx context.Context, reg *registry, u *unpacker, layer Descriptor) error {
	if !validDigest(layer.Digest) || layer.Size <= 0 {
		return fmt.Errorf("layer descriptor %q is invalid", layer.Digest)
	}
	resp, err := reg.get(ctx, "blobs", layer.Digest, "")
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	v := newVerifier(resp.Body, layer)
	r, closeLayer, err := layerReader(layer.MediaType, v)
	if err != nil {
		return err
	}
	if err := u.apply(r); err != nil {
		return fmt.Errorf("layer %s: %w", layer.Digest, err)
	}
	if err := closeLayer(); err != nil {
		return fmt.Errorf("layer %s: %w", layer.Digest, err)
	}
	return v.check()
}

// inject adds the agent and the mount points. It refuses a symlink on any
// of those paths.
func inject(root, agent string) error {
	for _, d := range mountPoints {
		cur := root
		for _, part := range strings.Split(d, "/") {
			cur = filepath.Join(cur, part)
			fi, err := os.Lstat(cur)
			if errors.Is(err, fs.ErrNotExist) {
				if err := os.Mkdir(cur, 0o755); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if !fi.IsDir() {
				return fmt.Errorf("image path /%s must be a directory", d)
			}
		}
	}
	src, err := os.Open(agent)
	if err != nil {
		return fmt.Errorf("open guest agent: %w", err)
	}
	defer func() { _ = src.Close() }()
	dst, err := os.OpenFile(filepath.Join(root, agentPath), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return fmt.Errorf("create guest agent: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return fmt.Errorf("copy guest agent: %w", err)
	}
	if err := dst.Close(); err != nil {
		return err
	}
	return os.Chmod(filepath.Join(root, agentPath), 0o755)
}

// buildExt4 creates a sparse ext4 image from root. It returns the image
// size.
func buildExt4(ctx context.Context, root, img string) (int64, error) {
	var used int64
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		used += 4096
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			used += fi.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	size := max(2*used+64<<20, 128<<20)
	size = (size + 4095) &^ 4095
	return size, MakeExt4(ctx, root, img, size, "vmcp-root")
}

// MakeExt4 creates an ext4 image of size bytes, filled from dir when dir is
// not empty.
func MakeExt4(ctx context.Context, dir, img string, size int64, label string) error {
	f, err := os.OpenFile(img, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	args := []string{"-q", "-F", "-t", "ext4", "-b", "4096", "-L", label, "-E", "lazy_itable_init=0,lazy_journal_init=0"}
	if dir != "" {
		args = append(args, "-d", dir)
	}
	args = append(args, img)
	cmd := exec.CommandContext(ctx, "mke2fs", args...)
	cmd.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mke2fs: %w: %s", err, firstLine(out))
	}
	return nil
}

func firstLine(b []byte) string {
	s, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
