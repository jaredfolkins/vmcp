// Package image converts a digest-pinned OCI image into a read-only ext4
// root filesystem with the vmcp guest agent.
package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Media types.
const (
	mediaOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	maxManifestBytes    = 8 << 20
	maxConfigBytes      = 8 << 20
)

var manifestAccept = strings.Join([]string{mediaOCIManifest, mediaOCIIndex, mediaDockerManifest, mediaDockerList}, ", ")

// Reference is a parsed image reference pinned by digest.
type Reference struct {
	// Registry is the base URL of the registry API.
	Registry   string
	Repository string
	Digest     string
}

// ParseReference parses "host/repo@sha256:..." or "repo@sha256:...". A
// name without a registry host means Docker Hub. registry, when set,
// replaces the registry base URL that the name implies.
func ParseReference(ref, registry string) (Reference, error) {
	name, digest, ok := strings.Cut(ref, "@")
	if !ok || !validDigest(digest) {
		return Reference{}, fmt.Errorf("image reference %q must be pinned by a sha256 digest", ref)
	}
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i] // drop a tag; the digest wins
	}
	host, repo := "docker.io", name
	if first, rest, found := strings.Cut(name, "/"); found && (strings.ContainsAny(first, ".:") || first == "localhost") {
		host, repo = first, rest
	}
	if host == "docker.io" && !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	if repo == "" || strings.Contains(repo, "..") {
		return Reference{}, fmt.Errorf("image reference %q has an invalid repository", ref)
	}
	base := registry
	if base == "" {
		if host == "docker.io" {
			host = "registry-1.docker.io"
		}
		base = "https://" + host
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Reference{}, fmt.Errorf("registry URL %q is invalid", base)
	}
	return Reference{Registry: strings.TrimSuffix(u.String(), "/"), Repository: repo, Digest: digest}, nil
}

func validDigest(d string) bool {
	hexPart, ok := strings.CutPrefix(d, "sha256:")
	if !ok || len(hexPart) != 64 {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil && strings.ToLower(hexPart) == hexPart
}

// Descriptor is an OCI content descriptor.
type Descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

// Platform is an OCI platform.
type Platform struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

type manifest struct {
	MediaType string       `json:"mediaType"`
	Config    Descriptor   `json:"config"`
	Layers    []Descriptor `json:"layers"`
	Manifests []Descriptor `json:"manifests"`
}

// Config is the part of the OCI image configuration that vmcp uses.
type Config struct {
	Entrypoint []string `json:"Entrypoint"`
	Cmd        []string `json:"Cmd"`
	Env        []string `json:"Env"`
	WorkingDir string   `json:"WorkingDir"`
	User       string   `json:"User"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       Config `json:"config"`
}

// registry fetches content from one repository. It answers a bearer
// challenge with the given token, or with an anonymous token when no token
// is given.
type registry struct {
	ref   Reference
	token string
	http  *http.Client
}

func (r *registry) get(ctx context.Context, kind, digest, accept string) (*http.Response, error) {
	u := fmt.Sprintf("%s/v2/%s/%s/%s", r.ref.Registry, r.ref.Repository, kind, digest)
	resp, err := r.do(ctx, u, accept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && r.token == "" {
		challenge := resp.Header.Get("WWW-Authenticate")
		_ = resp.Body.Close()
		tok, err := r.anonymousToken(ctx, challenge)
		if err != nil {
			return nil, err
		}
		r.token = tok
		if resp, err = r.do(ctx, u, accept); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("registry %s %s returned %d", kind, digest, resp.StatusCode)
	}
	return resp, nil
}

func (r *registry) do(ctx context.Context, u, accept string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registry request: %w", err)
	}
	return resp, nil
}

// anonymousToken answers a "Bearer realm=...,service=...,scope=..."
// challenge without credentials.
func (r *registry) anonymousToken(ctx context.Context, challenge string) (string, error) {
	params, ok := parseChallenge(challenge)
	if !ok || params["realm"] == "" {
		return "", errors.New("registry requires authentication and sent no bearer challenge")
	}
	u, err := url.Parse(params["realm"])
	if err != nil || u.Scheme != "https" {
		return "", errors.New("registry token realm must be an https URL")
	}
	q := u.Query()
	for _, k := range []string{"service", "scope"} {
		if params[k] != "" {
			q.Set(k, params[k])
		}
	}
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token request returned %d", resp.StatusCode)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return "", fmt.Errorf("decode registry token: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("registry token response has no token")
}

func parseChallenge(h string) (map[string]string, bool) {
	rest, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return nil, false
	}
	out := map[string]string{}
	for _, part := range strings.Split(rest, ",") {
		k, v, found := strings.Cut(strings.TrimSpace(part), "=")
		if found {
			out[k] = strings.Trim(v, `"`)
		}
	}
	return out, true
}

// fetchJSON reads a manifest or config blob, checks its digest, and decodes
// it.
func (r *registry) fetchJSON(ctx context.Context, kind, digest, accept string, limit int64, out any) (string, error) {
	resp, err := r.get(ctx, kind, digest, accept)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", fmt.Errorf("read %s %s: %w", kind, digest, err)
	}
	if int64(len(b)) > limit {
		return "", fmt.Errorf("%s %s is larger than %d bytes", kind, digest, limit)
	}
	sum := sha256.Sum256(b)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != digest {
		return "", fmt.Errorf("%s digest %s, want %s", kind, got, digest)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return "", fmt.Errorf("decode %s %s: %w", kind, digest, err)
	}
	return resp.Header.Get("Content-Type"), nil
}

// resolve returns the platform manifest for the reference. An index or
// manifest list selects the entry for the platform.
func (r *registry) resolve(ctx context.Context, platform Platform) (manifest, error) {
	digest := r.ref.Digest
	for range 2 {
		var m manifest
		ctype, err := r.fetchJSON(ctx, "manifests", digest, manifestAccept, maxManifestBytes, &m)
		if err != nil {
			return manifest{}, err
		}
		mt := m.MediaType
		if mt == "" {
			mt = ctype
		}
		switch mt {
		case mediaOCIManifest, mediaDockerManifest:
			if len(m.Layers) == 0 {
				return manifest{}, errors.New("image manifest has no layers")
			}
			return m, nil
		case mediaOCIIndex, mediaDockerList:
			next := ""
			for _, d := range m.Manifests {
				if d.Platform != nil && d.Platform.OS == platform.OS && d.Platform.Architecture == platform.Architecture &&
					(platform.Variant == "" || d.Platform.Variant == platform.Variant) {
					next = d.Digest
					break
				}
			}
			if next == "" || !validDigest(next) {
				return manifest{}, fmt.Errorf("image index has no %s/%s manifest", platform.OS, platform.Architecture)
			}
			digest = next
		default:
			return manifest{}, fmt.Errorf("unsupported manifest media type %q", mt)
		}
	}
	return manifest{}, errors.New("image index points to another index")
}

// verifier counts and hashes the bytes that pass through it.
type verifier struct {
	r    io.Reader
	h    hash.Hash
	n    int64
	max  int64
	want string
}

func newVerifier(r io.Reader, d Descriptor) *verifier {
	return &verifier{r: r, h: sha256.New(), max: d.Size, want: d.Digest}
}

func (v *verifier) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)
	v.n += int64(n)
	v.h.Write(p[:n])
	if v.n > v.max {
		return n, fmt.Errorf("blob %s is larger than its %d byte descriptor", v.want, v.max)
	}
	return n, err
}

// check reads any rest of the blob and compares size and digest.
func (v *verifier) check() error {
	if _, err := io.Copy(io.Discard, v); err != nil {
		return err
	}
	if v.n != v.max {
		return fmt.Errorf("blob %s has %d bytes, want %d", v.want, v.n, v.max)
	}
	if got := "sha256:" + hex.EncodeToString(v.h.Sum(nil)); got != v.want {
		return fmt.Errorf("blob digest %s, want %s", got, v.want)
	}
	return nil
}
