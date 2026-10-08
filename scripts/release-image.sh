#!/usr/bin/env bash
# Build the vmcp image of one pushed commit from the public repository and
# publish it under its release version. Callers pin the printed digest,
# never a tag.
#
# Usage, from a vmcp checkout: scripts/release-image.sh <YYYYMMDDvN> <40-character commit>
# Needs: docker, git, gh, and a GitHub token with write:packages in
# $GHCR_TOKEN or from `gh auth token`.
set -euo pipefail

repo="https://github.com/jaredfolkins/vmcp.git"
image="ghcr.io/jaredfolkins/vmcp"
version="${1:-}"
commit="${2:-}"
[[ "${version}" =~ ^[0-9]{8}v[1-9][0-9]{0,2}$ && "${commit}" =~ ^[0-9a-f]{40}$ ]] ||
  { echo "usage: $0 <YYYYMMDDvN> <40-character commit>" >&2; exit 2; }
git fetch --quiet origin main
git merge-base --is-ancestor "${commit}" origin/main ||
  { echo "commit ${commit} is not on the public main branch" >&2; exit 2; }

# A private Docker config keeps the token out of the user's config.
config="$(mktemp -d)"
trap 'rm -rf "${config}"' EXIT
token="${GHCR_TOKEN:-$(gh auth token)}"
user="$(GH_TOKEN="${token}" gh api user --jq .login)"
printf '%s' "${token}" | DOCKER_CONFIG="${config}" docker login ghcr.io -u "${user}" --password-stdin >/dev/null

# A release version names exactly one set of bytes.
if DOCKER_CONFIG="${config}" docker manifest inspect "${image}:${version}" >/dev/null 2>&1; then
  echo "version ${version} is already published; choose the next version" >&2
  exit 2
fi

docker build --pull \
  --build-arg "VMCP_VERSION=${version}" --build-arg "VMCP_COMMIT=${commit}" \
  --label "org.opencontainers.image.revision=${commit}" \
  --label "org.opencontainers.image.version=${version}" \
  -t "${image}:${version}" -t "${image}:sha-${commit}" "${repo}#${commit}"
DOCKER_CONFIG="${config}" docker push "${image}:${version}" >/dev/null
DOCKER_CONFIG="${config}" docker push "${image}:sha-${commit}" >/dev/null
digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "${image}:${version}")"
printf 'version=%s\ncommit=%s\ndigest=%s\n' "${version}" "${commit}" "${digest}"
