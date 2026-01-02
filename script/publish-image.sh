#!/usr/bin/env bash
set -x
set -eo pipefail

repo_root="$(cargo locate-project --workspace --message-format plain 2>/dev/null | xargs dirname)"
cd "${repo_root}"

IMAGE_NAME="${IMAGE_NAME:-raiko-agent}"
DOCKER_REPOSITORY="${DOCKER_REPOSITORY:-us-docker.pkg.dev/evmchain/images}"
PLATFORM="${PLATFORM:-linux/amd64}"
TAG="${1:-}"

if [[ -z "${TAG}" ]]; then
  if [[ -t 0 ]]; then
    read -p "Do you have specific tag to build? default[latest]: " TAG
  fi
  TAG="${TAG:-latest}"
fi

PUSH_DECISION="${PUSH_DECISION:-}"
if [[ -z "${PUSH_DECISION}" && -t 0 ]]; then
  read -p "Do you want to push to ${DOCKER_REPOSITORY}? [y/N]: " PUSH_DECISION
fi
PUSH_DECISION=$(echo "${PUSH_DECISION}" | tr '[:upper:]' '[:lower:]')

echo "Building ${IMAGE_NAME}:${TAG} for ${PLATFORM}..."
docker buildx build . \
  -f Dockerfile \
  --load \
  --platform "${PLATFORM}" \
  -t "${IMAGE_NAME}:latest" \
  --progress=plain \
  2>&1 | tee "log.build.${IMAGE_NAME}.${TAG}"

docker tag "${IMAGE_NAME}:latest" "${DOCKER_REPOSITORY}/${IMAGE_NAME}:latest"
docker tag "${IMAGE_NAME}:latest" "${DOCKER_REPOSITORY}/${IMAGE_NAME}:${TAG}"

if [[ "${PUSH_DECISION}" == "y" || "${PUSH_DECISION}" == "yes" ]]; then
  docker push "${DOCKER_REPOSITORY}/${IMAGE_NAME}:${TAG}"
  docker push "${DOCKER_REPOSITORY}/${IMAGE_NAME}:latest"
else
  echo "Skipped push. To push later:"
  echo "  docker push ${DOCKER_REPOSITORY}/${IMAGE_NAME}:${TAG}"
  echo "  docker push ${DOCKER_REPOSITORY}/${IMAGE_NAME}:latest"
fi
