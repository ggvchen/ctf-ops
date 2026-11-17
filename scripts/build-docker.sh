#!/usr/bin/env bash
# 构建并导出 ctf-ops 镜像
#
#   ./scripts/build-docker.sh                 # 按当前架构构建 + 导出 tar.gz
#   ./scripts/build-docker.sh linux/amd64     # 构建 x86 版（需 buildx + qemu）
#   PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple ./scripts/build-docker.sh
#
# 产物：dist/ctf-ops-<arch>-<日期>.tar.gz   （给别人的机器用 docker load -i 即可）
set -euo pipefail
cd "$(dirname "$0")/.."

PLATFORM="${1:-}"
TAG="${TAG:-ctf-ops:latest}"
DATE="$(date +%Y%m%d)"
mkdir -p dist

BUILD_ARGS=()
if [ -n "${PIP_INDEX:-}" ]; then
  BUILD_ARGS+=(--build-arg "PIP_INDEX=$PIP_INDEX")
fi
if [ "${WITH_SHOTS:-0}" = "1" ]; then
  BUILD_ARGS+=(--build-arg WITH_SHOTS=1)
fi

if [ -n "$PLATFORM" ]; then
  ARCH="${PLATFORM#linux/}"
  echo "[*] buildx 构建 $PLATFORM → $TAG"
  # macOS 自带 bash 3.2：空数组在 set -u 下直接展开会报 unbound variable
  docker buildx build --platform "$PLATFORM" -f docker/Dockerfile \
    ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} -t "$TAG" --load .
else
  ARCH="$(docker version --format '{{.Server.Arch}}')"
  echo "[*] 构建本机架构 linux/${ARCH} → ${TAG}"
  docker build -f docker/Dockerfile ${BUILD_ARGS[@]+"${BUILD_ARGS[@]}"} -t "$TAG" .
fi

OUT="dist/ctf-ops-${ARCH}-${DATE}.tar.gz"
echo "[*] 导出到 ${OUT}（稍等，镜像较大）"
docker save "$TAG" | gzip -1 > "$OUT"

echo
echo "✓ 完成"
ls -lh "$OUT" | awk '{print "  镜像包: "$9"  "$5}'
echo "  给别人的用法:"
echo "    docker load -i $(basename "$OUT")"
echo "    docker run -d --name ctf-ops -p 8899:8899 \\"
echo "      -v \$PWD/ctf-data/evidence:/opt/ctf-ops/evidence \\"
echo "      -v \$PWD/ctf-data/config:/opt/ctf-ops/config \\"
echo "      $TAG"
