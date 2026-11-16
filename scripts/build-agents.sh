#!/usr/bin/env bash
# 构建 Go 版 WAF agent 的静态二进制（部署到靶机用，免运行时）。
#
#   ./scripts/build-agents.sh
#
# 需要本机有 go（>=1.21）。产物在 ctfops/agents/bin/waf-go-<os>-<arch>。
# 只想跑测试的话，darwin/arm64 或 linux/amd64 任一即可。
set -euo pipefail
cd "$(dirname "$0")/.."

GO=${GO:-go}
command -v "$GO" >/dev/null || { echo "找不到 go，请先安装 Go 1.21+"; exit 1; }

ROOT=$(pwd)
SRC="$ROOT/ctfops/agents/wafgo"
OUT="$ROOT/ctfops/agents/bin"
mkdir -p "$OUT"

echo "==> go vet"
(cd "$SRC" && "$GO" vet ./...)

# 靶机基本是 linux/amd64 或 linux/arm64；darwin/arm64 用于本机自测
for target in linux/amd64 linux/arm64 darwin/arm64; do
  os=${target%/*}; arch=${target#*/}
  printf "==> %-14s " "$target"
  (cd "$SRC" && GOOS=$os GOARCH=$arch CGO_ENABLED=0 \
      "$GO" build -trimpath -ldflags "-s -w" -o "$OUT/waf-go-$os-$arch" .)
  ls -lh "$OUT/waf-go-$os-$arch" | awk '{print $5}'
done
echo "完成：$OUT"
