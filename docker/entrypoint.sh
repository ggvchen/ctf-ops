#!/usr/bin/env bash
# 容器入口：保证配置存在，然后把参数交给 ops；
# 第一个参数不是 ops 子命令时，直接执行（方便 `docker run -it img bash`）。
set -e

cd /opt/ctf-ops

# 首次启动（或挂载了空 config 卷）时补上配置，否则 ops 会直接报“配置文件不存在”
[ -s config/config.yaml ] || cp config/config.example.yaml config/config.yaml
[ -s config/targets.yaml ] || cp config/targets.example.yaml config/targets.yaml

mkdir -p evidence backups report outbox logs

case "${1:-}" in
  init|doctor|status|dash|version|targets|ssh|backup|scan|exploit|\
  flag|logs|traffic|shot|waf|harden|vuln|ai|auto)
    exec ./ops "$@"
    ;;
  "")
    exec ./ops dash --host 0.0.0.0 --no-open
    ;;
  *)
    # bash / sh / nmap / tshark / python3 ... 直接交给系统
    exec "$@"
    ;;
esac
