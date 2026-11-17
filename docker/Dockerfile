# CTF/AWD 作战辅助系统 —— Kali 一体化镜像
#
# 目标：一个镜像里既有本项目的运行时，也有它调用到的所有外部工具，
#       比赛现场 `docker run` 起来就能用，不用再装任何东西。
#
# 构建（默认按当前架构）：
#   docker build -f docker/Dockerfile -t ctf-ops:latest .
# 构建 x86 版（给服务器用，需 buildx/qemu，会比较慢）：
#   docker buildx build --platform linux/amd64 -f docker/Dockerfile -t ctf-ops:amd64 --load .

FROM kalilinux/kali-rolling:latest

LABEL org.opencontainers.image.title="ctf-ops" \
      org.opencontainers.image.description="CTF/AWD 作战辅助系统（SSH 运维/备份/扫描/批量利用/交 flag/取证/日志与流量分析）" \
      org.opencontainers.image.source="https://github.com/ggvchen/ctf-ops"

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Asia/Shanghai \
    LANG=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/ctf-ops/.venv/bin:$PATH"

# ---------------------------------------------------------------- 系统依赖
# 关于 nmap：kali 的 nmap 带 cap_net_admin,cap_net_raw 文件能力，容器没给
# NET_ADMIN 时 exec 直接 EPERM（报 "Operation not permitted"）。这里去掉文件能力，
# 容器内 root 默认就有 NET_RAW，-sS/-sU 照常可用；要 OS 探测再 --cap-add NET_ADMIN。
#
# 说明几个容易踩的点：
#  - tshark 安装时 wireshark-common 会弹“是否允许非 root 抓包”，非交互下默认否，
#    容器里本来就是 root，不影响抓包
#  - nuclei 在 kali 源里就是 3.x 的 deb，不用去 GitHub 拖二进制（国内经常超时）
#  - default-mysql-client 提供 mysqldump，备份业务库要用
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv python3-pip python3-dev \
        nmap tshark tcpdump \
        nuclei sqlmap nikto \
        default-mysql-client \
        openssh-client curl wget git unzip jq \
        dnsutils netcat-traditional socat \
        procps iproute2 net-tools psmisc \
        ca-certificates tzdata less vim-tiny \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
    && (setcap -r /usr/lib/nmap/nmap 2>/dev/null || true)

WORKDIR /opt/ctf-ops

# ---------------------------------------------------------------- Python 依赖
# 先单独装依赖，改代码时不会重建这一层
COPY requirements.txt /tmp/requirements.txt
ARG PIP_INDEX=""
RUN python3 -m venv .venv \
 && ./.venv/bin/pip install -q --upgrade pip \
 && ( if [ -n "$PIP_INDEX" ]; then \
          ./.venv/bin/pip install -q -i "$PIP_INDEX" -r /tmp/requirements.txt python-evtx bcrypt ; \
      else \
          ./.venv/bin/pip install -q -r /tmp/requirements.txt python-evtx bcrypt \
          || ./.venv/bin/pip install -q -i https://pypi.tuna.tsinghua.edu.cn/simple \
                 -r /tmp/requirements.txt python-evtx bcrypt ; \
      fi ) \
 && rm -f /tmp/requirements.txt

# 可选：步骤截图需要 playwright + chromium（体积 +500MB，默认不装）
ARG WITH_SHOTS=0
RUN if [ "$WITH_SHOTS" = "1" ]; then \
        ./.venv/bin/pip install -q playwright \
        && ./.venv/bin/playwright install --with-deps chromium ; \
    fi

# ---------------------------------------------------------------- 项目本体
COPY . /opt/ctf-ops

RUN chmod +x ops docker/entrypoint.sh \
 && cp -n config/config.example.yaml config/config.yaml \
 && cp -n config/targets.example.yaml config/targets.yaml \
 && mkdir -p evidence backups report outbox logs \
 && ./.venv/bin/python -m compileall -q ctfops \
 && ./ops --help >/dev/null

# 运行时数据（数据库、取证产物、备份包）挂这三个目录即可持久化
VOLUME ["/opt/ctf-ops/evidence", "/opt/ctf-ops/config", "/opt/ctf-ops/backups"]

EXPOSE 8899

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8899/api/overview >/dev/null || exit 1

ENTRYPOINT ["/opt/ctf-ops/docker/entrypoint.sh"]
CMD ["dash", "--host", "0.0.0.0", "--no-open"]
