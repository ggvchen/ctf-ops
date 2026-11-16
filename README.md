# ctf-ops · CTF / AWD 作战辅助系统

一套给"打比赛的人"用的运维台。核心不是炫技，是**在 30 秒内完成一件重复劳动并留下证据**：
连靶机、备份业务、扫漏洞、批量打、抓 flag 交上去、把日志和流量讲清楚、把每一步截图存好。

> 仅用于**你被授权攻击的靶场/比赛环境**。系统默认只读优先、爆破限速、回滚可验证。

## 一条命令上手

```bash
cd ctf-ops
./ops init            # 生成 config/config.yaml 与 targets.yaml
vim config/targets.yaml   # 填靶机 IP / 账号
./ops doctor          # 自检：工具链、依赖、SSH 连通性、AI 端点
./ops dash            # 打开 Web 作战控制台 http://127.0.0.1:8899
```

`./ops` 会自动使用项目内 `.venv`，首次运行自动装依赖。
控制台和命令行操作**同一套数据**（`evidence/ops.db`），浏览器里点的每一步同样会入库、同样进报告。

## Web 控制台

`./ops dash` 起一个本地服务（默认只监听 `127.0.0.1:8899`），浏览器里完成全部动作：

| 页面 | 能做什么 |
| --- | --- |
| 总览 | 靶机/发现/FLAG/待提交/备份实时计数、严重度分布、最新发现、六个一键动作 |
| 靶机 | 清单（**防守 / 攻击** 角色、认证方式、Web、标签、**逐机 token**）、**接口配置（提交 flag 接口 + flag 服务器请求格式，一次填完）**、单条添加、**按 IP/域名列表批量添加攻击目标**、**编辑（含改名）与删除**、**勾选后批量改角色 / 改备份源 / 删除**（写回 YAML 且保留注释） |
| 运维 | 选靶机 → 下发命令 → 逐台回显 rc/输出/耗时，支持 sudo 与超时 |
| 备份 | 建备份（tag + 是否带 MySQL）、备份列表、一键回滚（二次确认） |
| 扫描 | 端口 / Web 指纹 / nuclei 三个按钮；**发现汇总分页（20/50/100/200 每页）+ 勾选批量删除 + 撤销删除**，可按严重度过滤，点行看证据 |
| 利用 | 选插件、勾「只探测」、批量打，结果表直接显示命中与提取到的 FLAG；**AI 按漏洞描述写插件** |
| FLAG | 上机检索、发现即提交、待提交一键补交、每条可复制、**flag 服务器一键拉取 / 单机调试** |
| 日志 | 拉取靶机日志并分析；**本地路径支持拖入文件/文件夹**；支持 **Linux auditd / Windows EVTX / sshd / Web 访问日志**；结果含统计、发现、时间线、明细、完整报告 |
| 流量 | **pcap 可直接拖进来**；出统计、发现、可疑时序；**响应体在内存里扫 flag，默认不落盘** |
| 取证 | 填 URL 自动截图 / 登记已有截图 / 生成时间线 / 缩略图画廊 |
| AI | **本地模型配置（端点预设 / 拉模型列表 / 连通测试 / 保存即生效）**、带文件提问、源码审计 |
| 报告 | 生成 md + html，产物列表可预览可下载 |

交互细节：
- 长任务（扫描、备份、利用、日志、流量）**异步执行**，右下角任务抽屉实时滚日志，带颜色分级；
- 日志走 **WebSocket 推送**（标准库手写 RFC 6455，不是轮询）：断线自动重连，连续失败才降级为 900ms 轮询，顶栏右上角有 `实时 / 重连中 / 轮询` 状态灯；
- 抽屉支持多任务切换，关掉页面不影响任务继续跑，重新打开还在；
- 每个动作执行完自动刷新相关表格与顶部计数；
- 备份目录在「备份」页可直接改（默认 `backups/`），保存后立即生效，外置盘上的历史包也会出现在产物列表里。

## 能力地图

| 需求 | 命令 | 说明 |
| --- | --- | --- |
| SSH 连靶机 | `ops ssh exec -t web-01 "id"` | 批量并发、sudo、自动重连，结果入库 |
| 传文件 | `ops ssh upload /local /remote -t all` | SFTP，自动建目录 |
| 现场取证 | `ops ssh snapshot -t all` | 进程/网络/账号/cron/最近登录一屏打尽 |
| 备份业务系统 | `ops backup run -t all --tag baseline` | 远端 tar + mysqldump → 拉回 → sha256，可回滚 |
| 扫端口 | `ops scan ports -t all --ports 1-65535` | 优先 nmap；不可用时自动回退内置 TCP 扫描 |
| Web 指纹 | `ops scan web -t all` | 存活、框架、注释线索、上传点、敏感路径 |
| 扫漏洞 | `ops scan vulns -t all` | nuclei，AI 排序攻击路径 |
| 批量利用 | `ops exploit run thinkphp_rce -t all` | 插件式 PoC，多线程，命中即入库 |
| 找 flag | `ops flag hunt -t all --submit` | SSH grep + 常见落点 + 本地扫描 |
| 问 flag 服务器 | `ops flag server --url 'http://10.10.0.1/api/flag?token={token_url}'` | 经靶机请求内网接口，token 可从靶机文件读 |
| 交 flag | `ops flag submit` | 幂等去重、失败重试、限速、双模式（API/人工） |
| 日志分析 | `ops logs analyze auth.log access.log` | 爆破、爆破后登录、提权、webshell、注入，出时间线 |
| 拉日志分析 | `ops ssh logs -t all` | 远端拉取 + 分析 + 快照，一条命令 |
| 流量分析 | `ops traffic analyze xxx.pcap` | 扫描/注入/上传/凭据/反弹 shell/flag 提取 |
| 步骤截图 | `ops shot capture "3-上传shell" --url ...` | 浏览器截图 + 时间线 |
| 多机终端 | `ops dash` → 终端页 | 每机常驻 shell、广播命令、状态保留 |
| WAF 部署 | `ops waf deploy -t @defense` | 旁路读访问日志，默认只监听不动流量 |
| 攻击审计 | `ops waf audit --to-vuln` | 拉命中记录，可直接进漏洞库 |
| 加固封禁 | `ops waf enforce --rule sqli,cmdi` | SIGHUP 热加载，命中即封禁源 IP |
| 漏洞重放 | `ops vuln replay --all -t @attack` | 把抓到的攻击请求打到对手靶机 |
| AI 写插件 | `ops ai plugin "CVE-2021-41773 ..."` | 生成 → 校验 → 草稿 → 人工启用 |
| 出报告 | `ops report` | Markdown + HTML，含 flag 提交表 |
| Web 控制台 | `ops dash` | 全功能操作台，长任务异步 + 实时日志 |
| 本地 AI | `ops ai ask "@源码.php 找漏洞"` | OpenAI 兼容端点，不可用自动降级；页面可改端点与模型 |

## AWD 实战节奏

```bash
# T+0   开局：连通性 + 摸资产（2 分钟）
./ops doctor
./ops scan ports -t all --ports 1-10000

# T+2   立刻备份，防被打挂（最重要的一步）
./ops backup source -t @defense            # 先看一眼备份源对不对
./ops backup source -t @defense --detect   # 不对就远程探一下
./ops backup run -t @defense --tag baseline

# T+5   找入口：Web 指纹 + 模板扫描
./ops scan web -t all
./ops scan vulns -t all

# T+10  进攻：批量打，命中即交 flag
./ops exploit run thinkphp_rce -t all
./ops flag hunt -t all --submit

# T+15  防守：上 WAF（只监听，不改业务流量）
./ops waf deploy -t @defense --mode monitor

# 每轮   防守：看自己有没有被打
./ops waf audit --to-vuln      # WAF 命中 → 漏洞库
./ops ssh logs -t all          # 拉日志 + 爆破/webshell/提权研判
./ops ssh snapshot -t all      # 现场快照留证

# 抢分   把对手打我们的 payload 打回去
./ops vuln replay --all -t @attack

# 被打狠了  加固：命中即封禁源 IP
./ops waf enforce -t @defense --rule sqli,cmdi,webshell

# 被打挂  回滚
./ops backup list
./ops backup restore backups/web-01_baseline_20261116_101500.tar.gz -t web-01 --yes

# 收尾
./ops shot timeline && ./ops report
```

要点：
- **备份永远在改动之前**。`--tag` 用 `baseline` / `pre-patch` 区分。
- `flag hunt` 是 AWD 里性价比最高的动作——flag 常直接落在 `/flag`、`/tmp`、web 目录。
- 平台风控躲不过就去改 `submit.interval`，别用 `--workers` 硬顶。

## CTF 解题节奏

```bash
# 做题同时留证，writeup 直接成文
./ops shot capture "1-信息收集" --url http://target --note "robots.txt 泄露 /backup"
./ops shot capture "2-SQL注入" --url "http://target/?id=1'" --note "报错注入回显"
./ops shot mark "3-拿到flag" --image ~/Desktop/flag.png --note "flag{...}"

./ops ai audit ./src/upload.php          # 源码审计
./ops traffic analyze capture.pcap       # 流量题
./ops logs analyze ./logs                # 日志题
./ops shot timeline                       # 生成图文时间线
```

## 配置要点

`config/config.yaml` 里三块最关键：

**1. 凭据用环境变量，别写进仓库**

```yaml
ssh:
  user: root
  password: ${TARGET_PASSWORD:-}
  key_file: ${TARGET_KEY:-~/.ssh/id_rsa}
```

靶机可各自覆盖，支持 `{name, host, ssh_port, user, password, key_file, web, webroot, tags, note, db, role}`。

`role` 决定"这台机器是自家的还是对手的"，影响默认选择：

| 角色 | 含义 | 默认参与的动作 |
| --- | --- | --- |
| `defense`（默认） | 我方靶机 | 备份、WAF、日志取证、终端、快照 |
| `attack` | 攻击目标 | 扫描、漏洞利用、漏洞重放 |

命令行也可用 `@attack` / `@defense` 直接按角色选目标，如 `ops scan web -t @attack`。

**备份源（`webroot`）**：要打包的远端目录，三种来源按优先级取：

1. 本次任务显式指定（API `sources` / `backup_target(src=...)`）
2. 靶机配置里的 `webroot`（Web 端「备份」页可改，写回 YAML）
3. 自动探测：读 nginx/apache 配置里的 `root`，再退回 `/var/www/html`、`/www/wwwroot` 等常见路径

```yaml
targets:
  - name: web-01
    host: 10.16.0.73
    webroot: /www/wwwroot/portal     # 留空 = 自动探测
```

打包前会先用 `[ -d ]` 确认目录存在——**否则 tar 会生成一个空包，看起来却"成功"了**（这个坑踩过）。
Web 端「备份」页顶部就是这张表，保存即写回 YAML，靶机暂时不通也能先存着（会提示未验证）。

**2. FLAG 提交：两种模式**

```yaml
# A. 平台有 API
submit:
  mode: generic_http
  url: https://platform.example.com/api/flag
  method: POST
  json_body: {flag: "{flag}", token: "{token}"}
  headers: {Content-Type: application/json}
  token: ${FLAG_TOKEN}
  success_key: success        # 响应里判断成功的字段，支持 data.code 这种嵌套
  interval: 1.0

# B. 平台只能网页提交（默认）
submit:
  mode: manual
```
manual 模式把 flag 写到 `outbox/flags_YYYYMMDD.txt`，一行一个，方便粘贴。

**3. 本地 AI（不联网）**

```yaml
ai:
  base_url: http://127.0.0.1:11434/v1   # Ollama
  model: qwen2.5:7b
```

| 本地服务 | base_url | 启动 |
| --- | --- | --- |
| Ollama | `http://127.0.0.1:11434/v1` | `ollama serve && ollama pull qwen2.5:7b` |
| LM Studio | `http://127.0.0.1:1234/v1` | 界面里开 Local Server |
| vLLM | `http://127.0.0.1:8000/v1` | `vllm serve Qwen/Qwen2.5-7B-Instruct` |

模型选择（本机 LM Studio 实测过一轮，供参考）：

| 用途 | 建议 | 实测 |
| --- | --- | --- |
| 日志/流量研判、问答 | 20B 以上的指令模型 | 35B-A3B（MoE）单轮 12–20 秒，够快 |
| 源码审计 | 代码向模型（`qwen2.5-coder` 系列） | 27B 稠密模型首轮含加载约 60 秒 |
| 写 PoC 插件 | 同上，温度 0.1–0.2 | 35B 生成 40 行插件约 36 秒 |

```bash
./ops ai check                       # 端点 + 模型可用性
./ops ai ask "@www/upload.php 这里有什么漏洞"   # @路径 直接注入文件内容
./ops ai audit www/upload.php       # 结构化审计：漏洞点 + payload + 修复
./ops ai plugin "CVE-xxxx 描述"      # 生成 PoC 插件（先落草稿，人工确认再启用）
```

**AI 只做研判建议**——端点不可用时全部功能照常，规则引擎结果仍然输出。
模型名直接写 LM Studio 里显示的那个 id，比如
`qwen3.8-35b-a3b-distill-mtp-apex-i-miniplus-v2.1-abliterated`；写错会得到 404 而不是静默失败。

插件生成做了两层兜底：**NAME 自动规整**（模型爱把 `cve-2021-41773` 直接当标识，
而插件名要当模块名用，只能 `[a-z0-9_]`）和**校验失败回喂模型重试一次**
（把 AST 报错原文发回去让它自己改，比重新描述一遍有效得多）。

## 靶机增删改

```bash
ops targets                                  # 列表（不带子命令也能看）
ops targets add 10.16.0.74 --role attack --web http://10.16.0.74
ops targets edit web-01 --host 10.16.0.74 --role defense --webroot /www/wwwroot/portal
ops targets edit web-01 --name web-01-prod   # 改名
ops targets rm old-01 --yes                  # 删除（历史记录保留）
ops targets batch -t @defense --role attack  # 批量改角色
ops targets batch -t a,b,c --webroot /www/wwwroot/site
ops targets batch -t @attack --delete --yes  # 批量删除
```

Web 端在「靶机」表格每行右侧有「编辑 / 删除」；勾选多行后表头右侧出现批量条，可以：

- **批量改角色**：下拉选防守/攻击 → 应用角色
- **批量改备份源**：输入一个远端绝对路径（留空 = 恢复自动探测）
- **批量删除**：二次确认，历史记录同样保留

批量操作**读一次文件、写一次盘、重载一次配置**，不是逐台调用接口；任何一步失败整批回滚。

几个约定：

- **写入方式是行级手术**：只改对应字段那一行（含 `web:` 这类块状列表的续行），注释、缩进、字段顺序都保留；写完回读校验，不一致自动回滚。
- **改名会级联**：`backups / events / flags / vulns / shots` 里的 `target` 一起更新，看板与报告不会对不上；同时会关掉该靶机已开的终端会话。
- **删除只删配置**：历史备份、发现、FLAG 全部保留（可在返回里看到保留条数），只是不再参与扫描/备份/防护/重放。
- **凭据留空表示不修改**；要清掉口令与密钥，勾「清除已有口令 / 密钥」（CLI 用 `--clear-credentials`）。

## 扫描规则与模板都在哪

这套系统的"漏洞检测"分三层，规则位置各不相同——想加东西时对着下面找：

| 层 | 位置 | 是什么 | 怎么加 |
| --- | --- | --- | --- |
| **Web 指纹** | `ctfops/scan.py` 的 `INTERESTING` | 敏感路径字典（`.git/config`、`.env`、`backup.zip`、`/flag`…），带级别 | 加一行 `"/路径": ("说明", "high")` |
| **nuclei 模板** | 靶机侧容器 `redteam-kali` 的 `/root/nuclei-templates`（本机约 1.4 万个 YAML） | CVE / RCE / 默认口令等社区模板，按标签收敛 | 把自定义 `.yaml` 放进该目录，用 `--templates` 指定 |
| **PoC 插件** | `ctfops/plugins/exploits/*.py` | 自己写的利用插件（现成 4 个：ThinkPHP RCE、Apache 穿越、Redis 未授权、SSH 弱口令） | 复制 `_template.py` 照着写 |
| **WebShell 特征** | `config/rules/webshell.yaml` | 主机侧后门特征库（19 条），可调分值 | 直接改 YAML，保存即生效 |
| **WAF 规则** | `ctfops/waf.py` 的 `DEFAULT_RULES` | 10 条旁路检测规则（sqli/traversal/cmdi/…） | 改源码或部署后改靶机上 `rules.json` |

nuclei 在本机是 **docker 包装器**（`~/.local/bin/nuclei` → `docker exec redteam-kali nuclei`），
所以要求 OrbStack/Docker 处于运行状态，且目标地址要能在容器内访问：

```bash
docker exec redteam-kali ls /root/nuclei-templates | head   # 模板在哪
docker exec redteam-kali nuclei -tl | wc -l                 # 模板总数
./ops scan vulns -t @attack --tags cve,rce,sqli              # 按标签跑
./ops scan vulns -t @attack --templates http/technologies/    # 按目录跑
```

程序已处理两个坑：**结果走 stdout**（`-o` 写的是容器内路径，宿主机读不到，会静默 0 结果）；
**`127.0.0.1` 自动改成 `host.docker.internal`**（否则容器里的 127.0.0.1 是它自己）。

> 全量 1.1 万个模板扫单个站点要几分钟，所以默认按 `scan.nuclei_tags` 收敛。
> 想全量就 `--tags cve` 或把配置里 `nuclei_tags` 置空，然后在网页上异步跑。

## WebShell 主查杀（D盾 那类）

nuclei 是"发请求找洞"，查杀是"看文件找马"。这一层对标 D盾 的核心能力：

```bash
./ops scan shell --path backups/site-20261116.tar.gz     # 扫备份包
./ops scan shell --path /www/wwwroot/site                # 扫本地目录
./ops scan shell -t @defense                             # 从靶机 webroot 拉脚本再扫
```

靶机上**不需要任何运行时**：远端只用 `tar` + `find` 打包脚本文件拉回本地，规则匹配在本地做。

内置 19 条规则，覆盖一句话、变量函数、`base64_decode`/`gzinflate` 组合、命令执行、
文件写入、冰蝎、哥斯拉、蚁剑、无字母混淆、十六进制密集、图片马、反弹 shell、`.user.ini` 劫持等；
再加 4 条文件级启发式（极小文件含 eval、超长单行、24 小时内改动、777 权限）。

打分制：单文件累计 **≥70 判恶意、≥40 判可疑**，同一规则多次命中不重复加分但会记 `×N`。
实践效果（`tests/fixtures/webroot`）：

```
malicious 100  uploads/2024.php    +95 一句话木马(eval 收 POST)   +60 极小文件
malicious 100  uploads/shell.php   +95 冰蝎特征                   +80 base64+eval
malicious 100  inc/cache.php       +85 gzinflate+eval             +80 base64+eval
malicious 100  static/logo.jpg     +90 图片马                     +90 system 收 GET
suspicious 40  inc/conf.php        +25 权限 777                   +15 24h 内改动
```

业务文件（`index.php`、`inc/db.php`、`.htaccess`）全部判 clean，不误报。

## 自动作战：防守靶机自动守，攻击目标自动打

角色决定动作，一条命令跑完：

```bash
./ops auto run                    # 守 + 打 + 交（推荐）
./ops auto run --defense          # 只做防守
./ops auto run --attack --no-submit   # 只打不交
./ops auto run --dry-run          # 只看会做什么，不动手
```

Web 端在「总览 → 自动作战」，两行控制：

- 第一行：**全流程（守+打+交）** / **只防守** / **只攻击** + 三个开关（含备份 / 含查杀 / 含重放）
- 第二行：**定时** 开关（选 5/10/15/30 分钟一轮）+ **AI 排序攻击路径** 按钮

跑完直接显示每一步的结果、拿到的 flag、以及平台返回。

**定时模式**适合无人值守：后台线程按间隔反复跑「守+打+交」，顶部胶囊显示
「定时中 · 第 N 轮」和倒计时。三个细节：

- 已提交过的 flag **不会重复提交**（平台会判重复，还可能触发风控）；
- 每轮失败只记 `errors` 继续下一轮，定时器不会因为一次异常停掉；
- 页面刷新后能从缓存恢复，不用重新跑一遍（模型一轮要一两分钟）。

**防守靶机（role=defense）走这五步**：

| 步骤 | 做什么 | 幂等策略 |
| --- | --- | --- |
| WAF 状态 | 没在跑就按站点语言部署（Go/PHP/python） | 已在跑就跳过 |
| 基线备份 | 打包 webroot + 可选 mysqldump | 当天已备份就跳过 |
| 后门查杀 | 拉回脚本文件过 19 条特征规则 | 每次都查（业务会变） |
| 自动加固 | 查到后门才切 enforce，拦截 webshell/phpcode/cmdi | 没后门不动 |
| 攻击入库 | WAF 命中写进漏洞库，供攻击侧重放 | 30 分钟窗口去重 |

**攻击目标（role=attack）走这四步**：Web 指纹 → 逐个插件（check 不过自动跳过）→
把 WAF 抓到的 payload 重放过来 → 收集响应里的 flag 入库。

实测一轮（真 Docker 靶机 + 模拟靶场）4 秒完成：

```
防守 lab-def   WAF 状态 php enforce 已运行
防守 lab-def   基线备份 webroot=/var/www/html
防守 lab-def   后门查杀 扫 8 个文件，恶意 4：inc/cache.php、uploads/shell.php、uploads/2024.php
防守 lab-def   自动加固 拦截规则 sqli, cmdi, phpcode, webshell（PHP 版在请求内直接 403，不封 IP）
防守 lab-def   攻击入库 命中 3 类，新增 3 条

攻击 lab-atk   Web 指纹 Server=Apache/2.4.49 (Unix)
攻击 lab-atk   插件 apache_traversal  ✓  GET /cgi-bin/.%2e/.../etc/passwd
攻击 lab-atk   插件 cve_2021_41773    ✓  读到 passwd，含 flag
攻击 lab-atk   插件 redis_unauth/ssh_weak/thinkphp_rce  ✗ check 未命中（跳过）
攻击 lab-atk   漏洞重放 3 次请求，3 次有响应

提交成功 1/1 → 平台返回 "flag 正确，+100"
```

**刻意的取舍**：

- **不自动删文件**。查到后门只加固 + 报警，删文件交给人在界面确认——自动删错一个业务文件，
  AWD 直接掉分，比被挂马还亏。
- **失败不中断**。任何一步异常都记进报告的 `errors` 继续往下做，比赛里时间比流程完整重要。
- **单步可关**。备份/查杀/重放都能单独关掉，慢的时候先保命。

## 提交接口：直接粘浏览器的 cURL

> 现在两个请求格式都在「靶机 → 接口配置」里统一填：左边是**提交 flag 接口**，
> 右边是**flag 服务器**（下一节）。flag 页只留一键拉取/提交的快捷按钮。
> 老路子（cURL 导入）依然可用，保存的是同一条「页面配置」。

比赛平台的提交接口形状各异（JSON、form、带 CSRF 头、cookie 鉴权）。手工在 YAML 里拼
很容易漏一个头就 403，而浏览器 `Network → 右键提交请求 → Copy as cURL` 是现成的、**100% 准确**的请求描述。

```bash
./ops flag curl "curl 'https://ctf.example.com/api/submit' \
  -H 'content-type: application/json' \
  -H 'x-csrf-token: abc' \
  --data-raw '{\"flag\":\"flag{xxx}\",\"team\":\"t1\"}'" \
  --name ctf-example --test 'flag{一个真flag}'
```

Web 端在「FLAG → 提交接口」：粘贴 → 自动解析出 `POST /api/submit`、
保留 `content-type` / `x-csrf-token`、把 `flag` 字段替换成 `{flag}` 占位符 →
填个名字保存即启用，可以顺手填一个真 flag 试提交。

**能认出的格式**：Chrome/Edge 的 bash 形式（含 `$'...'` 与反斜杠续行）、Firefox 的 bash 形式、
Windows cmd 形式（`^` 续行 + 双引号）。`Host`、`Content-Length`、`Sec-*`、`Accept-Encoding`
这类复制出来就没用的头会自动丢掉。

**flag 位置的识别**是两级判断：

1. 按字段名：`flag` / `answer` / `content` / `key` …（`token`、`csrf`、`session` 这类一律跳过）
2. 按值的形状：`flag{...}` / `CTF{...}` / 32-40-64 位 hex / base64

支持嵌套 JSON（`data.answer` 这种路径也能定位），也支持 URL 查询参数里带 flag。
认不出时用 `--flag-key data.answer` 手工指定。

**多套配置**：导入的接口存在 `submit_profiles` 表里，可以同时留多个（不同平台/场次），
随时切换激活项。提交器优先用激活的导入配置，没有才回落到 `config.yaml` 的 `submit` 段，
所以原有 YAML 配置不会被破坏。

导入的配置默认 `strict=true`：响应里既没有 JSON 成功字段、也没有 success/correct 关键词时
**按失败处理**并回显响应片段——避免"其实没交上却显示成功"这种最难受的误判。

## flag 服务器：flag 不在机器上，只能从内网接口问

不少比赛的 flag 不落盘，而是给一个只在内网开的接口（`http://10.10.0.1/api/flag?token=...`），
必须**从靶机内部**请求，本机直连不到。这就是「经靶机取 flag」：

```
靶机页填格式  →  SSH 上靶机执行 curl/wget/python3  →  解析响应  →  入库  →  提交
```

在「靶机 → 接口配置 → flag 服务器」里填一次，之后在「FLAG」页点**立即拉取**即可
（定时作战和轮次监控也都会自动走这一步）。

| 字段 | 说明 |
| --- | --- |
| 方式 | `HTTP 请求` 或 `本地命令`（平台给的是 `/readflag`、`./getflag` 这种） |
| 服务器地址 | 从靶机上能访问的地址；支持占位符（见下） |
| 响应字段 | JSON 里 flag 的位置，如 `data.flag`；留空则用 `flag_patterns` 正则扫全文 |
| 在靶机上取 token 的命令 | 默认 `cat /flag_token \|\| cat /token`，平台把每队 token 落到文件里的场景 |
| 逐机 token | 靶机表格里直接填，优先级最高（每台机器 token 不同的比赛） |
| 工具 | `自动降级`（默认）：curl → wget → python3，按靶机上有什么自己选 |

**占位符**（URL / 请求头 / 请求体 / 命令里都能用）：

| 占位符 | 替换成 |
| --- | --- |
| `{token}` | token 原样（shell 安全引用，含 `'` `;` `$()` 也不会被当成命令执行） |
| `{token_url}` | token 做 URL 编码（base64 里的 `+ / =` 进查询串必须转义） |
| `{ip}` `{host}` `{name}` | 靶机地址 / 名称 |

命令行的等价操作：

```bash
./ops flag server --url 'http://10.10.0.1/api/flag?token={token_url}&host={ip}' \
                  --field data.flag --token-cmd 'cat /flag_token'
./ops flag server --show          # 看当前配置
./ops flag server --dry-run       # 只跑一台，把命令和原始响应摊开
./ops flag server                 # 全部跑一遍（默认拉完自动提交）
```

几个真实的坑，都已经处理：

- **rc=0 但 HTTP 403**：`curl` 拿到 403 依然返回 0，只看退出码会误判成功。现在用
  `-w '%{http_code}'` 把状态码带回来，`>=400` 一律算失败并回显响应片段；
- **响应不是纯 JSON**：先按整体解析，失败就截 `{...}` 再试一次；再不行才退回正则；
- **配置写坏就起不来**：页面保存走行级 YAML 编辑 + 回读校验，值对不上立刻中止不落盘，注释和顺序都不动。

## AWD 轮次监控（自动跟 flag 刷新）

AWD 每 N 分钟换一次 flag，换完要重新提交。`ops flag watch` 就是盯这件事的：

```bash
./ops flag watch -t @defense --interval 300          # 常驻，每 5 分钟查一次
./ops flag watch --once                              # 只查一轮
./ops flag watch --interval 120 --no-submit          # 只检测不提交
./ops flag watch --deep                              # 每轮都全盘 grep（慢但不会漏）
```

判定逻辑很简单但够用：**flag 内容变了就是换轮了**（平台不会主动通知）。

- 每台靶机维护一个"已知 flag 集合"，当前集合减已知集合 = 新 flag；
- 先探固定落点（`/flag`、`/flag.txt`、`/root/flag*`、`/tmp/flag*`、`/var/www/html/flag`），
  一次 `exec` 就够，代价极低；没探到才退回全盘 `grep`（`--deep` 强制每轮都 grep）；
- 新 flag 入库（`flags` 表 digest 唯一，天然幂等）→ 交给 `submit` 配置的方式提交；
- 每轮结果写 `rounds` 表，界面「FLAG → 轮次记录」能看到"第几轮、哪台、flag、是否刷新、提交结果"；
- **已知集合落 `settings` 表**，进程重启不会把旧 flag 当新的再交一遍（这点在 AWD 里很关键，
  重复提交轻则无效，重则被判作弊）。

Web 端在「FLAG」页：选间隔（60s ~ 15min）→ 启动 → 显示"第 N 轮 · 下次检测 X 秒"，
另有「立即检查一轮」「清空已知」（换场次用）。

## 用 Docker 搭测试靶机

本机 Docker 可用时，最好的练手方式是自己起一台带后门的靶机：

```bash
# PHP 站点（mod_php），把仓库里的样本目录挂进去
docker run -d --name ctf-lab -p 18080:80 \
  -v "$PWD/tests/fixtures/webroot:/var/www/html" \
  docker.m.daocloud.io/library/php:8.2-apache
docker exec ctf-lab a2enmod rewrite && docker restart ctf-lab

./ops targets add 127.0.0.1:18080 --role attack -n lab-docker --web http://127.0.0.1:18080
./ops scan web -t lab-docker        # 指纹
./ops scan vulns -t lab-docker      # nuclei 模板
./ops scan shell --path tests/fixtures/webroot   # 查杀（4 个后门全中）
```

`tests/fixtures/webroot` 里放了 4 个真实的马（一句话、冰蝎、gzinflate+base64、图片马）和
正常业务文件，用来验证"该报的报、不该报的不报"。
镜像源换成了 `docker.m.daocloud.io`，因为直连 Docker Hub 在本机不通。

## WAF 与漏洞闭环

比赛里最有价值的不是"拦住"，而是**知道谁在打我们、用什么打、然后照着打回去**。这套闭环是：

```
访问日志 ──► WAF agent（只监听）──► 攻击审计 ──► 漏洞库 ──┬─► 加固（封禁源 IP）
                                                          └─► 重放（打对手靶机）
```

**三种引擎，按站点运行时自动挑**（也可 `--engine` 强制）：

| 引擎 | 依赖 | 原理 | 适用 |
| --- | --- | --- | --- |
| `go`（默认优先） | **无**，静态单文件 | 读访问日志做旁路检测 | 任何站点，尤其是没 python3 的镜像 |
| `php` | 站点本身就是 PHP | `watchbird.php` 挂 `auto_prepend_file`，请求内检测 | PHP 站（php-fpm / mod_php） |
| `python` | 需要 python3 | 读访问日志做旁路检测 | 有 python3 的机器，行为与 Go 版一致 |

```bash
./scripts/build-agents.sh       # 一次性：构建 linux/amd64、linux/arm64、darwin/arm64 的 Go agent
./ops waf deploy -t @defense --engine auto     # auto: Go > PHP > python
./ops waf deploy -t @defense --engine php      # 强制用 watchbird
```

Go agent 是**单文件静态二进制**（约 2.2MB，`CGO_ENABLED=0`），上传到 `/tmp/ctfops-waf/waf-go`
就能跑，不需要目标机有任何运行时——这正是"目标机没有 python3"时的解法。
PHP 版 `watchbird.php` 则挂在 `auto_prepend_file` 上，连日志都不用读。
三者写同一份 `audit.jsonl`、同一套 `rules.json`，所以后面的审计/漏洞库/重放完全不用改。

配置与状态都在靶机 `/tmp/ctfops-waf`，SIGHUP 热加载，**不重启业务、不改端口**。

```bash
./ops waf deploy -t @defense --mode monitor --logs /var/log/nginx/access.log
./ops waf status -t @defense
./ops waf audit  -t @defense --to-vuln            # 命中进漏洞库
./ops vuln replay --all -t @attack                # 打到攻击目标
./ops waf enforce -t @defense --rule sqli,cmdi    # 命中即封禁
./ops waf stop -t @defense --unban
```

内置 10 条规则：SQL 注入、路径穿越、命令注入、PHP 代码注入、XSS、Log4j/JNDI、
webshell 访问、敏感文件探测、扫描器 UA、SSRF。匹配前先做 URL 解码（含双层编码），
因为真实日志里的 payload 基本都是编码过的；一条请求命中多条时只记第一条（最具体）。

**加固做了什么**：把命中规则标记为 `block`，agent 进入 `enforce` 模式，
对命中源 IP 执行 `iptables -I INPUT -s <ip> -j DROP`（`--no-ban` 可只记录不封）。
`ops waf stop --unban` 会清空 INPUT 规则。

**漏洞重放**：从审计记录还原 `METHOD + path + UA`，Host 换成攻击目标自己的地址再发一遍；
2xx/3xx 记为有响应，响应里的 flag 自动提取入账。

## 日志格式支持到哪一步

自动识别，不用手工选格式：先看内容特征，再拿文件名兜底。

| 平台 | 格式 | 识别依据 | 给出什么 |
| --- | --- | --- | --- |
| Linux | **sshd / auth.log / secure** | 认证类行占比 > 50%，或文件名 | 爆破源 IP 计数、成功登录、sudo 命令、建号 |
| Linux | **syslog / messages / journalctl 文本** | `时间 主机 服务[pid]:` 通用行 | Top 服务、级别分布、认证失败、可疑 CRON、OOM/segfault、关审计 |
| Linux | **auditd** | `type=SYSCALL` / `msg=audit(` | 按一次 syscall 合并 EXECVE/PATH/CWD/PROCTITLE，还原**完整命令行**：打包、外传、账号变更、SUID、痕迹清理 |
| Linux | **bash/zsh 历史** | `#<epoch>` 时间戳行或文件名 | 远程脚本直连执行、反弹 shell、解码执行、持久化、清历史 |
| Linux | **dpkg / yum / dnf** | `install ...` / `Installed:` | 装了什么包，netcat/nmap/socat 这类攻击工具重点标记 |
| Linux | **nginx / apache error.log** | `[时间] [级别] [client IP]` | PHP 致命错误、包含失败、上游拒绝、单 IP 高频报错 |
| 通用 | **Web 访问日志（combined）** | 组合日志正则 | 注入/穿越/上传/扫描器 UA、404 洪水 |
| Windows | **EVTX**（Security/System/Application/Sysmon/PowerShell） | 扩展名 `.evtx` | 4625 爆破、4720/4732 建号提权、7045/4697 服务、4698 计划任务、1102 清日志、4648 横向、4104 脚本块；Sysmon 1/3/8/10/13/22 按 Provider 单独判定 |
| Windows | **wevtutil 导出**（`/f:text`、`/f:xml`、PowerShell 导出） | `Event[N]:` 或 `<Event` | 与 EVTX 同一套研判规则 |
| Windows | **IIS 日志** | `#Fields:` 含 `cs-uri-stem` | 扫描器 UA、可疑 URI、状态码分布、Top URI |
| Windows | **防火墙日志**（pfirewall.log） | `#Fields:` 含 `action`/`src-ip` | DROP 计数、Top 源 IP |

EVTX 用 `python-evtx`：装到项目 venv 或用户站点（`pip install --user python-evtx`）都能被认出来，
缺库时报告会直接给安装命令和 `wevtutil` 备选，不会只丢一句"未识别"。

**多文件只跑一次 AI**：每个文件先走规则引擎，最后把合并后的材料交一次大模型做综合研判
（早先是每文件一次 + 合并再一次，两个文件就是 3 次调用，本地 35B 要两三分钟，看着像卡死）。
任务日志会逐条报进度：`[1/2] 分析 audit.log` → `AI 综合研判…` → `分析完成`。

## 流量分析为什么不导文件

以前用 `tshark --export-objects` 把 HTTP 对象全导出再清理：一个 19MB 的包能导出
**4.4 万个文件、占 211MB**，而且清理时的成批 `unlink` 会被宿主的安全删除守卫拦下，
分析线程直接被打断 —— 界面上就表现为**任务永远停在"执行中"**（`ended` 有值、`status`
还是 running，因为异常是 `BaseException` 而不是 `Exception`）。

现在两处都改了：

1. `analyze_pcap` 默认**不导出**，直接读 `http.file_data` 字段在内存里扫 flag
   （本例 13600 段响应体，9 秒跑完，磁盘 0 增长）。需要人工翻文件时把
   `config.yaml` 的 `export_objects: true` 打开，导出目录会**全部保留不删除**；
2. `JobManager._run` 补了 `except BaseException`：任务被外部打断也会落到 `failed`
   并写明原因，不会再出现"永远执行中"。

顺带加了进度日志（协议分布 → HTTP 请求数 → SYN 统计 → 凭据 → 响应体 → AI），
18MB 的包带 AI 大约 3 分钟，至少能看见它在动。

## 拖拽导入：日志 / 流量直接拖文件进来

浏览器出于安全拿不到本地文件的绝对路径，所以「拖进来」的实际动作是**上传一份到
`workdir/evidence/uploads/<时间戳>/<文件名>`**，再把路径自动填进输入框 —— 分析接口本来就
支持 workdir 相对路径，所以拖完直接点「分析」就能跑。

- **文件夹也能拖**：递归展开目录结构（`webkitGetAsEntry`），保留相对层级；
- **同一个文件拖多次不会重复占空间**：先问 `/api/upload/exists?name=&size=`，命中就复用原路径；
- 跑在 Electron 外壳里时（`File.path` 有值）直接用原路径，不复制；
- 拖拽时输入框高亮，松开变绿；单个框只收一个文件（流量页），日志页支持多个用逗号累积；
- 上限：单文件 2GB、单次 500 个文件 / 合计 1GB，超了会提示并跳过；
- 服务端只允许写 `evidence/uploads/` 下，`../` 和绝对路径一律 400。

## 发现汇总：分页 / 批量删除 / 撤销

发现会越攒越多（一次全盘查杀就能上百条），所以列表按页给：

- 每页 20/50/100/200 可选，工具条显示「共 N 条 · 第 x/y 页 · 已选 M 条」；
- 表头勾选框管当页，**跨页勾选按 id 记住**（翻页不丢），删除只删勾选的那些；
- 「清空筛选结果」按当前级别筛选全删；删到最后一页空了会自动回退一页。

**删前一律落盘**：每次删除都会在 `evidence/trash/` 写一份
`findings-<时间>-<选中|筛选>.json`，工具条上的「撤销删除（N）」直接把它回填回去
（回填按 `ts+target+title` 去重，不会重复插入）。发现是证据，误删一次就说不清了。

```bash
curl -s localhost:8899/api/findings/trash            # 有哪些快照
curl -s -X POST localhost:8899/api/findings/restore \
     -H 'Content-Type: application/json' -d '{"file":"findings-20261116-201500-选中.json"}'
```

## 本地模型配置（在页面上改，不用碰 YAML）

「AI」页第一块就是模型配置，现场换模型不用重启服务、也不用断掉已连的终端：

| 能做什么 | 说明 |
| --- | --- |
| 端点预设 | LM Studio `:1234` · Ollama `:11434` · vLLM `:8000` · llama.cpp `:8080`，点一下填好并顺手探测 |
| 拉取模型列表 | 问 `/v1/models` 要清单，直接填进**原生下拉框**，点开就能选；当前模型不在清单里会单独标注 |
| 手填 | 清单里没有的模型名（自建网关/改名后的模型）点「手填」直接写 |
| 测试连通 | 真发一条 `max_tokens=32` 的补全，回显耗时、tokens、回复原文；模型名不在清单里会单独警告 |
| 保存配置 | 行级写入 `config.yaml` 的 `ai` 段（注释保留），**运行时立即生效** |
| 折叠 | 面板右上角箭头可折叠，状态记在 localStorage，刷新/换页都保持；「靶机 → 接口配置」同样可折叠 |

几个刻意的设计：

- **`/models` 通了 ≠ 能用**：有的端点清单正常但模型名写错，所以「测试连通」一定要真跑一次补全；
- **思考型模型正文为空**：只吐 `reasoning_content` 时会被判成失败，并提示「调大 max_tokens」；
- **本地模型不走系统代理**：所有探测和请求都 `trust_env=False`，否则 Clash 一开就连不上 `127.0.0.1`；
- **写坏要有兜底**：写完立刻 `yaml.safe_load` 回读，任何一项对不上就整体放弃写入。

命令行等价：`./ops ai ask "..."`、`./ops ai health`，端点信息仍读同一份配置。

## 让 AI 写插件

```bash
./ops ai plugin "CVE-2021-41773 Apache 2.4.49 路径穿越，GET /cgi-bin/.%2e/.%2e/etc/passwd"
```

流程是**生成 → 静态校验 → 落草稿 → 人工确认启用**：
模型输出先写进 `ctfops/plugins/exploits/_drafts/`（加载器不扫描该目录），
校验只做 AST 检查（语法、必备变量、`exploit()` 是否存在），**不执行模型给的代码**；
确认后点「保存并启用」才移进正式目录，之后和手写插件完全一样可批量跑。

Web 端在「利用」页底部的「AI 写插件」面板；漏洞库每行也有「AI 插件」按钮，可直接带上下文生成。

## 写一个 PoC 插件

放 `ctfops/plugins/exploits/你的名字.py`，30 行即可：

```python
NAME = "my_poc"
DESCRIPTION = "某某系统 任意文件读取"
KIND = "web"            # web | ssh | local
SEVERITY = "high"

def check(ctx):          # 可选：先探活，避免无谓打击
    r = ctx.get(ctx.base + "/download?file=../../etc/passwd")
    return "root:x:0:0" in r.text

def exploit(ctx):
    r = ctx.get(ctx.base + "/download?file=../../flag")
    return {"ok": True, "evidence": r.text, "flags": []}   # flag 会自动正则提取
```

`ctx` 提供：`get/post`、`ssh()`、`run(cmd)`、`put(remote, content)`、`log(msg)`、`target`、`cfg`。

```bash
./ops exploit list
./ops exploit run my_poc -t all --check-only   # 先只看命中
./ops exploit run my_poc -t all
```

## 产物在哪

```
ctf-ops/
├── evidence/
│   ├── ops.db              # 全部动作/发现/flag/备份/截图
│   ├── shots/              # 步骤截图
│   ├── logs/<target>/      # 拉回的主机日志 + analysis.md
│   ├── snapshot/           # 现场快照
│   └── pcap/<name>/        # 导出的 HTTP 对象
├── ctfops/web/            # Web 控制台
│   ├── server.py          # 标准库 HTTP 服务，默认只绑 127.0.0.1
│   ├── api.py             # REST 接口（动作 → 任务队列）
│   ├── jobs.py            # 异步任务 + 增量日志
│   └── static/            # 前端：零依赖、零 CDN，断网可用
├── backups/                # 备份包（带 sha256）
├── outbox/                 # 待人工提交的 flag
└── report/                 # report.md / report.html / timeline.md
```

## 设计取舍

- **SQLite 落库而不是内存**：比赛中断电/重启，证据还在。
- **幂等**：flag 有唯一索引、备份带时间戳、插件可反复跑，不会重复计分或重复提交。
- **插件而非硬编码**：新漏洞 5 分钟加一个文件，不用改主程序。
- **改配置靠行级手术而非整体重写**：`yamledit` 只改目标那一行，保留注释、缩进和手写格式；写坏了会自动回滚。
- **AI 可选而非必需**：现场网络差、模型没起来，系统必须还能打。
- **限速与礼貌**：SSH 爆破带 sleep，nuclei 限 80 rps，提交带 interval——为了不被封。
- **前端零依赖**：比赛环境常断网，页面不引任何 CDN/npm 包，`python -m ctfops.cli dash` 即用。
- **WebSocket 自己写**：标准库没有 WS，又不愿为推送引 fastapi/websockets，于是手写握手与帧编解码（`ctfops/web/ws.py`，约 200 行），出问题也能一眼看懂。
- **终端用哨兵行定界**：常驻 shell 里靠 `printf 'MARK $?'` 判断一条命令结束，既能保留 `cd` 状态，又不会把下一条命令的输出串进来。
- **WAF 做旁路而不是反向代理**：把业务端口挪到代理后面，是 AWD 里最容易把服务搞挂的操作；访问日志已经含攻击源/方法/路径/UA，足够取证，且天然零风险。
- **控制台只绑本机**：默认 `127.0.0.1`，不对外暴露；产物走 `/artifact` 时做 workdir 越界校验，密码字段不进任何 API 响应。

## 已知限制

- `backup restore` 会覆盖远端 web 目录，必须显式 `--yes`。
- 截图依赖 `playwright`（`pip install playwright && playwright install chromium`），没装时退化为整屏截图/纯文字记录。
- 流量分析依赖 `tshark`；超大 pcap（>500MB）建议先 `editcap` 切分。
- 自动提交只适配 JSON/表单类接口；有验证码/签名的平台请用 manual 模式。
- Windows 靶机仅支持 SSH 可达的场景，未做 RDP/WinRM。
- 终端是**命令级交互**（输入一行、回车执行），不是全屏 TUI：`vim`、`top` 这类 curses 程序看不了，请用 `tail -n`、`ps aux` 之类的一次性命令。
- WebSocket 推送只在单进程内有效；多开实例时各看各的。
- WAF 只解析 **combined 格式**访问日志（nginx/apache 默认格式）；自定义 log_format 需自行调整 `LOG_RE`。
- WAF 的"加固"是**按源 IP 封禁**，不是应用层拦截；对手换 IP 就失效，适合打时间差抢分，不适合长期。
- 重放只还原 `METHOD + path + UA`（访问日志没有请求体），POST 型漏洞需手工补 body。
- AI 生成的插件只做静态校验，**不保证逻辑正确**；启用前请看一眼代码，别直接对着生产靶机跑。

## 环境适配提示

**工具被 Docker 包装器顶替**：如果 `nmap` / `nuclei` 实际是 OrbStack、Docker Desktop 的
wrapper（表现为 `failed to connect to the docker API`），`ops doctor` 会直接标红并说明原因。
此时 `scan ports` 会自动降级到内置纯 Python TCP 扫描（无需 root、无需 nmap），
`scan vulns` 会明确提示 nuclei 不可用，改用 `exploit` 插件手工验证。

修好真工具的方式：

```bash
brew install nmap
brew install nuclei        # 或 go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
open -a OrbStack           # 或者把 Docker 起起来
```

**代理干扰**：企业网络/Clash 常见 `HTTP_PROXY` 环境变量会让发往靶机的请求走代理而失败。
系统对靶机 HTTP、SSH、本地 AI 端点**默认直连（trust_env=False）**，
只有 FLAG 提交接口受 `submit.use_proxy` 控制（默认 False）。

## 自检

```bash
./.venv/bin/python tests/smoke.py            # 195 项离线断言，不碰真实靶机
./.venv/bin/python tests/flagserver_e2e.py  # 26 项：mock sshd + flag 服务 + 提交平台，跑通「经靶机取 flag」
./.venv/bin/python tests/config_api_e2e.py  # 50 项：页面配置写入/回读/非法值拦截、模型探测
./.venv/bin/python tests/ui_config_e2e.py   # 18 项：真浏览器点「保存配置」，回读 YAML 验证
./.venv/bin/python tests/ui_capture.py 8901 # 14 页截图 + 前端 console 错误检查
```
