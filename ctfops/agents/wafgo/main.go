// ctf-ops WAF agent (Go) —— 单文件静态二进制，不依赖目标机的任何运行时。
//
// 与 python 版行为一致：默认只监听访问日志，enforce 时按规则封禁源 IP。
// 文件：config.json / rules.json / audit.jsonl / status.json（均在同一目录）
// 信号：SIGHUP 热重载配置与规则
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Scope    string `json:"scope"`
	Pattern  string `json:"pattern"`
	Action   string `json:"action"`
	re       *regexp.Regexp
}

type Config struct {
	Mode    string   `json:"mode"`
	Autoban bool     `json:"autoban"`
	BanCmd  string   `json:"ban_cmd"`
	Logs    []string `json:"logs"`
}

type Status struct {
	Running  bool     `json:"running"`
	PID      int      `json:"pid"`
	Engine   string   `json:"engine"`
	Mode     string   `json:"mode"`
	Autoban  bool     `json:"autoban"`
	Started  int64    `json:"started"`
	Uptime   float64  `json:"uptime"`
	Requests int64    `json:"requests"`
	Matched  int64    `json:"matched"`
	Banned   int64    `json:"banned"`
	Logs     []string `json:"logs"`
	Rules    int      `json:"rules"`
}

type Audit struct {
	TS       int64  `json:"ts"`
	IP       string `json:"ip"`
	Method   string `json:"method"`
	Path     string `json:"path"`
	UA       string `json:"ua"`
	Status   int    `json:"status"`
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Matched  string `json:"matched"`
	Action   string `json:"action"`
	Engine   string `json:"engine"`
}

type tailer struct {
	path string
	f    *os.File
	r    *bufio.Reader
	info os.FileInfo
}

var (
	logRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) ([^"]*?)(?: [^"]*)?" (\d{3}) (\S+)(?: "[^"]*" "([^"]*)")?`)
	mu    sync.Mutex
)

func readJSON(path string, v interface{}) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return json.Unmarshal(data, v) == nil
}

func writeJSON(path string, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0644) == nil {
		os.Rename(tmp, path)
	}
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// urlDecode2 解码两层，覆盖 %252e%252e 这种双层编码
func urlDecode2(s string) string {
	for i := 0; i < 2; i++ {
		var b strings.Builder
		for j := 0; j < len(s); j++ {
			if s[j] == '%' && j+2 < len(s) {
				hi, ok1 := hexVal(s[j+1])
				lo, ok2 := hexVal(s[j+2])
				if ok1 && ok2 {
					b.WriteByte(hi<<4 | lo)
					j += 2
					continue
				}
			}
			b.WriteByte(s[j])
		}
		if b.String() == s {
			break
		}
		s = b.String()
	}
	return s
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

type Agent struct {
	home     string
	cfg      Config
	rules    []Rule
	tails    map[string]*tailer
	started  int64
	requests int64
	matched  int64
	banned   int64
	bans     map[string]bool
}

func (a *Agent) load() {
	a.cfg = Config{Mode: "monitor", BanCmd: "iptables -I INPUT -s {ip} -j DROP"}
	readJSON(filepath.Join(a.home, "config.json"), &a.cfg)
	if a.cfg.Mode == "" {
		a.cfg.Mode = "monitor"
	}

	var raw []Rule
	if readJSON(filepath.Join(a.home, "rules.json"), &raw) {
		a.rules = raw[:0]
		for _, r := range raw {
			if r.Pattern == "" {
				continue
			}
			re, err := regexp.Compile("(?i)" + r.Pattern)
			if err != nil {
				continue
			}
			r.re = re
			if r.Scope == "" {
				r.Scope = "any"
			}
			if r.Action == "" {
				r.Action = "monitor"
			}
			a.rules = append(a.rules, r)
		}
	}
	if a.bans == nil {
		a.bans = map[string]bool{}
	}
	data, err := os.ReadFile(filepath.Join(a.home, "bans.txt"))
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if line = strings.TrimSpace(line); line != "" {
				a.bans[line] = true
			}
		}
	}
}

func (a *Agent) status() Status {
	running := int64(time.Now().Unix()) - a.started
	return Status{
		Running: true, PID: os.Getpid(), Engine: "go", Mode: a.cfg.Mode,
		Autoban: a.cfg.Autoban, Started: a.started, Uptime: float64(running),
		Requests: a.requests, Matched: a.matched, Banned: a.banned,
		Logs: a.cfg.Logs, Rules: len(a.rules),
	}
}

func (a *Agent) ban(ip string) {
	if ip == "" || ip == "-" || ip == "127.0.0.1" || ip == "::1" || a.bans[ip] {
		return
	}
	cmd := strings.ReplaceAll(a.cfg.BanCmd, "{ip}", ip)
	if err := exec.Command("sh", "-c", cmd).Run(); err == nil {
		a.bans[ip] = true
		a.banned++
		if f, err := os.OpenFile(filepath.Join(a.home, "bans.txt"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			fmt.Fprintln(f, ip)
			f.Close()
		}
	}
}

func (a *Agent) handle(line string) {
	m := logRe.FindStringSubmatch(line)
	if m == nil {
		return
	}
	ip, method, path, ua, statusStr := m[1], m[3], m[4], m[7], m[5]
	a.requests++

	decoded := urlDecode2(path)
	for _, r := range a.rules {
		var hay string
		switch r.Scope {
		case "url":
			hay = decoded
		case "ua":
			hay = ua
		default:
			hay = decoded + " " + ua
		}
		loc := r.re.FindStringSubmatch(hay)
		if loc == nil {
			continue
		}
		block := a.cfg.Mode == "enforce" && r.Action == "block"
		rec := Audit{
			TS: time.Now().Unix(), IP: ip, Method: method,
			Path: cut(path, 1200), UA: cut(ua, 300), Status: 200,
			RuleID: r.ID, Name: r.Name, Severity: r.Severity,
			Matched: cut(loc[0], 200), Action: "monitor", Engine: "go",
		}
		if block {
			rec.Status = 403
			rec.Action = "block"
		}
		_ = statusStr
		a.matched++
		mu.Lock()
		if f, err := os.OpenFile(filepath.Join(a.home, "audit.jsonl"),
			os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			data, _ := json.Marshal(rec)
			f.Write(append(data, '\n'))
			f.Close()
		}
		mu.Unlock()
		if block && a.cfg.Autoban {
			a.ban(ip)
		}
		return
	}
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func (a *Agent) tail() {
	for _, path := range a.cfg.Logs {
		t := a.tails[path]
		if t == nil {
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			if _, err := f.Seek(0, io.SeekEnd); err != nil {
				f.Close()
				continue
			}
			info, _ := f.Stat()
			t = &tailer{path: path, f: f, r: bufio.NewReaderSize(f, 1<<20), info: info}
			a.tails[path] = t
		} else {
			// 轮转/截断：重开
			if info, err := os.Stat(path); err == nil {
				same := t.info != nil && os.SameFile(info, t.info)
				if !same || (t.info != nil && info.Size() < t.info.Size()) {
					t.f.Close()
					f, err := os.Open(path)
					if err != nil {
						delete(a.tails, path)
						continue
					}
					t.f = f
					t.r = bufio.NewReaderSize(f, 1<<20)
					t.info = info
				}
			}
		}
		for i := 0; i < 500; i++ {
			line, err := t.r.ReadString('\n')
			if line != "" {
				a.handle(strings.TrimRight(line, "\r\n"))
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				delete(a.tails, path)
				break
			}
		}
	}
}

func main() {
	home := flag.String("home", "/tmp/ctfops-waf", "工作目录")
	flag.Parse()

	a := &Agent{home: *home, tails: map[string]*tailer{}, started: time.Now().Unix()}
	a.load()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	reload := make(chan struct{}, 1)
	go func() {
		for s := range sig {
			if s == syscall.SIGHUP {
				select {
				case reload <- struct{}{}:
				default:
				}
			} else {
				os.Exit(0)
			}
		}
	}()

	lastStatus := time.Now().Unix()
	writeJSON(filepath.Join(*home, "status.json"), a.status())
	for {
		select {
		case <-reload:
			a.load()
			writeJSON(filepath.Join(*home, "status.json"), a.status())
		default:
		}
		a.tail()
		if now := time.Now().Unix(); now-lastStatus >= 2 {
			writeJSON(filepath.Join(*home, "status.json"), a.status())
			lastStatus = now
		}
		time.Sleep(400 * time.Millisecond)
	}
}
