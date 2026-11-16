<?php
/**
 * watchbird.php —— ctf-ops 的 PHP WAF 传感器
 *
 * 由 auto_prepend_file 在每个请求前执行：
 *   - monitor 模式：只记录，不改变任何响应
 *   - enforce 模式：命中 block 规则时返回 403 并终止
 *
 * 配置：/tmp/ctfops-waf/watchbird.json（rules 与 python 版同格式）
 * 审计：/tmp/ctfops-waf/audit.jsonl（与 python 版同一份，统一取证）
 *
 * 原则：任何异常都不能影响业务，全程 @ 抑制 + 尽早 return。
 */
if (PHP_SAPI === 'cli') {
    return;
}
if (basename(isset($_SERVER['SCRIPT_FILENAME']) ? $_SERVER['SCRIPT_FILENAME'] : '') === 'watchbird.php') {
    return;
}

$WB_DIR = '/tmp/ctfops-waf';
$WB_CFG = $WB_DIR . '/watchbird.json';
if (!@is_file($WB_CFG)) {
    return;
}

$wb_cfg = @json_decode(@file_get_contents($WB_CFG), true);
if (!is_array($wb_cfg)) {
    return;
}

$rules = isset($wb_cfg['rules']) && is_array($wb_cfg['rules']) ? $wb_cfg['rules'] : array();
$mode = isset($wb_cfg['mode']) ? $wb_cfg['mode'] : 'monitor';
$ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '-';
$uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
$ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';

/* IP 黑名单：不需要 root、不需要防火墙，直接在请求内拒绝。
   由主控通过 SSH 往 bans.txt 追加（目录 777），比 iptables 更适合普通权限的站。 */
$wb_bans_file = $WB_DIR . '/bans.txt';
if (@is_file($wb_bans_file)) {
    $wb_bans = @file($wb_bans_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (is_array($wb_bans) && in_array($ip, $wb_bans, true)) {
        @file_put_contents($WB_DIR . '/audit.jsonl',
            json_encode(array('ts' => time(), 'ip' => $ip, 'method' => $method,
                              'path' => substr($uri, 0, 1200), 'ua' => substr($ua, 0, 300),
                              'status' => 403, 'rule_id' => 'ip-ban',
                              'name' => 'IP 黑名单', 'severity' => 'high',
                              'matched' => $ip, 'action' => 'block'),
                JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "banned\n";
        exit;
    }
}

/* 部署自检：仅本机可触发，用来确认 auto_prepend 真的生效 */
if (isset($_GET['__wb_probe']) && ($ip === '127.0.0.1' || $ip === '::1')) {
    header('X-Watchbird: ok');
    echo 'WB_OK';
    exit;
}

/* URL 解码两次，覆盖 %252e%252e 这类双层编码 */
$decoded = rawurldecode($uri);
for ($i = 0; $i < 2; $i++) {
    $again = rawurldecode($decoded);
    if ($again === $decoded) {
        break;
    }
    $decoded = $again;
}

foreach ($rules as $r) {
    if (empty($r['pattern'])) {
        continue;
    }
    $scope = isset($r['scope']) ? $r['scope'] : 'any';
    if ($scope === 'url') {
        $hay = $decoded;
    } elseif ($scope === 'ua') {
        $hay = $ua;
    } else {
        $hay = $decoded . ' ' . $ua;
    }

    $pattern = '~' . str_replace('~', '\~', $r['pattern']) . '~i';
    $hit = @preg_match($pattern, $hay, $m);
    if (!$hit) {
        continue;
    }

    $isBlock = ($mode === 'enforce')
        && ((isset($r['action']) ? $r['action'] : 'monitor') === 'block');

    $rec = array(
        'ts' => time(),
        'ip' => $ip,
        'method' => $method,
        'path' => substr($uri, 0, 1200),
        'ua' => substr($ua, 0, 300),
        'status' => $isBlock ? 403 : 200,
        'rule_id' => isset($r['id']) ? $r['id'] : '',
        'name' => isset($r['name']) ? $r['name'] : '',
        'severity' => isset($r['severity']) ? $r['severity'] : 'medium',
        'matched' => substr($m[0], 0, 200),
        'action' => $isBlock ? 'block' : 'monitor',
        'engine' => 'php',
    );
    @file_put_contents(
        $WB_DIR . '/audit.jsonl',
        json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX
    );

    /* 状态只在命中时更新，避免每个请求都写盘 */
    $st = array(
        'engine' => 'php',
        'mode' => $mode,
        'matched' => 0,
        'blocked' => 0,
        'requests' => 0,
        'started' => isset($wb_cfg['started']) ? $wb_cfg['started'] : time(),
        'rules' => count($rules),
        'last_ts' => time(),
        'webroot' => isset($wb_cfg['webroot']) ? $wb_cfg['webroot'] : '',
    );
    $old = @file_get_contents($WB_DIR . '/php_status.json');
    if ($old) {
        $o = @json_decode($old, true);
        if (is_array($o)) {
            $st['matched'] = isset($o['matched']) ? (int) $o['matched'] : 0;
            $st['blocked'] = isset($o['blocked']) ? (int) $o['blocked'] : 0;
            $st['started'] = isset($o['started']) ? $o['started'] : $st['started'];
        }
    }
    $st['matched']++;
    if ($isBlock) {
        $st['blocked']++;
    }
    @file_put_contents($WB_DIR . '/php_status.json', json_encode($st, JSON_UNESCAPED_UNICODE), LOCK_EX);

    if ($isBlock) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        echo "blocked by watchbird\n";
        exit;
    }
    break;
}
