-- VpsPanel schema v1 (SQLite)

CREATE TABLE IF NOT EXISTS servers (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    host            TEXT    NOT NULL,
    ssh_port        INTEGER NOT NULL DEFAULT 22,
    ssh_user        TEXT    NOT NULL DEFAULT 'root',
    auth_type       TEXT    NOT NULL DEFAULT 'password', -- password | key
    secret_cipher   BLOB,                                -- AES-256-GCM 密文
    tags            TEXT    DEFAULT '',
    provider        TEXT    DEFAULT '',
    region          TEXT    DEFAULT '',
    expires_at      DATETIME,
    status          TEXT    DEFAULT 'unknown',           -- unknown | online | offline | error
    last_check_at   DATETIME,
    os_info         TEXT    DEFAULT '',
    cpu_cores       INTEGER DEFAULT 0,
    mem_mb          INTEGER DEFAULT 0,
    disk_gb         INTEGER DEFAULT 0,
    note            TEXT    DEFAULT '',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_host_port ON servers(host, ssh_port);

CREATE TABLE IF NOT EXISTS templates (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    core        TEXT NOT NULL,     -- xray | sing-box
    protocol    TEXT NOT NULL,     -- vless-reality | hysteria2 | trojan ...
    config_tmpl TEXT NOT NULL,
    defaults    TEXT DEFAULT '{}',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS deployments (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id        INTEGER NOT NULL,
    template_id      INTEGER,
    protocol         TEXT NOT NULL,
    port             INTEGER NOT NULL,
    config_json      TEXT DEFAULT '',
    status           TEXT DEFAULT 'pending', -- pending|running|success|failed|rolledback
    version          INTEGER DEFAULT 1,
    prev_backup_path TEXT DEFAULT '',
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    finished_at      DATETIME,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    token      TEXT NOT NULL UNIQUE,
    filter     TEXT DEFAULT '{}',
    format     TEXT DEFAULT 'v2rayn', -- v2rayn | singbox
    enabled    INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS metrics (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id INTEGER NOT NULL,
    ts        DATETIME DEFAULT CURRENT_TIMESTAMP,
    cpu       REAL DEFAULT 0,
    mem       REAL DEFAULT 0,
    disk      REAL DEFAULT 0,
    net_in    INTEGER DEFAULT 0,
    net_out   INTEGER DEFAULT 0,
    uptime    INTEGER DEFAULT 0,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_metrics_server_ts ON metrics(server_id, ts);

CREATE TABLE IF NOT EXISTS traffic (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id  INTEGER NOT NULL,
    user_tag   TEXT DEFAULT '',
    up_bytes   INTEGER DEFAULT 0,
    down_bytes INTEGER DEFAULT 0,
    sampled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tasks (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    type      TEXT NOT NULL,
    target_id INTEGER,
    status    TEXT DEFAULT 'queued',
    progress  INTEGER DEFAULT 0,
    log_path  TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT DEFAULT 'admin',
    action     TEXT NOT NULL,
    target     TEXT DEFAULT '',
    payload    TEXT DEFAULT '',
    ip         TEXT DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 家宽 SOCKS5 等「非 VPS」落地节点（P2：LandingNode 的数据来源）
CREATE TABLE IF NOT EXISTS landing_nodes (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT NOT NULL,
    kind           TEXT NOT NULL DEFAULT 'home_socks5', -- server | home_socks5
    host           TEXT NOT NULL,
    port           INTEGER NOT NULL DEFAULT 1080,
    username       TEXT DEFAULT '',
    pass_cipher    BLOB,                                -- AES-256-GCM 密文
    expect_exit_ip TEXT DEFAULT '',
    status         TEXT DEFAULT 'unknown',              -- unknown | ok | fail
    last_test_at   DATETIME,
    last_error     TEXT DEFAULT '',
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_landing_host_port ON landing_nodes(host, port);
