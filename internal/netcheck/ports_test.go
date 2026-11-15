package netcheck

import "testing"

// 真实报错现场：ss 的 stdout 里混入了 SSH 登录告警（历史上被 grep 当成了「占用」）
const polluted = "Could not chdir to home directory /home/next: No such file or directory x86_64\n"

const ssOutput = `LISTEN 0      4096         0.0.0.0:22           0.0.0.0:*
LISTEN 0      4096            [::]:22              [::]:*
LISTEN 0      4096         0.0.0.0:443          0.0.0.0:*
LISTEN 0      4096         0.0.0.0:44398        0.0.0.0:*
LISTEN 0      4096      127.0.0.1:18080        0.0.0.0:*
`

const netstatOutput = `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp6       0      0 :::443                  :::*                    LISTEN
tcp        0      0 0.0.0.0:44398           0.0.0.0:*               LISTEN
`

const lsofOutput = `COMMAND  PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
sshd     812 root    3u  IPv4  20001      0t0  TCP *:22 (LISTEN)
xray    1024 root    4u  IPv6  20002      0t0  TCP *:44398 (LISTEN)
`

func TestParseListeningSS(t *testing.T) {
	m := ParseListening(ssOutput)
	for _, p := range []int{22, 443, 44398, 18080} {
		if _, ok := m[p]; !ok {
			t.Errorf("ss 输出应包含端口 %d，实际 %v", p, m)
		}
	}
	if len(m) != 4 {
		t.Errorf("应解析出 4 个端口，实际 %d: %v", len(m), m)
	}
}

func TestParseListeningNetstat(t *testing.T) {
	m := ParseListening(netstatOutput)
	for _, p := range []int{22, 443, 44398} {
		if _, ok := m[p]; !ok {
			t.Errorf("netstat 输出应包含端口 %d，实际 %v", p, m)
		}
	}
}

func TestParseListeningLsof(t *testing.T) {
	m := ParseListening(lsofOutput)
	if _, ok := m[44398]; !ok {
		t.Errorf("lsof 输出应包含 44398，实际 %v", m)
	}
}

// 关键回归：被 stderr 污染的输出绝不能解析出任何端口（否则会误报占用）
func TestPollutedOutputHasNoPorts(t *testing.T) {
	if m := ParseListening(polluted); len(m) != 0 {
		t.Fatalf("污染输出不应解析出端口，实际 %v", m)
	}
	// 混在一起的极端情况：告警 + 真实监听行
	m := ParseListening(polluted + ssOutput)
	if _, ok := m[44398]; !ok {
		t.Fatalf("混合输出仍应解析出真实端口")
	}
}

// 严格匹配：:443 不能被当成 :44398
func TestExactPortMatch(t *testing.T) {
	m := ParseListening("LISTEN 0 4096 0.0.0.0:44398 0.0.0.0:*\n")
	if _, ok := m[4439]; ok {
		t.Fatalf("不应把 44398 误判为 4439")
	}
	if _, ok := m[443]; ok {
		t.Fatalf("不应把 44398 误判为 443")
	}
	if _, ok := m[44398]; !ok {
		t.Fatalf("44398 应被识别")
	}
}
