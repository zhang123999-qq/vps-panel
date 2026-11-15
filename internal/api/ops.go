package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	"vpspanel/internal/chain"
	"vpspanel/internal/kernel"
	"vpspanel/internal/landing"
	"vpspanel/internal/provision"
	"vpspanel/internal/socks5probe"
	"vpspanel/internal/sshx"
	"vpspanel/internal/store"
	"vpspanel/internal/validate"
)

// dialServer 按 id 取服务器并建立 SSH 连接（调用方负责 Close）。
func (s *Server) dialServer(ctx context.Context, id uint, timeout time.Duration) (*ssh.Client, store.Server, error) {
	var srv store.Server
	if err := s.DB.First(&srv, id).Error; err != nil {
		return nil, srv, fmt.Errorf("服务器 #%d 不存在", id)
	}
	sec, err := s.openSecret(srv)
	if err != nil {
		return nil, srv, fmt.Errorf("解密凭证失败")
	}
	client, err := sshx.Dial(ctx, srv.Host, sshx.Credentials{
		User: srv.SSHUser, Port: srv.SSHPort,
		Password: sec.Password, PrivateKey: []byte(sec.PrivateKey), Passphrase: sec.Passphrase,
		Timeout: 10 * time.Second,
	}, s.HostKeys)
	if err != nil {
		return nil, srv, fmt.Errorf("%s SSH 连接失败: %w", srv.Name, err)
	}
	return client, srv, nil
}

// ── 内核：版本总览 / 远端升级（对应需求 1B）────────────────────

type kernelRow struct {
	ServerID   uint   `json:"server_id"`
	ServerName string `json:"server_name"`
	Host       string `json:"host"`
	Xray       string `json:"xray"`
	Singbox    string `json:"singbox"`
	XrayDiff   bool   `json:"xray_diff"`
	SboxDiff   bool   `json:"singbox_diff"`
	Error      string `json:"error,omitempty"`
}

// kernelsOverview 列出版本差异：内嵌版本 vs 各远端当前版本。
func (s *Server) kernelsOverview(c *gin.Context) {
	var list []store.Server
	s.DB.Order("id").Find(&list)

	rows := make([]kernelRow, 0, len(list))
	for _, srv := range list {
		row := kernelRow{ServerID: srv.ID, ServerName: srv.Name, Host: srv.Host}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 25*time.Second)
		client, _, err := s.dialServer(ctx, srv.ID, 8*time.Second)
		if err != nil {
			row.Error = "连接失败"
			cancel()
			rows = append(rows, row)
			continue
		}
		x, b := kernel.Status(ctx, client)
		client.Close()
		cancel()
		row.Xray, row.Singbox = x, b
		row.XrayDiff = x != kernel.XrayVersion
		row.SboxDiff = b != kernel.SingboxVersion
		rows = append(rows, row)
	}
	c.JSON(http.StatusOK, gin.H{
		"builtin": kernel.Builtin(),
		"items":   rows,
	})
}

type kernelUpdateReq struct {
	ServerIDs []uint `json:"server_ids"`
	Target    string `json:"target"` // xray | singbox | all
}

type kernelOut struct {
	ServerID   uint     `json:"server_id"`
	ServerName string   `json:"server_name"`
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	XrayOld    string   `json:"xray_old"`
	XrayNew    string   `json:"xray_new"`
	SboxOld    string   `json:"sbox_old"`
	SboxNew    string   `json:"sbox_new"`
	Restarted  int      `json:"restarted"`
	Logs       []string `json:"logs"`
}

// kernelUpdate 推送内嵌内核到远端（1B）。与「内嵌内核升级(1A)」是两个不同入口。
func (s *Server) kernelUpdate(c *gin.Context) {
	var req kernelUpdateReq
	if err := c.ShouldBindJSON(&req); err != nil || len(req.ServerIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择服务器"})
		return
	}
	if req.Target == "" {
		req.Target = "all"
	}
	if req.Target != "xray" && req.Target != "singbox" && req.Target != "all" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target 只能是 xray / singbox / all"})
		return
	}

	outs := make([]kernelOut, 0, len(req.ServerIDs))
	for _, id := range req.ServerIDs {
		outs = append(outs, s.kernelUpdateOne(id, req.Target))
	}
	c.JSON(http.StatusOK, gin.H{"results": outs})
}

func (s *Server) kernelUpdateOne(id uint, target string) kernelOut {
	out := kernelOut{ServerID: id}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// P1：内核替换是「备份→安装→自检→回滚」的临界区，必须串行
	unlock := s.lockPlan(id, 0)
	defer unlock()

	client, srv, err := s.dialServer(ctx, id, 10*time.Second)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	defer client.Close()
	out.ServerName = srv.Name

	logf := func(m string) { out.Logs = append(out.Logs, m) }

	if target == "xray" || target == "all" {
		old, now, err := kernel.EnsureXray(ctx, client, logf)
		if err != nil {
			out.Error = "xray 更新失败: " + err.Error()
			return out
		}
		out.XrayOld, out.XrayNew = old, now
	}
	if target == "singbox" || target == "all" {
		old, now, err := kernel.EnsureSingbox(ctx, client, logf)
		if err != nil {
			out.Error = "sing-box 更新失败: " + err.Error()
			if out.XrayNew == "" {
				return out
			}
		} else {
			out.SboxOld, out.SboxNew = old, now
		}
	}

	n, _ := kernel.RestartAll(ctx, client, logf)
	out.Restarted = n
	out.OK = out.Error == ""
	s.audit("kernel.push", srv.Host, fmt.Sprintf("target=%s xray=%s singbox=%s", target, out.XrayNew, out.SboxNew))
	return out
}

// ── 落地节点（家宽 SOCKS5）：LandingNode 数据源 ────────────────

type landingReq struct {
	Name         string `json:"name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	ExpectExitIP string `json:"expect_exit_ip"`
}

// landingOptions 合并展示两类落地（VPS + 家宽），供「落地选择」直接用。
func (s *Server) landingOptions(c *gin.Context) {
	var servers []store.Server
	s.DB.Order("id").Find(&servers)
	var homs []store.LandingNode
	s.DB.Order("id").Find(&homs)

	items := make([]gin.H, 0, len(servers)+len(homs))
	for _, sv := range servers {
		items = append(items, gin.H{
			"kind": "server", "id": sv.ID, "name": sv.Name,
			"detail": fmt.Sprintf("%s · 落地端口在链路里指定", sv.Host),
			"status": sv.Status,
		})
	}
	for _, h := range homs {
		items = append(items, gin.H{
			"kind": "home_socks5", "id": h.ID, "name": h.Name,
			"detail":     fmt.Sprintf("%s:%d", h.Host, h.Port),
			"status":     h.Status,
			"expect_ip":  h.ExpectExitIP,
			"last_error": h.LastError,
		})
	}
	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (s *Server) landingList(c *gin.Context) {
	var list []store.LandingNode
	s.DB.Order("id desc").Find(&list)
	c.JSON(http.StatusOK, gin.H{"items": list})
}

func (s *Server) landingCreate(c *gin.Context) {
	var req landingReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}
	if req.Host == "" || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名称和地址必填"})
		return
	}
	// P0：host 会被用于 SOCKS5 出站与远端探测，必须严格校验（防命令注入）
	if err := validate.Host(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Port == 0 {
		req.Port = 1080
	}
	if err := validate.Port(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ExpectExitIP != "" {
		if err := validate.Host(req.ExpectExitIP); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "预期出口 IP 格式不合法"})
			return
		}
	}
	node := store.LandingNode{
		Name: req.Name, Kind: "home_socks5", Host: req.Host, Port: req.Port,
		Username: req.Username, ExpectExitIP: req.ExpectExitIP, Status: "unknown",
	}
	if req.Password != "" {
		ct, err := s.Box.Seal([]byte(req.Password))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "加密失败"})
			return
		}
		node.PassCipher = []byte(ct)
	}
	if err := s.DB.Create(&node).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "该地址+端口已存在"})
		return
	}
	s.audit("landing.create", fmt.Sprintf("%s:%d", req.Host, req.Port), req.Name)
	c.JSON(http.StatusOK, node)
}

func (s *Server) landingUpdate(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node store.LandingNode
	if err := s.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	var req landingReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}
	if req.Port == 0 {
		req.Port = node.Port
	}
	if err := validate.Host(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validate.Port(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	node.Name, node.Host, node.Port = req.Name, req.Host, req.Port
	node.Username, node.ExpectExitIP = req.Username, req.ExpectExitIP
	if req.Password != "" {
		ct, err := s.Box.Seal([]byte(req.Password))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "加密失败"})
			return
		}
		node.PassCipher = []byte(ct)
	}
	if err := s.DB.Save(&node).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit("landing.update", fmt.Sprintf("%s:%d", req.Host, req.Port), req.Name)
	c.JSON(http.StatusOK, node)
}

func (s *Server) landingDelete(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node store.LandingNode
	if err := s.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	s.DB.Delete(&store.LandingNode{}, id)
	s.audit("landing.delete", fmt.Sprintf("%s:%d", node.Host, node.Port), node.Name)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// landingTest 测试家宽 SOCKS5：TCP → 握手 → 认证 → CONNECT → 出口 IP 比对。
func (s *Server) landingTest(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var node store.LandingNode
	if err := s.DB.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	pass, err := s.landingPass(node)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "解密家宽口令失败（master.key 可能已更换）"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 40*time.Second)
	defer cancel()

	pr := socks5probe.Probe(ctx, node.Host, node.Port, node.Username, pass)
	now := time.Now()
	node.LastTestAt = &now
	node.Status = "fail"
	node.LastError = ""
	if pr != nil && pr.Reachable && pr.Handshake && pr.AuthOK && pr.ConnectOK {
		if node.ExpectExitIP != "" && pr.ExitIP != "" && !strings.Contains(pr.ExitIP, node.ExpectExitIP) {
			node.LastError = fmt.Sprintf("出口 IP 不符：期望 %s，实际 %s", node.ExpectExitIP, pr.ExitIP)
		} else {
			node.Status = "ok"
		}
	} else if pr != nil {
		node.LastError = pr.Error
	}
	s.DB.Save(&node)
	s.audit("landing.test", fmt.Sprintf("%s:%d", node.Host, node.Port), node.Status)

	c.JSON(http.StatusOK, gin.H{"ok": node.Status == "ok", "result": pr, "node": node})
}

func (s *Server) landingPass(node store.LandingNode) (string, error) {
	if len(node.PassCipher) == 0 {
		return "", nil
	}
	raw, err := s.Box.Open(string(node.PassCipher))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ── 链路：前置 + 落地（统一入口，需求 3）──────────────────────

type chainReq struct {
	RelayID     uint   `json:"relay_id"`
	LandingKind string `json:"landing_kind"` // server | home_socks5
	LandingID   uint   `json:"landing_id"`
	RelayPort   int    `json:"relay_port"`
	LandingPort int    `json:"landing_port"` // 仅 kind=server 时使用
	LinkProto   string `json:"link_proto"`   // 仅 kind=server：vless-reality | vmess-ws
	Dest        string `json:"dest"`
	SNI         string `json:"sni"`
	Tag         string `json:"tag"`
}

func (s *Server) chainDeploy(c *gin.Context) {
	var req chainReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}
	if req.RelayID == 0 || req.LandingID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择前置与落地"})
		return
	}
	if req.LandingKind == "" {
		req.LandingKind = "server"
	}
	if req.RelayPort == 0 {
		req.RelayPort = provision.DefaultPort
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Minute)
	defer cancel()

	relay, relaySrv, err := s.dialServer(ctx, req.RelayID, 10*time.Second)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer relay.Close()

	// 组装统一落地抽象
	var node *landing.Node
	var landingClient *ssh.Client
	switch req.LandingKind {
	case "server":
		if req.LandingID == req.RelayID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "前置与落地不能是同一台服务器"})
			return
		}
		if req.LandingPort == 0 {
			req.LandingPort = 8443
		}
		lc, lsrv, err := s.dialServer(ctx, req.LandingID, 10*time.Second)
		if err != nil {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
			return
		}
		defer lc.Close()
		landingClient = lc
		node = &landing.Node{
			Kind: landing.KindServer, ID: lsrv.ID, Name: lsrv.Name,
			Host: lsrv.Host, Port: req.LandingPort,
			Protocol: req.LinkProto,
		}
		if node.Protocol == "" {
			node.Protocol = "vless-reality"
		}
	case "home_socks5":
		var h store.LandingNode
		if err := s.DB.First(&h, req.LandingID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"ok": false, "error": "家宽节点不存在"})
			return
		}
		pass, err := s.landingPass(h)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"ok": false, "error": "解密家宽口令失败"})
			return
		}
		if h.Status != "ok" {
			c.JSON(http.StatusOK, gin.H{"ok": false, "error": "该家宽节点尚未通过测试，请先点「测试」"})
			return
		}
		node = &landing.Node{
			Kind: landing.KindHomeSocks5, ID: h.ID, Name: h.Name,
			SocksHost: h.Host, SocksPort: h.Port, SocksUser: h.Username, SocksPass: pass,
			ExpectExitIP: h.ExpectExitIP,
		}
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "未知落地类型"})
		return
	}

	// P1：与单协议部署共用同一把锁，防止并发写同一台机器的同一端口
	unlockRelay := s.lockPlan(req.RelayID, req.RelayPort)
	defer unlockRelay()
	if req.LandingKind == "server" && req.LandingPort > 0 {
		unlockLanding := s.lockPlan(req.LandingID, req.LandingPort)
		defer unlockLanding()
	}

	var logs []string
	res, err := chain.Deploy(ctx, relay, relaySrv.Host, node, landingClient, chain.Params{
		RelayPort: req.RelayPort, Dest: req.Dest, SNI: req.SNI, Tag: req.Tag,
	}, func(m string) { logs = append(logs, m) })
	if err != nil {
		s.DB.Create(&store.Deployment{
			ServerID: req.RelayID, Protocol: "chain", Port: req.RelayPort,
			Status: "failed", ConfigJSON: mustJSON(map[string]any{"error": err.Error(), "logs": logs}),
		})
		s.pruneFailures(req.RelayID)
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error(), "logs": logs})
		return
	}

	s.DB.Where("server_id = ? AND port = ? AND protocol = ? AND status = ?", req.RelayID, req.RelayPort, "chain", "success").
		Delete(&store.Deployment{})
	rec := store.Deployment{
		ServerID: req.RelayID, Protocol: "chain", Port: req.RelayPort, Status: "success",
		ConfigJSON: mustJSON(map[string]any{
			"link": res.Link, "meta": res.Meta,
			"spec": map[string]any{
				"tag": req.Tag, "relay_port": req.RelayPort,
				"landing_kind": req.LandingKind, "landing_id": req.LandingID,
				"exit_ip": res.ExitIP,
			},
		}),
	}
	s.DB.Create(&rec)
	s.audit("chain.deploy", relaySrv.Host, fmt.Sprintf("%s→%s port=%d", relaySrv.Host, node.Label(), req.RelayPort))

	c.JSON(http.StatusOK, gin.H{"ok": true, "link": res.Link, "meta": res.Meta, "exit_ip": res.ExitIP, "logs": logs})
}
