package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vpspanel/internal/sshx"
	"vpspanel/internal/store"
	"vpspanel/internal/validate"
)

type probeReq struct {
	ServerID   uint   `json:"server_id"` // 编辑态传 id：未填新凭证时沿用已保存的凭证
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
	SSHUser    string `json:"ssh_user"`
	AuthType   string `json:"auth_type"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase"`
}

// probe 用于表单里的「测试连接」：不落库，直接试连并采集信息。
func (s *Server) probe(c *gin.Context) {
	var req probeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	host := strings.TrimSpace(req.Host)
	user := strings.TrimSpace(req.SSHUser)
	if user == "" {
		user = "root"
	}
	port := req.SSHPort
	if port == 0 {
		port = 22
	}
	if host == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "请先填写地址 / IP"})
		return
	}
	if err := validate.Host(host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": err.Error()})
		return
	}

	pwd, key, pass := req.Password, req.PrivateKey, req.Passphrase

	// 编辑态且没输入新凭证 → 取库里已保存的那份
	if pwd == "" && key == "" && req.ServerID > 0 {
		var stored store.Server
		if err := s.DB.First(&stored, req.ServerID).Error; err == nil {
			if sec, err := s.openSecret(stored); err == nil {
				pwd, key, pass = sec.Password, sec.PrivateKey, sec.Passphrase
			}
		}
	}
	if pwd == "" && key == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "error": "请先填写密码或私钥"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	creds := sshx.Credentials{
		User: user, Port: port,
		Password: pwd, PrivateKey: []byte(key), Passphrase: pass,
		Timeout: 8 * time.Second,
	}
	client, err := sshx.Dial(ctx, host, creds, s.HostKeys)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close()

	info, _ := sshx.Probe(ctx, client)
	c.JSON(http.StatusOK, gin.H{"ok": true, "info": info})
}
