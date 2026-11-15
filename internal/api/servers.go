package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vpspanel/internal/sshx"
	"vpspanel/internal/store"
	"vpspanel/internal/validate"
)

// serverView 是对外的服务器结构。
// 严格对应表格七列：name / host / username / status / os / specs / (操作)
// 所有字符串字段保证单行、无控制字符，前端可安全放进 <td>。
type serverView struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Status   string `json:"status"`
	OS       string `json:"os"`
	Specs    string `json:"specs"`

	// 兼容字段（旧前端/脚本可能还在用）
	SSHPort  int    `json:"ssh_port"`
	SSHUser  string `json:"ssh_user"`
	OSInfo   string `json:"os_info"`
	CPUCores int    `json:"cpu_cores"`
	MemMB    int    `json:"mem_mb"`
	DiskGB   int    `json:"disk_gb"`

	Tags        string `json:"tags"`
	Provider    string `json:"provider"`
	Region      string `json:"region"`
	Note        string `json:"note"`
	LastCheckAt string `json:"last_check_at"`
}

func viewOf(sv store.Server) serverView {
	// 历史数据里可能存了带换行/告警的 os_info，读出时再清洗一次
	osName := sshx.OSName(sv.OSInfo)
	if osName == "" {
		osName = sshx.Sanitize(sshx.Truncate(sv.OSInfo, 64))
	}
	specs := sshx.Specs(sv.CPUCores, sv.MemMB, sv.DiskGB)
	last := ""
	if sv.LastCheckAt != nil {
		last = sv.LastCheckAt.Format(time.RFC3339)
	}
	return serverView{
		ID: sv.ID, Name: sshx.Sanitize(sv.Name), Host: sshx.Sanitize(sv.Host),
		Port: sv.SSHPort, Username: sshx.Sanitize(sv.SSHUser),
		Status: sv.Status, OS: osName, Specs: specs,
		SSHPort: sv.SSHPort, SSHUser: sshx.Sanitize(sv.SSHUser), OSInfo: osName,
		CPUCores: sv.CPUCores, MemMB: sv.MemMB, DiskGB: sv.DiskGB,
		Tags: sshx.Sanitize(sv.Tags), Provider: sshx.Sanitize(sv.Provider),
		Region: sshx.Sanitize(sv.Region), Note: sshx.Sanitize(sv.Note),
		LastCheckAt: last,
	}
}

type serverReq struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	SSHPort    int    `json:"ssh_port"`
	SSHUser    string `json:"ssh_user"`
	AuthType   string `json:"auth_type"`
	Password   string `json:"password"`
	PrivateKey string `json:"private_key"`
	Passphrase string `json:"passphrase"`
	Tags       string `json:"tags"`
	Provider   string `json:"provider"`
	Region     string `json:"region"`
	Note       string `json:"note"`
}

// secretPayload 是加密后落库的明文结构。
type secretPayload struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

func (s *Server) sealSecret(req serverReq) (string, error) {
	p := secretPayload{Password: req.Password, PrivateKey: req.PrivateKey, Passphrase: req.Passphrase}
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return s.Box.Seal(raw)
}

func (s *Server) openSecret(srv store.Server) (secretPayload, error) {
	var p secretPayload
	if len(srv.SecretCipher) == 0 {
		return p, nil
	}
	raw, err := s.Box.Open(string(srv.SecretCipher))
	if err != nil {
		return p, err
	}
	err = json.Unmarshal(raw, &p)
	return p, err
}

func normalize(req *serverReq) {
	req.Name = strings.TrimSpace(req.Name)
	req.Host = strings.TrimSpace(req.Host)
	req.SSHUser = strings.TrimSpace(req.SSHUser)
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}
	if req.SSHUser == "" {
		req.SSHUser = "root"
	}
	if req.AuthType != "key" {
		req.AuthType = "password"
	}
}

func (s *Server) createServer(c *gin.Context) {
	var req serverReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}
	normalize(&req)
	if req.Host == "" || req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "名称和地址必填"})
		return
	}
	if err := validate.Host(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.AuthType == "key" && req.PrivateKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "私钥不能为空"})
		return
	}
	if req.AuthType == "password" && req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "密码不能为空"})
		return
	}

	cipherText, err := s.sealSecret(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "加密凭证失败"})
		return
	}

	srv := store.Server{
		Name: req.Name, Host: req.Host, SSHPort: req.SSHPort, SSHUser: req.SSHUser,
		AuthType: req.AuthType, SecretCipher: []byte(cipherText),
		Tags: req.Tags, Provider: req.Provider, Region: req.Region,
		Status: "unknown", Note: req.Note,
	}
	if err := s.DB.Create(&srv).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "该地址+端口已存在"})
		return
	}
	s.audit("server.create", srv.Host, req.Name)
	c.JSON(http.StatusOK, srv)
}

func (s *Server) updateServer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var srv store.Server
	if err := s.DB.First(&srv, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "服务器不存在"})
		return
	}
	var req serverReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}
	normalize(&req)
	if err := validate.Host(req.Host); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// P1：从密码切换到私钥（或反之）但不提供新凭证时，旧密文与新 auth_type 不匹配
	if req.AuthType != srv.AuthType && req.Password == "" && req.PrivateKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "切换认证方式时必须重新填写密码或私钥"})
		return
	}

	srv.Name = req.Name
	srv.Host = req.Host
	srv.SSHPort = req.SSHPort
	srv.SSHUser = req.SSHUser
	srv.AuthType = req.AuthType
	srv.Tags = req.Tags
	srv.Provider = req.Provider
	srv.Region = req.Region
	srv.Note = req.Note

	// 只有填了新的密码/私钥才覆盖，留空表示沿用旧凭证
	if req.Password != "" || req.PrivateKey != "" {
		cipherText, err := s.sealSecret(req)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "加密凭证失败"})
			return
		}
		srv.SecretCipher = []byte(cipherText)
	}

	if err := s.DB.Save(&srv).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit("server.update", srv.Host, srv.Name)
	c.JSON(http.StatusOK, srv)
}

func (s *Server) deleteServer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var srv store.Server
	if err := s.DB.First(&srv, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "服务器不存在"})
		return
	}
	if err := s.DB.Delete(&store.Server{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	s.audit("server.delete", srv.Host, srv.Name)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// testServer 建立 SSH 连接并采集系统信息，同时刷新 status/os_info 等字段。
func (s *Server) testServer(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var srv store.Server
	if err := s.DB.First(&srv, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "服务器不存在"})
		return
	}

	sec, err := s.openSecret(srv)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解密凭证失败"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 20*time.Second)
	defer cancel()

	creds := sshx.Credentials{
		User: srv.SSHUser, Port: srv.SSHPort,
		Password: sec.Password, PrivateKey: []byte(sec.PrivateKey), Passphrase: sec.Passphrase,
		Timeout: 8 * time.Second,
	}

	now := time.Now()
	client, err := sshx.Dial(ctx, srv.Host, creds, s.HostKeys)
	if err != nil {
		srv.Status = "offline"
		srv.LastCheckAt = &now
		s.DB.Save(&srv)
		c.JSON(http.StatusOK, gin.H{"ok": false, "status": "offline",
			"error": sshx.Sanitize(err.Error()), "server": viewOf(srv)})
		return
	}
	defer client.Close()

	info, probeErr := sshx.Probe(ctx, client)
	srv.Status = "online"
	srv.LastCheckAt = &now
	if probeErr == nil {
		// 只写入清洗后的单行值，绝不把 MOTD/换行写进 os_info
		srv.OSInfo = sshx.Sanitize(sshx.Truncate(info.OS, 64))
		srv.CPUCores = info.Cores
		srv.MemMB = info.MemMB
		srv.DiskGB = info.DiskGB
	}
	s.DB.Save(&srv)
	s.audit("server.test", srv.Host, "ok")

	resp := gin.H{"ok": true, "status": "online", "info": info, "server": viewOf(srv)}
	if probeErr != nil {
		resp["warning"] = "已连接，但系统信息采集不完整: " + probeErr.Error()
	}
	c.JSON(http.StatusOK, resp)
}
