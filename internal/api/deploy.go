package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"vpspanel/internal/provision"
	"vpspanel/internal/sshx"
	"vpspanel/internal/store"
	"vpspanel/internal/validate"
)

type deployReq struct {
	ServerIDs []uint `json:"server_ids"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Tag       string `json:"tag"`
	Network   string `json:"network"`
	Dest      string `json:"dest"`
	SNI       string `json:"sni"`
	Method    string `json:"method"`
}

type deployOut struct {
	ServerID   uint     `json:"server_id"`
	ServerName string   `json:"server_name"`
	OK         bool     `json:"ok"`
	Error      string   `json:"error,omitempty"`
	Link       string   `json:"link,omitempty"`
	Logs       []string `json:"logs"`
	DeployID   uint     `json:"deploy_id,omitempty"`
}

// deploy 对选中的服务器逐个执行部署。串行执行，避免同时打满多条 SSH 会话。
func (s *Server) deploy(c *gin.Context) {
	var req deployReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}
	if len(req.ServerIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请至少选择一台服务器"})
		return
	}
	if req.Port == 0 {
		req.Port = provision.DefaultPort // 默认 443
	}
	if err := validate.Port(req.Port); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择协议"})
		return
	}
	// 提前白名单校验，避免把未知协议带进渲染/落盘流程
	if err := validate.Protocol(req.Protocol); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	outs := make([]deployOut, 0, len(req.ServerIDs))
	for _, id := range req.ServerIDs {
		o := s.deployOne(c.Request.Context(), id, req)
		outs = append(outs, o)
	}
	c.JSON(http.StatusOK, gin.H{"results": outs})
}

func (s *Server) deployOne(ctx context.Context, id uint, req deployReq) deployOut {
	out := deployOut{ServerID: id}
	unlock := s.lockPlan(id, req.Port)
	defer unlock()

	var srv store.Server
	if err := s.DB.First(&srv, id).Error; err != nil {
		out.Error = "服务器不存在"
		return out
	}
	out.ServerName = srv.Name

	sec, err := s.openSecret(srv)
	if err != nil {
		out.Error = "解密凭证失败"
		return out
	}

	dctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	client, err := sshx.Dial(dctx, srv.Host, sshx.Credentials{
		User: srv.SSHUser, Port: srv.SSHPort,
		Password: sec.Password, PrivateKey: []byte(sec.PrivateKey), Passphrase: sec.Passphrase,
		Timeout: 10 * time.Second,
	}, s.HostKeys)
	if err != nil {
		out.Error = "SSH 连接失败: " + err.Error()
		return out
	}
	defer client.Close()

	spec := &provision.Spec{
		Protocol: req.Protocol, Port: req.Port, Tag: req.Tag,
		Network: req.Network, Dest: req.Dest, SNI: req.SNI, Method: req.Method,
	}
	if spec.Tag == "" {
		spec.Tag = fmt.Sprintf("%s-%s", srv.Name, req.Protocol)
	}

	var logs []string
	res, err := provision.Deploy(dctx, client, srv.Host, spec, func(msg string) {
		logs = append(logs, msg)
	})
	out.Logs = logs
	if err != nil {
		out.Error = err.Error()
		// 失败也落一条记录，方便排查
		s.DB.Create(&store.Deployment{
			ServerID: id, Protocol: req.Protocol, Port: req.Port,
			Status: "failed", ConfigJSON: mustJSON(map[string]any{"error": err.Error(), "logs": logs}),
		})
		s.pruneFailures(id)
		return out
	}

	payload := map[string]any{
		"link": res.Link,
		"meta": res.Meta,
		"spec": spec,
	}
	// 幂等：同服务器同端口同协议只保留最新一条成功记录
	s.DB.Where("server_id = ? AND port = ? AND protocol = ? AND status = ?", id, req.Port, req.Protocol, "success").
		Delete(&store.Deployment{})

	rec := store.Deployment{
		ServerID: id, Protocol: req.Protocol, Port: req.Port,
		Status: "success", ConfigJSON: mustJSON(payload),
	}
	s.DB.Create(&rec)

	s.pruneFailures(id)

	out.OK = true
	out.Link = res.Link
	out.DeployID = rec.ID
	s.audit("deploy."+req.Protocol, srv.Host, fmt.Sprintf("port=%d ok", req.Port))
	return out
}

type nodeView struct {
	ID        uint   `json:"id"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Status    string `json:"status"`
	Link      string `json:"link"`
	Tag       string `json:"tag"`
	CreatedAt string `json:"created_at"`
}

// nodes 返回某台服务器上已部署的节点。
func (s *Server) nodes(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var list []store.Deployment
	if err := s.DB.Where("server_id = ?", id).Order("id desc").Find(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	views := make([]nodeView, 0, len(list))
	for _, d := range list {
		v := nodeView{ID: d.ID, Protocol: d.Protocol, Port: d.Port, Status: d.Status, CreatedAt: d.CreatedAt.Format("2006-01-02 15:04")}
		var payload struct {
			Link string `json:"link"`
			Spec struct {
				Tag string `json:"tag"`
			} `json:"spec"`
		}
		if json.Unmarshal([]byte(d.ConfigJSON), &payload) == nil {
			v.Link = payload.Link
			v.Tag = payload.Spec.Tag
		}
		views = append(views, v)
	}
	c.JSON(http.StatusOK, gin.H{"items": views})
}

// removeNode 卸载并删除部署记录。
func (s *Server) removeNode(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var d store.Deployment
	if err := s.DB.First(&d, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	var srv store.Server
	if err := s.DB.First(&srv, d.ServerID).Error; err == nil {
		if sec, err := s.openSecret(srv); err == nil {
			ctx, cancel := context.WithTimeout(c.Request.Context(), 60*time.Second)
			defer cancel()
			if client, err := sshx.Dial(ctx, srv.Host, sshx.Credentials{
				User: srv.SSHUser, Port: srv.SSHPort,
				Password: sec.Password, PrivateKey: []byte(sec.PrivateKey), Passphrase: sec.Passphrase,
				Timeout: 10 * time.Second,
			}, s.HostKeys); err == nil {
				_ = provision.Uninstall(ctx, client, d.Protocol, d.Port, nil)
				client.Close()
			}
		}
	}
	s.DB.Delete(&store.Deployment{}, id)
	s.audit("node.remove", d.Protocol, fmt.Sprintf("port=%d", d.Port))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return strings.ReplaceAll(err.Error(), `"`, "'")
	}
	return string(b)
}
