package api

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"vpspanel/internal/config"
	"vpspanel/internal/crypto"
	"vpspanel/internal/kernel"
	"vpspanel/internal/sshx"
	"vpspanel/internal/store"
	"vpspanel/internal/web"
)

var Version = "0.5.0-m4"

type Server struct {
	DB  *gorm.DB
	Box *crypto.Box
	Cfg *config.Config

	// HostKeys 固定 SSH 主机指纹（TOFU），防中间人
	HostKeys *sshx.HostKeys

	// 部署互斥：键为 "serverID:port"，避免并发写同一台机器的同一端口
	locks sync.Map
}

// tryLockPlan 非阻塞加锁：已有同键任务时返回 ok=false。
func (s *Server) tryLockPlan(serverID uint, port int) (func(), bool) {
	key := fmt.Sprintf("%d:%d", serverID, port)
	v, _ := s.locks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	if !m.TryLock() {
		return func() {}, false
	}
	return m.Unlock, true
}

// lockPlan 加锁并返回解锁函数。
func (s *Server) lockPlan(serverID uint, port int) func() {
	key := fmt.Sprintf("%d:%d", serverID, port)
	v, _ := s.locks.LoadOrStore(key, &sync.Mutex{})
	m := v.(*sync.Mutex)
	m.Lock()
	return m.Unlock
}

func New(db *gorm.DB, cfg *config.Config, box *crypto.Box) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery(), SecurityGuard())

	s := &Server{
		DB: db, Box: box, Cfg: cfg,
		HostKeys: sshx.LoadHostKeys(filepath.Join(cfg.DataDir, "known_hosts.json")),
	}

	api := r.Group("/api")
	{
		api.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"ok": true, "version": Version,
				"data":    cfg.DataDir,
				"kernels": kernel.Builtin(), // P1：内嵌版本唯一来源
				"time":    time.Now().Format(time.RFC3339),
			})
		})

		api.GET("/protocols", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"items": protocols})
		})

		api.GET("/servers", s.listServers)
		api.POST("/servers", s.createServer)
		api.PUT("/servers/:id", s.updateServer)
		api.DELETE("/servers/:id", s.deleteServer)
		api.POST("/servers/:id/test", s.testServer)
		api.POST("/probe", s.probe)
		api.POST("/deploy", s.deploy)
		api.GET("/servers/:id/nodes", s.nodes)
		api.DELETE("/deployments/:id", s.removeNode)
		api.POST("/deployments/:id/test", s.nodeTest)     // 本地面板测试（真实出口 IP + 延迟）
		api.POST("/servers/:id/cleanup", s.cleanupServer) // 清理残余节点服务与配置

		// 内核：远端升级（1B）。内嵌内核升级是构建期脚本(1A)，不在运行时接口里。
		api.GET("/kernels", s.kernelsOverview)
		api.POST("/kernels/update", s.kernelUpdate)
		// 落地节点（家宽 SOCKS5 数据源，P2）
		api.GET("/landing-options", s.landingOptions)
		api.GET("/landing-nodes", s.landingList)
		api.POST("/landing-nodes", s.landingCreate)
		api.PUT("/landing-nodes/:id", s.landingUpdate)
		api.DELETE("/landing-nodes/:id", s.landingDelete)
		api.POST("/landing-nodes/:id/test", s.landingTest)
		// 链路（统一落地抽象）
		api.POST("/chain/deploy", s.chainDeploy)

		api.GET("/deployments", func(c *gin.Context) {
			var list []store.Deployment
			s.DB.Order("id desc").Limit(100).Find(&list)
			c.JSON(http.StatusOK, gin.H{"items": list})
		})

		api.GET("/audit", func(c *gin.Context) {
			var list []store.AuditLog
			s.DB.Order("id desc").Limit(200).Find(&list)
			c.JSON(http.StatusOK, gin.H{"items": list})
		})
	}

	static := web.Handler()
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		static.ServeHTTP(c.Writer, c.Request)
	})

	return r
}

func (s *Server) listServers(c *gin.Context) {
	var list []store.Server
	if err := s.DB.Order("id desc").Find(&list).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	// 统一转换成视图：字段与表格列一一对应，字符串全部单行
	views := make([]serverView, 0, len(list))
	for _, sv := range list {
		views = append(views, viewOf(sv))
	}
	c.JSON(http.StatusOK, gin.H{"items": views, "total": len(views)})
}

// pruneFailures 只保留最近 20 条失败记录，避免 DB 无界增长。
func (s *Server) pruneFailures(serverID uint) {
	var ids []uint
	if err := s.DB.Model(&store.Deployment{}).
		Where("server_id = ? AND status = ?", serverID, "failed").
		Order("id desc").Offset(20).Pluck("id", &ids).Error; err != nil {
		return
	}
	if len(ids) > 0 {
		s.DB.Delete(&store.Deployment{}, ids)
	}
}

func (s *Server) audit(action, target, payload string) {
	_ = s.DB.Create(&store.AuditLog{
		Actor: "local", Action: action, Target: target, Payload: payload,
	}).Error
}

// protocols 是前端下拉框的数据源；status 决定是否可点「部署」。
type proto struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Core        string `json:"core"`
	NeedsDomain bool   `json:"needs_domain"`
	Transport   string `json:"transport"`
	Status      string `json:"status"` // ready | experimental | pending
	Note        string `json:"note"`
}

var protocols = []proto{
	{"vmess", "VMess", "xray", false, "TCP / WS", "ready", "AEAD 加密，可套 WS+TLS"},
	{"vless", "VLESS", "xray", false, "TCP / Reality", "ready", "Reality 无需域名，抗封锁最好"},
	{"shadowsocks", "Shadowsocks", "xray", false, "TCP / UDP", "ready", "2022 版协议，轻量"},
	{"trojan", "Trojan", "xray", true, "TCP / TLS", "ready", "自签证书，伪装 HTTPS"},
	{"hysteria2", "Hysteria2", "sing-box", true, "QUIC / UDP", "ready", "速度最好，注意服务商限 UDP"},
	{"wireguard", "WireGuard", "system", false, "UDP", "ready", "系统 wg-quick；需远端 wireguard-tools"},
	{"masque", "MASQUE", "sing-box", true, "HTTP/3", "experimental", "CONNECT-IP，实验性，需 sing-box ≥1.14"},
	{"socks", "SOCKS5", "xray", false, "TCP", "ready", "可带账号密码"},
	{"http", "HTTP 代理", "xray", false, "TCP", "ready", "可带账号密码"},
}
