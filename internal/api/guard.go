package api

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

// IsLocalHost 判断 Host 头是否指向本机。
// 用途：防止 DNS rebinding —— 攻击者把自己的域名解析到 127.0.0.1，
// 让浏览器"同源"访问面板。
func IsLocalHost(h string) bool {
	h = strings.Trim(strings.TrimSpace(h), "[]")
	switch strings.ToLower(h) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(h); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// OriginAllowed 判断 Origin 是否与请求 Host 同源。
func OriginAllowed(origin, reqHost string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, reqHost)
}

// SecurityGuard 是全局安全中间件：
//
//  1. Host 必须是本机（挡 DNS rebinding）
//  2. 写操作必须是 application/json（挡 <form> 之类的"简单请求"CSRF）
//  3. Origin 若存在必须同源（挡跨站 fetch）
//
// 面板无鉴权、仅监听 127.0.0.1，这三条是当前架构下最低成本的纵深防御。
// maxBodyBytes 限制请求体大小，避免超大 JSON 拖垮内存（本面板所有接口都是小载荷）。
const maxBodyBytes = 1 << 20 // 1MB

func SecurityGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 基础安全响应头（挡点击劫持 / MIME 嗅探 / 外链泄露 referrer）
		h := c.Writer.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")

		// 请求体上限：写操作在边缘读一次（≤1MB），超限直接 413，
		// 避免把巨大 body 交给后续 handler 才失败（错误码不明确）。
		switch c.Request.Method {
		case "POST", "PUT", "PATCH", "DELETE":
			if c.Request.Body != nil {
				body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes))
				if err != nil {
					c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{"error": "请求体过大（上限 1MB）"})
					return
				}
				c.Request.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		host := c.Request.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !IsLocalHost(host) {
			c.AbortWithStatusJSON(403, gin.H{"error": "forbidden host"})
			return
		}

		switch c.Request.Method {
		case "POST", "PUT", "PATCH", "DELETE":
			// 空 body（如 DELETE /api/deployments/1）不强制 JSON：空载荷本身无法携带 CSRF 数据，
			// 且非简单方法仍会触发预检。有 body 时才要求 application/json。
			if c.Request.ContentLength > 0 {
				if ct := c.ContentType(); !strings.HasPrefix(ct, "application/json") {
					c.AbortWithStatusJSON(415, gin.H{"error": "Content-Type 必须是 application/json"})
					return
				}
			}
			if o := c.GetHeader("Origin"); o != "" && !OriginAllowed(o, c.Request.Host) {
				c.AbortWithStatusJSON(403, gin.H{"error": "跨站请求被拒绝"})
				return
			}
		}
		c.Next()
	}
}
