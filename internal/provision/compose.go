// 本文件提供配置片段的构造函数，供「单协议部署」与「组合场景（链路/家宽）」共用，
// 避免同一份 JSON 结构在多处重复拼装。
package provision

import (
	"encoding/json"
	"fmt"
)

// RealityInbound 构造 VLESS + Reality 入站片段。
func RealityInbound(port int, uuid, privKey, shortID, dest, sni string) map[string]any {
	return map[string]any{
		"listen":   "0.0.0.0",
		"port":     port,
		"protocol": "vless",
		"settings": map[string]any{
			"clients":    []any{map[string]any{"id": uuid, "flow": "xtls-rprx-vision"}},
			"decryption": "none",
		},
		"streamSettings": map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"show":        false,
				"dest":        dest,
				"xver":        0,
				"serverNames": []string{sni},
				"privateKey":  privKey,
				"shortIds":    []string{shortID},
			},
		},
		"sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
	}
}

// WSInbound 构造带路径的 WS 入站（vmess / vless-ws 共用）。
func WSInbound(port int, protocol, uuid, path string) map[string]any {
	settings := map[string]any{}
	if protocol == "vless" {
		settings = map[string]any{
			"clients":    []any{map[string]any{"id": uuid}},
			"decryption": "none",
		}
	} else {
		settings = map[string]any{"clients": []any{map[string]any{"id": uuid, "alterId": 0}}}
	}
	return map[string]any{
		"listen":         "0.0.0.0",
		"port":           port,
		"protocol":       protocol,
		"settings":       settings,
		"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{"path": path}},
		"sniffing":       map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}},
	}
}

// VLESSRealityOutbound 构造指向落地的 VLESS + Reality 出站（前置侧使用）。
func VLESSRealityOutbound(tag, server string, port int, uuid, pubKey, shortID, sni string) map[string]any {
	return map[string]any{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": server,
				"port":    port,
				"users":   []any{map[string]any{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}},
			}},
		},
		"streamSettings": map[string]any{
			"network":  "tcp",
			"security": "reality",
			"realitySettings": map[string]any{
				"serverName":  sni,
				"fingerprint": "chrome",
				"publicKey":   pubKey,
				"shortId":     shortID,
			},
		},
	}
}

// VMessWSOutbound 构造指向落地的 VMess + WS 出站（前置侧使用）。
func VMessWSOutbound(tag, server, host string, port int, uuid, path string) map[string]any {
	return map[string]any{
		"tag":      tag,
		"protocol": "vmess",
		"settings": map[string]any{
			"vnext": []any{map[string]any{
				"address": server,
				"port":    port,
				"users":   []any{map[string]any{"id": uuid, "alterId": 0, "security": "auto"}},
			}},
		},
		"streamSettings": map[string]any{
			"network":    "ws",
			"wsSettings": map[string]any{"path": path, "headers": map[string]any{"Host": host}},
		},
	}
}

// Socks5Outbound 构造家宽 SOCKS5 出站。
func Socks5Outbound(tag, addr string, port int, user, pass string) map[string]any {
	server := map[string]any{"address": addr, "port": port}
	if user != "" {
		server["users"] = []any{map[string]any{"user": user, "pass": pass}}
	}
	return map[string]any{
		"tag":      tag,
		"protocol": "socks",
		"settings": map[string]any{"servers": []any{server}},
	}
}

// FreedomOutbound 直连出站。
func FreedomOutbound(tag string) map[string]any {
	return map[string]any{"tag": tag, "protocol": "freedom", "settings": map[string]any{}}
}

// BuildConfig 拼装完整配置。
// 约定：outbounds 的第一个即默认出站（xray 的语义），所以调用方把「要走的出站」放第一位。
func BuildConfig(inbounds []any, orderedOutbounds []any) (string, error) {
	if len(orderedOutbounds) == 0 {
		orderedOutbounds = []any{FreedomOutbound("direct")}
	}
	cfg := map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  inbounds,
		"outbounds": orderedOutbounds,
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", fmt.Errorf("序列化配置失败: %w", err)
	}
	return string(b), nil
}
