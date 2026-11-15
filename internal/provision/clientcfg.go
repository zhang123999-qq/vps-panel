// 客户端配置生成：用于「本地面板测试」时在远端临时拉起一个客户端进程，
// 由它拨号到节点，再通过本地 SOCKS 入口访问外网，从而拿到**真实出口 IP 与延迟**。
//
// 说明：面板运行在 Windows，内嵌二进制是 linux/amd64，无法在本机拉起客户端；
// 因此测试进程放在目标 VPS 上执行（二进制已就位），测完立即杀掉。
package provision

import (
	"encoding/json"
	"fmt"
)

// ClientCore 返回该协议需要的客户端内核。
func ClientCore(protocol string) string {
	switch protocol {
	case "hysteria2":
		return "sing-box"
	default:
		return "xray"
	}
}

// NeedsLocalClient 判断是否需要临时客户端进程。
// SOCKS5 / HTTP 可直接用 curl 代理参数测试，无需额外进程。
func NeedsLocalClient(protocol string) bool {
	switch protocol {
	case "socks", "http":
		return false
	}
	return true
}

// RenderClientConfig 生成客户端配置：本地 SOCKS 入站 + 指向节点的出站。
func RenderClientConfig(host string, spec *Spec, localSocksPort int) (string, error) {
	if spec == nil {
		return "", fmt.Errorf("缺少节点参数")
	}
	if ClientCore(spec.Protocol) == "sing-box" {
		return renderSingboxClient(host, spec, localSocksPort)
	}
	return renderXrayClient(host, spec, localSocksPort)
}

func renderXrayClient(host string, s *Spec, localPort int) (string, error) {
	var outbound map[string]any
	switch s.Protocol {
	case "vless":
		users := []any{map[string]any{"id": s.UUID, "encryption": "none"}}
		stream := map[string]any{}
		if s.Network == "ws" {
			stream = map[string]any{"network": "ws", "wsSettings": map[string]any{"path": s.Path, "headers": map[string]any{"Host": host}}}
		} else {
			users = []any{map[string]any{"id": s.UUID, "encryption": "none", "flow": "xtls-rprx-vision"}}
			stream = map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"serverName": s.SNI, "fingerprint": "chrome",
					"publicKey": s.PubKey, "shortId": s.ShortID,
				},
			}
		}
		outbound = map[string]any{
			"protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": host, "port": s.Port, "users": users}}},
			"streamSettings": stream,
		}
	case "vmess":
		outbound = map[string]any{
			"protocol": "vmess",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": host, "port": s.Port,
				"users": []any{map[string]any{"id": s.UUID, "alterId": 0, "security": "auto"}}}}},
			"streamSettings": map[string]any{"network": "ws", "wsSettings": map[string]any{
				"path": s.Path, "headers": map[string]any{"Host": host}}},
		}
	case "shadowsocks":
		outbound = map[string]any{
			"protocol": "shadowsocks",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": host, "port": s.Port, "method": s.Method, "password": s.Password}}},
		}
	case "trojan":
		outbound = map[string]any{
			"protocol": "trojan",
			"settings": map[string]any{"servers": []any{map[string]any{
				"address": host, "port": s.Port, "password": s.Password}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "tls", "tlsSettings": map[string]any{
				"serverName": host, "allowInsecure": true}},
		}
	default:
		return "", fmt.Errorf("协议 %s 不支持临时客户端测试", s.Protocol)
	}

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": localPort, "protocol": "socks",
			"settings": map[string]any{"udp": false},
		}},
		"outbounds": []any{outbound},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func renderSingboxClient(host string, s *Spec, localPort int) (string, error) {
	if s.Protocol != "hysteria2" {
		return "", fmt.Errorf("协议 %s 不支持临时客户端测试", s.Protocol)
	}
	cfg := map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "socks", "listen": "127.0.0.1", "listen_port": localPort,
		}},
		"outbounds": []any{map[string]any{
			"type": "hysteria2", "server": host, "server_port": s.Port, "password": s.Password,
			"tls": map[string]any{"enabled": true, "server_name": host, "insecure": true},
		}},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
