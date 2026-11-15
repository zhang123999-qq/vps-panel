package store

import "time"

// LandingNode 是「非 VPS」的落地节点（家宽 SOCKS5）。
// 普通 VPS 落地直接用 servers 表，由 landing.Node 在服务层统一成同一抽象。
type LandingNode struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"` // home_socks5
	Host         string     `json:"host"`
	Port         int        `json:"port"`
	Username     string     `json:"username"`
	PassCipher   []byte     `json:"-"`
	ExpectExitIP string     `json:"expect_exit_ip"`
	Status       string     `json:"status"`
	LastTestAt   *time.Time `json:"last_test_at"`
	LastError    string     `json:"last_error"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (LandingNode) TableName() string { return "landing_nodes" }
