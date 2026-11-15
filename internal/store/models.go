package store

import "time"

type Server struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Name         string     `json:"name"`
	Host         string     `json:"host"`
	SSHPort      int        `json:"ssh_port"`
	SSHUser      string     `json:"ssh_user"`
	AuthType     string     `json:"auth_type"`
	SecretCipher []byte     `json:"-"`
	Tags         string     `json:"tags"`
	Provider     string     `json:"provider"`
	Region       string     `json:"region"`
	ExpiresAt    *time.Time `json:"expires_at"`
	Status       string     `json:"status"`
	LastCheckAt  *time.Time `json:"last_check_at"`
	OSInfo       string     `json:"os_info"`
	CPUCores     int        `json:"cpu_cores"`
	MemMB        int        `json:"mem_mb"`
	DiskGB       int        `json:"disk_gb"`
	Note         string     `json:"note"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

func (Server) TableName() string { return "servers" }

type Deployment struct {
	ID             uint       `gorm:"primaryKey" json:"id"`
	ServerID       uint       `json:"server_id"`
	TemplateID     *uint      `json:"template_id"`
	Protocol       string     `json:"protocol"`
	Port           int        `json:"port"`
	ConfigJSON     string     `json:"config_json"`
	Status         string     `json:"status"`
	Version        int        `json:"version"`
	PrevBackupPath string     `json:"prev_backup_path"`
	CreatedAt      time.Time  `json:"created_at"`
	FinishedAt     *time.Time `json:"finished_at"`
}

func (Deployment) TableName() string { return "deployments" }

type AuditLog struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Payload   string    `json:"payload"`
	IP        string    `json:"ip"`
	CreatedAt time.Time `json:"created_at"`
}

func (AuditLog) TableName() string { return "audit_logs" }
