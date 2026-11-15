package store

import (
	"path/filepath"
	"testing"
)

// 迁移机制验收：
//  1. 老库首次打开 user_version = 0；
//  2. 注入一条 ALTER TABLE 后重启 → 字段补齐、版本号 +1、**原有数据不丢**；
//  3. 再次重启 → 不重复执行（幂等）。
func TestMigrationAppliesAndPreservesData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mig.db")

	// 1) 基线库
	db, err := Open(path)
	if err != nil {
		t.Fatalf("打开基线库失败: %v", err)
	}
	var ver int
	if err := db.Raw("PRAGMA user_version").Scan(&ver).Error; err != nil {
		t.Fatalf("读取版本失败: %v", err)
	}
	if ver != 0 {
		t.Fatalf("基线库 user_version 应为 0，实际 %d", ver)
	}
	if err := db.Create(&Server{Name: "keep-me", Host: "1.1.1.1", SSHPort: 22, SSHUser: "root"}).Error; err != nil {
		t.Fatalf("写入测试数据失败: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	// 2) 注入一条迁移（模拟未来给 servers 加字段）
	orig := migrations
	migrations = []string{`ALTER TABLE servers ADD COLUMN host_key TEXT DEFAULT ''`}
	defer func() { migrations = orig }()

	db2, err := Open(path)
	if err != nil {
		t.Fatalf("迁移后打开失败: %v", err)
	}
	var ver2 int
	_ = db2.Raw("PRAGMA user_version").Scan(&ver2).Error
	if ver2 != 1 {
		t.Fatalf("迁移后 user_version 应为 1，实际 %d", ver2)
	}
	hasCol := db2.Migrator().HasColumn(&Server{}, "host_key")
	if !hasCol {
		t.Fatal("迁移后应存在 host_key 字段")
	}
	var count int64
	db2.Model(&Server{}).Where("name = ?", "keep-me").Count(&count)
	if count != 1 {
		t.Fatalf("迁移后原数据丢失，匹配行数 %d", count)
	}
	if sqlDB, err := db2.DB(); err == nil {
		_ = sqlDB.Close()
	}

	// 3) 再次打开：不应重复执行（重复 ALTER 会报 duplicate column）
	db3, err := Open(path)
	if err != nil {
		t.Fatalf("二次重启失败（可能重复执行了迁移）: %v", err)
	}
	var ver3 int
	_ = db3.Raw("PRAGMA user_version").Scan(&ver3).Error
	if ver3 != 1 {
		t.Fatalf("二次重启后版本应保持 1，实际 %d", ver3)
	}
}

// 库版本高于程序（用户降级 exe）时必须拒绝启动，避免破坏新库。
func TestMigrationRejectsNewerDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "newer.db")

	db, err := Open(path)
	if err != nil {
		t.Fatalf("打开失败: %v", err)
	}
	if err := db.Exec("PRAGMA user_version = 99").Error; err != nil {
		t.Fatalf("设置高版本失败: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	if _, err := Open(path); err == nil {
		t.Fatal("库版本高于程序时应拒绝启动")
	}
}

// 迁移必须原子：失败的迁移不得留下 schema 变更，user_version 保持不变
func TestMigrationAtomicOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "atomic.db")

	orig := migrations
	// 故意写一条非法 SQL
	migrations = []string{`ALTER TABLE servers ADD COLUMN`}
	defer func() { migrations = orig }()

	if _, err := Open(path); err == nil {
		t.Fatal("非法迁移应导致启动失败")
	}

	// 版本仍是 0，且没有半截 schema 变更（用合法迁移再验证能正常补）
	migrations = []string{`ALTER TABLE servers ADD COLUMN host_key TEXT DEFAULT ''`}
	db, err := Open(path)
	if err != nil {
		t.Fatalf("回滚后再迁移应成功: %v", err)
	}
	var ver int
	_ = db.Raw("PRAGMA user_version").Scan(&ver).Error
	if ver != 1 {
		t.Fatalf("成功后版本应为 1，实际 %d", ver)
	}
	if !db.Migrator().HasColumn(&Server{}, "host_key") {
		t.Fatal("字段未补齐")
	}
}
