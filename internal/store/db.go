package store

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

//go:embed schema.sql
var schemaSQL string

// Open 打开（或创建）SQLite 数据库并执行幂等迁移。
// 使用纯 Go 驱动 glebarez/sqlite（底层 modernc.org/sqlite），
// 因此 CGO_ENABLED=0 即可交叉编译到 Windows，无需 MSVC。
func Open(path string) (*gorm.DB, error) {
	db, err := gorm.Open(sqlite.Open(path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"),
		&gorm.Config{Logger: logger.Default.LogMode(logger.Warn)})
	if err != nil {
		return nil, err
	}

	for _, stmt := range splitStatements(schemaSQL) {
		if err := db.Exec(stmt).Error; err != nil {
			return nil, err
		}
	}
	if err := migrate(db); err != nil {
		return nil, err
	}
	return db, nil
}

// migrations 是**只增不改**的增量迁移脚本，索引即目标版本号。
// 以后要给表加字段时，在末尾追加一条：
//
//	`ALTER TABLE servers ADD COLUMN host_key TEXT DEFAULT ''`
//
// 老库启动时会按 user_version 顺序补齐，不会丢数据、不会重复执行。
var migrations = []string{
	// v1：基线由 schema.sql 建立，这里留空占位，便于后续追加
}

// migrate 按 PRAGMA user_version 顺序执行增量迁移。
func migrate(db *gorm.DB) error {
	var ver int
	if err := db.Raw("PRAGMA user_version").Scan(&ver).Error; err != nil {
		return err
	}
	if ver > len(migrations) {
		// 库比程序新（用户降级了 exe）：不执行，避免误操作，但给明确提示
		return fmt.Errorf("数据库版本 v%d 高于当前程序支持的 v%d，请升级面板版本", ver, len(migrations))
	}
	for i := ver; i < len(migrations); i++ {
		v := i + 1
		// 关键：DDL 与版本号必须在**同一个事务**里提交。
		// 否则进程在两者之间被杀 → schema 已改但版本没涨 → 下次启动重复执行 ALTER →
		// "duplicate column name" → 永久启动失败。
		err := db.Transaction(func(tx *gorm.DB) error {
			if err := tx.Exec(migrations[i]).Error; err != nil {
				return fmt.Errorf("第 v%d 条迁移执行失败: %w", v, err)
			}
			if err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v)).Error; err != nil {
				return fmt.Errorf("第 v%d 条迁移写版本号失败: %w", v, err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("数据库迁移中止（已回滚到 v%d，原数据未改动）: %w", v-1, err)
		}
	}
	return nil
}

// splitStatements 逐条执行，避免部分驱动不支持多语句 Exec。
func splitStatements(sql string) []string {
	var out []string
	for _, part := range strings.Split(sql, ";") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}
