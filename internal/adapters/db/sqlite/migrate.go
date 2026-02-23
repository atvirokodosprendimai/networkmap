package sqlite

import (
	"context"
	"embed"

	"github.com/pressly/goose/v3"
	"gorm.io/gorm"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func RunMigrations(ctx context.Context, db *gorm.DB) error {
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}

	if err := goose.SetDialect("sqlite3"); err != nil {
		return err
	}

	goose.SetBaseFS(migrationsFS)
	if err := goose.UpContext(ctx, sqlDB, "migrations"); err != nil {
		return err
	}

	return nil
}
