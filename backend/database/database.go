// Contracts-Manager/backend/database/database.go

package database

import (
	"database/sql"
	"os"
	"time"

	"Contracts-Manager/backend/config"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func getPostgresDSN() string {
	cfg := config.GetConfig()
	return cfg.GetDatabaseURL()
}

func ConnectDB() (*sql.DB, error) {
	dsn := getPostgresDSN()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	// Get config for connection pool settings
	cfg := config.GetConfig()

	// Set connection pool parameters
	db.SetConnMaxLifetime(time.Duration(cfg.Database.ConnMaxLifetime) * time.Second)
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}

func initDB(db *sql.DB) error {
	cfg := config.GetConfig()
	sqlFilePath := cfg.Paths.SchemaFile

	script, err := os.ReadFile(sqlFilePath)
	if err != nil {
		return err
	}

	_, err = db.Exec(string(script))
	if err != nil {
		return err
	}

	return nil
}
