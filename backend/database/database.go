// Open-Generic-Hub/backend/database/database.go

package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"time"

	"Open-Generic-Hub/backend/config"

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
	db.SetConnMaxLifetime(time.Duration(cfg.Database.ConnMaxLife) * time.Second)
	db.SetMaxOpenConns(cfg.Database.MaxOpenConns)
	db.SetMaxIdleConns(cfg.Database.MaxIdleConns)

	// Retry connection up to 10 times with 2 second delay
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := db.PingContext(ctx)
		cancel()
		if err == nil {
			return db, nil
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to database after retries: %v", err)
}

func InitDB(db *sql.DB) error {
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

// IsDatabaseInitialized checks if the database has been initialized by verifying if key tables exist
func IsDatabaseInitialized(db *sql.DB) bool {
	// Check if the users table exists and has at least one record
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'").Scan(&count)
	if err != nil || count == 0 {
		return false
	}

	// Optionally check if there are users
	err = db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return err == nil
}
