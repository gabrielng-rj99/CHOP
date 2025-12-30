/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		err = db.PingContext(ctx)
		cancel()
		if err == nil {
			return db, nil
		}
		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("failed to connect to database after retries: %v", err)
}

// InitDB initializes the database by executing all schema files in order.
// The schema directory contains modular SQL files that are executed alphabetically.
func InitDB(db *sql.DB) error {
	cfg := config.GetConfig()
	schemaDir := cfg.Paths.SchemaDir

	// Read all files in schema directory
	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		return fmt.Errorf("failed to read schema directory: %v", err)
	}

	// Filter and collect SQL files (excluding init.sql which is for psql CLI)
	var schemaFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") && entry.Name() != "init.sql" {
			schemaFiles = append(schemaFiles, entry.Name())
		}
	}

	// Sort files by name (which includes the numeric prefix: 01_, 02_, etc.)
	sort.Strings(schemaFiles)

	// Execute each schema file in order
	for _, schemaFile := range schemaFiles {
		schemaPath := filepath.Join(schemaDir, schemaFile)

		fmt.Printf("📦 Applying schema: %s\n", schemaFile)

		script, err := os.ReadFile(schemaPath)
		if err != nil {
			return fmt.Errorf("failed to read schema file %s: %v", schemaFile, err)
		}

		_, err = db.Exec(string(script))
		if err != nil {
			return fmt.Errorf("failed to execute schema file %s: %v", schemaFile, err)
		}

		fmt.Printf("✅ Schema applied: %s\n", schemaFile)
	}

	return nil
}

// IsDatabaseInitialized checks if the database has been initialized by verifying if key tables exist and seeds were applied
func IsDatabaseInitialized(db *sql.DB) bool {
	// Check if the users table exists
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'").Scan(&count)
	if err != nil || count == 0 {
		return false
	}

	// Check if roles table exists and has system roles (indicating seeds were applied)
	err = db.QueryRow("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'roles'").Scan(&count)
	if err != nil || count == 0 {
		return false
	}

	// Check if system roles exist (root, admin, user, viewer)
	err = db.QueryRow("SELECT COUNT(*) FROM roles WHERE is_system = true").Scan(&count)
	return err == nil && count >= 4 // At least the 4 system roles
}
