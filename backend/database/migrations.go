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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"Open-Generic-Hub/backend/config"
)

const migrationLockKey int64 = 918273645

type appliedMigration struct {
	Name     string
	Checksum string
}

func RunMigrationsFromConfig(db *sql.DB) error {
	cfg := config.GetConfig()
	return RunMigrations(db, cfg.Paths.MigrationsDir)
}

func RunMigrations(db *sql.DB, migrationsDir string) error {
	if migrationsDir == "" {
		return fmt.Errorf("migrations directory is empty")
	}

	files, err := listMigrationFiles(migrationsDir)
	if err != nil {
		return err
	}

	if len(files) == 0 {
		return nil
	}

	lockCtx, lockCancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer lockCancel()

	if err := acquireAdvisoryLock(lockCtx, db, migrationLockKey); err != nil {
		return err
	}
	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer unlockCancel()
		_ = releaseAdvisoryLock(unlockCtx, db, migrationLockKey)
	}()

	if err := ensureMigrationsTable(db); err != nil {
		return err
	}

	applied, err := loadAppliedMigrations(db)
	if err != nil {
		return err
	}

	for _, file := range files {
		path := filepath.Join(migrationsDir, file)

		script, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("failed to read migration %s: %w", file, readErr)
		}

		checksum := checksumBytes(script)

		if existing, ok := applied[file]; ok {
			if existing.Checksum != checksum {
				return fmt.Errorf("migration checksum mismatch for %s", file)
			}
			continue
		}

		if err := applyMigration(db, file, checksum, string(script)); err != nil {
			return err
		}
	}

	return nil
}

func listMigrationFiles(migrationsDir string) ([]string, error) {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read migrations directory: %w", err)
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			files = append(files, name)
		}
	}

	sort.Strings(files)
	return files, nil
}

func ensureMigrationsTable(db *sql.DB) error {
	stmt := `
CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);`
	_, err := db.Exec(stmt)
	if err != nil {
		return fmt.Errorf("failed to ensure schema_migrations table: %w", err)
	}
	return nil
}

func loadAppliedMigrations(db *sql.DB) (map[string]appliedMigration, error) {
	rows, err := db.Query(`SELECT name, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("failed to read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]appliedMigration)
	for rows.Next() {
		var name, checksum string
		if scanErr := rows.Scan(&name, &checksum); scanErr != nil {
			return nil, fmt.Errorf("failed to scan schema_migrations row: %w", scanErr)
		}
		applied[name] = appliedMigration{
			Name:     name,
			Checksum: checksum,
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("schema_migrations rows error: %w", err)
	}

	return applied, nil
}

func applyMigration(db *sql.DB, name, checksum, script string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to start migration transaction for %s: %w", name, err)
	}
	defer func() {
		_ = tx.Rollback()
	}()

	if _, err := tx.Exec(script); err != nil {
		return fmt.Errorf("failed to apply migration %s: %w", name, err)
	}

	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (name, checksum) VALUES ($1, $2)`,
		name,
		checksum,
	); err != nil {
		return fmt.Errorf("failed to record migration %s: %w", name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit migration %s: %w", name, err)
	}

	return nil
}

func checksumBytes(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func acquireAdvisoryLock(ctx context.Context, db *sql.DB, key int64) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		var locked bool
		if err := db.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&locked); err != nil {
			return fmt.Errorf("failed to acquire advisory lock: %w", err)
		}
		if locked {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out acquiring advisory lock")
		case <-ticker.C:
		}
	}
}

func releaseAdvisoryLock(ctx context.Context, db *sql.DB, key int64) error {
	var unlocked bool
	if err := db.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked); err != nil {
		return fmt.Errorf("failed to release advisory lock: %w", err)
	}
	if !unlocked {
		return fmt.Errorf("advisory lock was not held")
	}
	return nil
}
