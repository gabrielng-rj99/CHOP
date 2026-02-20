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

package repository

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"Open-Generic-Hub/backend/database"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	testDB   *sql.DB
	dbMutex  sync.Mutex
	dbOpened bool
)

func init() {
	// Cleanup any leftover test directories from previous test runs
	os.RemoveAll("logs")
	os.RemoveAll("logs_audit_test")
	os.RemoveAll("tests")
	os.RemoveAll("backend/tests")
}

// SetupTestDB initializes and returns a test database connection
func SetupTestDB() (*sql.DB, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Conexão PostgreSQL para testes
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	host := os.Getenv("POSTGRES_HOST")
	port := os.Getenv("POSTGRES_PORT")
	baseDB := os.Getenv("POSTGRES_DB")
	sslmode := os.Getenv("POSTGRES_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}
	if user == "" {
		user = "postgres"
	}
	if password == "" {
		password = "postgres"
	}
	if host == "" {
		host = "localhost"
	}
	if port == "" {
		port = "5432"
	}
	if baseDB == "" {
		baseDB = "contracts_manager_test"
	}

	dbname := deriveTestDBName(baseDB)
	if err := ensureDatabaseExists(user, password, host, port, sslmode, dbname); err != nil {
		return nil, err
	}

	dsn := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname + "?sslmode=" + sslmode
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Testa conexão
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %v", err)
	}

	migrationsDir := os.Getenv("MIGRATIONS_DIR")
	if migrationsDir == "" {
		migrationsDir = filepath.Join(resolveBackendRoot(), "database", "migrations")
	}
	if err := database.RunMigrations(db, migrationsDir); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %v", err)
	}

	schemaDir := os.Getenv("SCHEMA_DIR")
	if schemaDir == "" {
		schemaDir = filepath.Join(resolveBackendRoot(), "database", "schema")
	}
	if err := applySchemaIfNeeded(db, schemaDir); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	testDB = db
	dbOpened = true
	return db, nil
}

func deriveTestDBName(base string) string {
	wd, err := os.Getwd()
	if err != nil {
		return base
	}
	pkg := filepath.Base(wd)
	if pkg == "" || pkg == "." || pkg == string(filepath.Separator) {
		return base
	}

	re := regexp.MustCompile(`[^a-zA-Z0-9_]+`)
	safe := strings.ToLower(re.ReplaceAllString(pkg, "_"))
	if safe == "" {
		return base
	}

	return base + "_" + safe
}

func resolveBackendRoot() string {
	wd, err := os.Getwd()
	if err != nil {
		return "backend"
	}

	current := wd
	for {
		if filepath.Base(current) == "backend" {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "backend"
		}
		current = parent
	}
}

func applySchemaIfNeeded(db *sql.DB, schemaDir string) error {
	if database.IsDatabaseInitialized(db) {
		return nil
	}

	entries, err := os.ReadDir(schemaDir)
	if err != nil {
		return fmt.Errorf("failed to read schema directory: %v", err)
	}

	var schemaFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".sql") && entry.Name() != "init.sql" {
			schemaFiles = append(schemaFiles, entry.Name())
		}
	}

	sort.Strings(schemaFiles)

	for _, schemaFile := range schemaFiles {
		schemaPath := filepath.Join(schemaDir, schemaFile)
		script, err := os.ReadFile(schemaPath)
		if err != nil {
			return fmt.Errorf("failed to read schema file %s: %v", schemaFile, err)
		}

		if _, err := db.Exec(string(script)); err != nil {
			return fmt.Errorf("failed to execute schema file %s: %v", schemaFile, err)
		}
	}

	return nil
}

func ensureDatabaseExists(user, password, host, port, sslmode, dbname string) error {
	adminDB := os.Getenv("POSTGRES_ADMIN_DB")
	if adminDB == "" {
		adminDB = "postgres"
	}
	adminDSN := "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + adminDB + "?sslmode=" + sslmode
	admin, err := sql.Open("pgx", adminDSN)
	if err != nil {
		return fmt.Errorf("failed to open admin database: %v", err)
	}
	defer admin.Close()

	if err := admin.Ping(); err != nil {
		return fmt.Errorf("failed to ping admin database: %v", err)
	}

	var exists bool
	if err := admin.QueryRow("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)", dbname).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check test database: %v", err)
	}
	if !exists {
		if _, err := admin.Exec("CREATE DATABASE " + pqQuoteIdentifier(dbname)); err != nil {
			return fmt.Errorf("failed to create test database: %v", err)
		}
	}
	return nil
}

func pqQuoteIdentifier(id string) string {
	return `"` + strings.ReplaceAll(id, `"`, `""`) + `"`
}

// CloseDB closes the test database connection and removes the test database file and temporary directories
func CloseDB(db *sql.DB) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if db != nil {
		if err := db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %v", err)
		}
	}

	if dbOpened {
		dbOpened = false
		testDB = nil
	}
	return nil
}

// ClearTables removes all data from the test database tables
func ClearTables(db *sql.DB) error {
	// Desabilitar temporariamente as constraints FK
	_, err := db.Exec("SET session_replication_role = 'replica'")
	if err != nil {
		return fmt.Errorf("failed to disable constraints: %v", err)
	}
	defer db.Exec("SET session_replication_role = 'origin'")

	// Limpar todas as tabelas
	tables := []string{"contracts", "affiliates", "subcategories", "categories", "clients", "users", "system_settings"}
	for _, table := range tables {
		// Deletar em vez de truncate para evitar problemas com sequences
		_, err := db.Exec("DELETE FROM " + table)
		if err != nil {
			return fmt.Errorf("failed to clear table %s: %v", table, err)
		}
		// Resetar sequences para que IDs comecem do 1 novamente
		_, err = db.Exec("ALTER SEQUENCE " + table + "_id_seq RESTART WITH 1")
		if err != nil {
			// Ignorar erros se a sequence não existir (tabelas com UUIDs não têm sequences numéricas)
		}
	}
	return nil
}

// InsertTestClient inserts a test client and returns its ID
func InsertTestClient(db *sql.DB, name, registrationID string) (string, error) {
	// Gera um UUID válido
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO clients (id, name, registration_id) VALUES ($1, $2, $3)",
		id, name, registrationID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test client: %v", err)
	}
	return id, nil
}

// InsertTestAffiliate inserts a test affiliate and returns its ID
func InsertTestAffiliate(db *sql.DB, name string, clientID string) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO affiliates (id, name, client_id) VALUES ($1, $2, $3)",
		id, name, clientID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test affiliate: %v", err)
	}
	return id, nil
}

// InsertTestCategory inserts a test category and returns its ID
func InsertTestCategory(db *sql.DB, name string) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO categories (id, name) VALUES ($1, $2)",
		id, name,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test category: %v", err)
	}
	return id, nil
}

// InsertTestSubcategory inserts a test subcategory and returns its ID
func InsertTestSubcategory(db *sql.DB, name string, categoryID string) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO subcategories (id, name, category_id) VALUES ($1, $2, $3)",
		id, name, categoryID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test subcategory: %v", err)
	}
	return id, nil
}

// InsertTestContract inserts a test contract and returns its UUID
// startDate and endDate can be nil to represent nullable dates
func InsertTestContract(db *sql.DB, model, itemKey string, startDate, endDate *time.Time, subcategoryID, clientID string, subClientID interface{}) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO contracts (id, model, item_key, start_date, end_date, subcategory_id, client_id, affiliate_id, archived_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		id, model, itemKey, startDate, endDate, subcategoryID, clientID, subClientID, nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test contract: %v", err)
	}
	return id, nil
}
