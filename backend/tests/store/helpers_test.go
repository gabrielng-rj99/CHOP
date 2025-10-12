package tests

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var (
	testDB   *sql.DB
	dbMutex  sync.Mutex
	dbOpened bool
)

// SetupTestDB initializes and returns a test database connection
func SetupTestDB() (*sql.DB, error) {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	// Always remove old test.db before creating new DB to ensure fresh schema
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("failed to get caller info")
	}
	backendDir := filepath.Dir(filepath.Dir(filepath.Dir(filename))) // .../backend
	dbDir := filepath.Join(backendDir, "tests", "database")
	dbPath := filepath.Join(dbDir, "test.db")

	// Ensure the directory exists
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create tests/database directory: %v", err)
	}

	// Remove old test.db if it exists
	if _, err := os.Stat(dbPath); err == nil {
		_ = os.Remove(dbPath)
	}

	// Open (and create if needed) the SQLite database file
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Enable foreign key enforcement
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable foreign key enforcement: %v", err)
	}

	// Create all tables using the exact schema from init.sql
	tables := []string{
		`CREATE TABLE IF NOT EXISTS companies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			cnpj TEXT UNIQUE NOT NULL,
			archived_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS units (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			company_id TEXT NOT NULL,
			FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS categories (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS types (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			category_id TEXT NOT NULL,
			FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS licenses (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			product_key TEXT UNIQUE NOT NULL,
			start_date DATETIME NOT NULL,
			end_date DATETIME NOT NULL,
			type_id TEXT NOT NULL,
			company_id TEXT NOT NULL,
			unit_id TEXT,
			FOREIGN KEY (type_id) REFERENCES types(id),
			FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE,
			FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE SET NULL
		)`,
	}

	for _, query := range tables {
		if _, err := db.Exec(query); err != nil {
			db.Close()
			return nil, fmt.Errorf("failed to create table: %v", err)
		}
	}

	testDB = db
	dbOpened = true
	return db, nil
}

// CloseDB closes the test database connection and removes the test database file
func CloseDB(db *sql.DB) error {
	dbMutex.Lock()
	defer dbMutex.Unlock()

	if db != nil {
		if err := db.Close(); err != nil {
			return fmt.Errorf("failed to close database: %v", err)
		}
	}

	if dbOpened {
		_, filename, _, ok := runtime.Caller(0)
		if !ok {
			return fmt.Errorf("failed to get caller info")
		}
		backendDir := filepath.Dir(filepath.Dir(filepath.Dir(filename)))
		dbPath := filepath.Join(backendDir, "tests", "database", "test.db")
		if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove test database file: %v", err)
		}
		dbOpened = false
		testDB = nil
	}

	return nil
}

// ClearTables removes all data from the test database tables
func ClearTables(db *sql.DB) error {
	tables := []string{"licenses", "units", "types", "categories", "companies"}
	for _, table := range tables {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("failed to clear table %s: %v", table, err)
		}
	}
	return nil
}

// InsertTestCompany inserts a test company and returns its ID
func InsertTestCompany(db *sql.DB, name, cnpj string) (string, error) {
	id := fmt.Sprintf("test-company-%s", cnpj)
	_, err := db.Exec(
		"INSERT INTO companies (id, name, cnpj) VALUES (?, ?, ?)",
		id, name, cnpj,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test company: %v", err)
	}
	return id, nil
}

// InsertTestUnit inserts a test unit and returns its ID
func InsertTestUnit(db *sql.DB, name string, companyID string) (string, error) {
	id := fmt.Sprintf("test-unit-%s-%s", name, companyID)
	_, err := db.Exec(
		"INSERT INTO units (id, name, company_id) VALUES (?, ?, ?)",
		id, name, companyID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test unit: %v", err)
	}
	return id, nil
}

// InsertTestCategory inserts a test category and returns its ID
func InsertTestCategory(db *sql.DB, name string) (string, error) {
	id := fmt.Sprintf("test-category-%s", name)
	_, err := db.Exec(
		"INSERT INTO categories (id, name) VALUES (?, ?)",
		id, name,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test category: %v", err)
	}
	return id, nil
}

// InsertTestType inserts a test type and returns its ID
func InsertTestType(db *sql.DB, name string, categoryID string) (string, error) {
	id := fmt.Sprintf("test-type-%s-%s", name, categoryID)
	_, err := db.Exec(
		"INSERT INTO types (id, name, category_id) VALUES (?, ?, ?)",
		id, name, categoryID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test type: %v", err)
	}
	return id, nil
}

// InsertTestLicense inserts a test license and returns its ID
func InsertTestLicense(db *sql.DB, name, productKey string, startDate, endDate time.Time, typeID, companyID, unitID string) (string, error) {
	id := fmt.Sprintf("test-license-%s", productKey)
	_, err := db.Exec(
		"INSERT INTO licenses (id, name, product_key, start_date, end_date, type_id, company_id, unit_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, name, productKey, startDate, endDate, typeID, companyID, unitID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test license: %v", err)
	}
	return id, nil
}
