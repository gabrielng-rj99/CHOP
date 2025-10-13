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
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			registration_id TEXT UNIQUE NOT NULL,
			archived_at DATETIME
		)`,
		`CREATE TABLE IF NOT EXISTS entities (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			client_id TEXT NOT NULL,
			FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS categories (
			id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS lines (
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
			line_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			entity_id TEXT,
			FOREIGN KEY (line_id) REFERENCES lines(id),
			FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
			FOREIGN KEY (entity_id) REFERENCES entities(id) ON DELETE SET NULL
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
	tables := []string{"licenses", "entities", "lines", "categories", "clients"}
	for _, table := range tables {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("failed to clear table %s: %v", table, err)
		}
	}
	return nil
}

// InsertTestClient inserts a test client and returns its ID
func InsertTestClient(db *sql.DB, name, registrationID string) (string, error) {
	// Usa o registrationID passado como argumento
	id := fmt.Sprintf("test-client-%s", registrationID)
	_, err := db.Exec(
		"INSERT INTO clients (id, name, registration_id) VALUES (?, ?, ?)",
		id, name, registrationID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test client: %v", err)
	}
	return id, nil
}

// InsertTestEntity inserts a test entity and returns its ID
func InsertTestEntity(db *sql.DB, name string, clientID string) (string, error) {
	id := fmt.Sprintf("test-entity-%s-%s", name, clientID)
	_, err := db.Exec(
		"INSERT INTO entities (id, name, client_id) VALUES (?, ?, ?)",
		id, name, clientID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test entity: %v", err)
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

// InsertTestLine inserts a test type and returns its ID
func InsertTestLine(db *sql.DB, name string, categoryID string) (string, error) {
	id := fmt.Sprintf("test-line-%s-%s", name, categoryID)
	_, err := db.Exec(
		"INSERT INTO lines (id, name, category_id) VALUES (?, ?, ?)",
		id, name, categoryID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test line: %v", err)
	}
	return id, nil
}

// InsertTestLicense inserts a test license and returns its ID
func InsertTestLicense(db *sql.DB, name, productKey string, startDate, endDate time.Time, lineID, clientID, entityID string) (string, error) {
	id := fmt.Sprintf("test-license-%s", productKey)
	_, err := db.Exec(
		"INSERT INTO licenses (id, name, product_key, start_date, end_date, line_id, client_id, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		id, name, productKey, startDate, endDate, lineID, clientID, entityID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test license: %v", err)
	}
	return id, nil
}
