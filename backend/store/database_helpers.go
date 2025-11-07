package store

import (
	"database/sql"
	"fmt"
	"os"
	"sync"
	"time"

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
	dbname := os.Getenv("POSTGRES_DB")
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
	if dbname == "" {
		dbname = "contracts_manager"
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

	testDB = db
	dbOpened = true
	return db, nil
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
	tables := []string{"contracts", "dependents", "lines", "categories", "clients", "users", "login_attempts"}
	for _, table := range tables {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return fmt.Errorf("failed to clear table %s: %v", table, err)
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

// InsertTestDependent inserts a test entity and returns its ID
func InsertTestDependent(db *sql.DB, name string, clientID string) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO dependents (id, name, client_id) VALUES ($1, $2, $3)",
		id, name, clientID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test dependent: %v", err)
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

// InsertTestLine inserts a test type and returns its ID
func InsertTestLine(db *sql.DB, name string, categoryID string) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO lines (id, name, category_id) VALUES ($1, $2, $3)",
		id, name, categoryID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test line: %v", err)
	}
	return id, nil
}

// InsertTestContract inserts a test license and returns its UUID
func InsertTestContract(db *sql.DB, model, productKey string, startDate, endDate time.Time, lineID, clientID string, entityID interface{}) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id, archived_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		id, model, productKey, startDate, endDate, lineID, clientID, entityID, nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test license: %v", err)
	}
	return id, nil
}
