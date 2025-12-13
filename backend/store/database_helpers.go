/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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
		dbname = "agreements_manager_test"
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
	// Desabilitar temporariamente as constraints FK
	_, err := db.Exec("SET session_replication_role = 'replica'")
	if err != nil {
		return fmt.Errorf("failed to disable constraints: %v", err)
	}
	defer db.Exec("SET session_replication_role = 'origin'")

	// Limpar todas as tabelas
	tables := []string{"agreements", "sub_entities", "subcategories", "categories", "entities", "users", "system_settings"}
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

// InsertTestEntity inserts a test entity and returns its ID
func InsertTestEntity(db *sql.DB, name, registrationID string) (string, error) {
	// Gera um UUID válido
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO entities (id, name, registration_id) VALUES ($1, $2, $3)",
		id, name, registrationID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test entity: %v", err)
	}
	return id, nil
}

// InsertTestSubEntity inserts a test sub-entity and returns its ID
func InsertTestSubEntity(db *sql.DB, name string, entityID string) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO sub_entities (id, name, entity_id) VALUES ($1, $2, $3)",
		id, name, entityID,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test sub-entity: %v", err)
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

// InsertTestAgreement inserts a test agreement and returns its UUID
// startDate and endDate can be nil to represent nullable dates
func InsertTestAgreement(db *sql.DB, model, itemKey string, startDate, endDate *time.Time, subcategoryID, entityID string, subEntityID interface{}) (string, error) {
	id := uuid.New().String()
	_, err := db.Exec(
		"INSERT INTO agreements (id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id, archived_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
		id, model, itemKey, startDate, endDate, subcategoryID, entityID, subEntityID, nil,
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert test agreement: %v", err)
	}
	return id, nil
}
