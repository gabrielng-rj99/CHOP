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

package auditstore

import (
	"database/sql"
	"time"

	"Open-Generic-Hub/backend/repository"
	userstore "Open-Generic-Hub/backend/repository/user"
)

// SetupTestDB initializes and returns a test database connection
func SetupTestDB() (*sql.DB, error) {
	return repository.SetupTestDB()
}

// CloseDB closes the test database connection
func CloseDB(db *sql.DB) error {
	return repository.CloseDB(db)
}

// ClearTables removes all data from the test database tables
func ClearTables(db *sql.DB) error {
	return repository.ClearTables(db)
}

// InsertTestClient inserts a test client and returns its ID
func InsertTestClient(db *sql.DB, name, registrationID string) (string, error) {
	return repository.InsertTestClient(db, name, registrationID)
}

// InsertTestAffiliate inserts a test affiliate and returns its ID
func InsertTestAffiliate(db *sql.DB, name string, clientID string) (string, error) {
	return repository.InsertTestAffiliate(db, name, clientID)
}

// InsertTestCategory inserts a test category and returns its ID
func InsertTestCategory(db *sql.DB, name string) (string, error) {
	return repository.InsertTestCategory(db, name)
}

// InsertTestSubcategory inserts a test subcategory and returns its ID
func InsertTestSubcategory(db *sql.DB, name string, categoryID string) (string, error) {
	return repository.InsertTestSubcategory(db, name, categoryID)
}

// InsertTestContract inserts a test contract and returns its UUID
func InsertTestContract(db *sql.DB, model, itemKey string, startDate, endDate *time.Time, subcategoryID, clientID string, subClientID interface{}) (string, error) {
	return repository.InsertTestContract(db, model, itemKey, startDate, endDate, subcategoryID, clientID, subClientID)
}

// NewUserStore creates a new UserStore for testing
func NewUserStore(db repository.DBInterface) *userstore.UserStore {
	return userstore.NewUserStore(db)
}
