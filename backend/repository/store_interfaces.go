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
)

// DBInterface define a interface necessária para operações de banco de dados
// Isso permite que usemos tanto *sql.DB quanto mocks nos testes
type DBInterface interface {
	Query(query string, args ...interface{}) (*sql.Rows, error)
	QueryRow(query string, args ...interface{}) *sql.Row
	Exec(query string, args ...interface{}) (sql.Result, error)
}

// DBWithTx extends DBInterface with transaction support
// Use this interface for stores that need transaction support
type DBWithTx interface {
	DBInterface
	Begin() (*sql.Tx, error)
}

// TxInterface defines the interface for transaction operations
// This allows both *sql.Tx and mocks to be used
type TxInterface interface {
	DBInterface
	Commit() error
	Rollback() error
	Prepare(query string) (*sql.Stmt, error)
}

// Ensure *sql.DB implements DBWithTx
var _ DBWithTx = (*sql.DB)(nil)

// Ensure *sql.Tx implements TxInterface
var _ TxInterface = (*sql.Tx)(nil)
