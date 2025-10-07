package store

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
