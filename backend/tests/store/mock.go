package tests

import (
	"database/sql"
	"errors"
)

type MockDB struct {
	ExecCalled     bool
	QueryRowCalled bool
	QueryCalled    bool
	ShouldError    bool
	NoRows         bool
	LastQuery      string
	LastParams     []interface{}
}

func (m *MockDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	m.ExecCalled = true
	m.LastQuery = query
	m.LastParams = args
	if m.ShouldError {
		return nil, errors.New("mock error")
	}
	return &MockResult{}, nil
}

func (m *MockDB) QueryRow(query string, args ...interface{}) *sql.Row {
	m.QueryRowCalled = true
	m.LastQuery = query
	m.LastParams = args

	// Create a real database connection just for the Row
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return &sql.Row{}
	}
	defer db.Close()

	// Use empty query that will return the expected number of columns
	var queryToUse string
	switch {
	case m.ShouldError:
		return db.QueryRow("SELECT 1 WHERE 1=0") // Will cause error on Scan
	case m.NoRows:
		return db.QueryRow("SELECT 1 WHERE 1=0") // Will return no rows
	default:
		queryToUse = "SELECT 1, 2, 3, 4" // Will return data that can be scanned
	}

	return db.QueryRow(queryToUse)
}

func (m *MockDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	m.QueryCalled = true
	m.LastQuery = query
	m.LastParams = args
	if m.ShouldError {
		return nil, errors.New("mock error")
	}

	// Create a real database connection just for the Rows
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	if m.NoRows {
		return db.Query("SELECT 1 WHERE 1=0")
	}
	return db.Query("SELECT 1, 2, 3, 4")
}

func (m *MockDB) Close() error {
	return nil
}

type MockResult struct{}

func (r *MockResult) LastInsertId() (int64, error) {
	return 1, nil
}

func (r *MockResult) RowsAffected() (int64, error) {
	return 1, nil
}
