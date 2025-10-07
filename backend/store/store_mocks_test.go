package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"time"
)

type mockDriver struct{}

func (d mockDriver) Open(name string) (driver.Conn, error) {
	return &mockConn{}, nil
}

type mockConn struct{}

func (c *mockConn) Prepare(query string) (driver.Stmt, error) {
	return &mockStmt{query: query}, nil
}

func (c *mockConn) Close() error {
	return nil
}

func (c *mockConn) Begin() (driver.Tx, error) {
	return nil, nil
}

type mockStmt struct {
	query string
}

func (s *mockStmt) Close() error {
	return nil
}

func (s *mockStmt) NumInput() int {
	return -1
}

func (s *mockStmt) Exec(args []driver.Value) (driver.Result, error) {
	return &mockResult{1}, nil
}

func (s *mockStmt) Query(args []driver.Value) (driver.Rows, error) {
	return &mockDriverRows{
		rows: [][]driver.Value{
			{sql.NullString{String: "1", Valid: true}, sql.NullString{String: "Test", Valid: true}},
		},
		columns: []string{"id", "name"},
	}, nil
}

type mockDriverRows struct {
	rows       [][]driver.Value
	columns    []string
	currentRow int
}

func (r *mockDriverRows) Columns() []string {
	return r.columns
}

func (r *mockDriverRows) Close() error {
	return nil
}

func (r *mockDriverRows) Next(dest []driver.Value) error {
	r.currentRow++
	if r.currentRow >= len(r.rows) {
		return io.EOF
	}

	copy(dest, r.rows[r.currentRow])
	return nil
}

// Mock do sql.DB para testes
type mockDB struct {
	// Para verificar se os métodos foram chamados
	execCalled     bool
	queryCalled    bool
	queryRowCalled bool

	// Para controlar o comportamento dos métodos
	shouldError bool
	noRows      bool

	// Para verificar os parâmetros passados
	lastQuery  string
	lastParams []interface{}
}

// Garante que mockDB implementa DBInterface
var _ DBInterface = &mockDB{}

func (m *mockDB) Exec(query string, args ...interface{}) (sql.Result, error) {
	m.execCalled = true
	m.lastQuery = query
	m.lastParams = args

	if m.shouldError {
		return nil, errors.New("mock error")
	}

	return &mockResult{affected: 1}, nil
}

func (m *mockDB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	m.queryCalled = true
	m.lastQuery = query
	m.lastParams = args

	if m.shouldError {
		return nil, errors.New("mock error")
	}

	db := sql.OpenDB(mockConnector{})
	return db.Query(query, args...)
}

func (m *mockDB) QueryRow(query string, args ...interface{}) *sql.Row {
	m.queryRowCalled = true
	m.lastQuery = query
	m.lastParams = args

	if m.noRows {
		return &sql.Row{}
	}

	return &sql.Row{}
}

// Implementação dos métodos adicionais necessários da interface sql.DB
func (m *mockDB) Begin() (*sql.Tx, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDB) Close() error {
	return nil
}

func (m *mockDB) Ping() error {
	return nil
}

func (m *mockDB) Prepare(query string) (*sql.Stmt, error) {
	return nil, errors.New("not implemented")
}

func (m *mockDB) SetConnMaxLifetime(d time.Duration) {}

func (m *mockDB) SetMaxIdleConns(n int) {}

func (m *mockDB) SetMaxOpenConns(n int) {}

func (m *mockDB) Stats() sql.DBStats {
	return sql.DBStats{}
}

type mockConnector struct{}

func (c mockConnector) Connect(context.Context) (driver.Conn, error) {
	return &mockConn{}, nil
}

func (c mockConnector) Driver() driver.Driver {
	return &mockDriver{}
}

type mockResult struct {
	affected int64
}

func (m *mockResult) LastInsertId() (int64, error) {
	return 0, nil
}

func (m *mockResult) RowsAffected() (int64, error) {
	return m.affected, nil
}
