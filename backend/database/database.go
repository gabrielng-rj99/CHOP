// Licenses-Manager/backend/database/database.go

package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"

	_ "github.com/mattn/go-sqlite3"
)

func getDBPath() string {
	// Descobre o diretório do arquivo atual (database.go)
	_, b, _, _ := runtime.Caller(0)
	basePath := filepath.Dir(b)
	return filepath.Join(basePath, "licenses.db")
}

func ConnectDB() (*sql.DB, error) {
	dbPath := getDBPath()
	// Garante que o diretório database existe
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	_, err := os.Stat(dbPath)
	dbExists := !os.IsNotExist(err)

	dsn := dbPath + "?_loc=auto"
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}

	if !dbExists {
		err = initDB(db)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}

func initDB(db *sql.DB) error {
	_, b, _, _ := runtime.Caller(0)
	basePath := filepath.Dir(b)
	sqlFilePath := filepath.Join(basePath, "init.sql")

	script, err := os.ReadFile(sqlFilePath)
	if err != nil {
		return err
	}

	_, err = db.Exec(string(script))
	if err != nil {
		return err
	}

	return nil
}
