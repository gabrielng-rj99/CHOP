// Licenses-Manager/backend/database/database.go

package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"

	_ "github.com/mattn/go-sqlite3"
)

const DBPath = "./licenses.db"

func ConnectDB() (*sql.DB, error) {
	_, err := os.Stat(DBPath)
	dbExists := !os.IsNotExist(err)

	dsn := DBPath + "?_loc=auto"
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
