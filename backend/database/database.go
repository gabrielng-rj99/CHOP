// Contracts-Manager/backend/database/database.go

package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"

	_ "github.com/jackc/pgx/v5/stdlib"
)

func getPostgresDSN() string {
	// Exemplo de DSN: "postgres://user:password@localhost:5432/contracts_manager?sslmode=disable"
	// Recomenda-se usar variáveis de ambiente para dados sensíveis em produção
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
		// Detecta contexto de teste pelo POSTGRES_PORT ou variável de ambiente
		if port == "65432" || os.Getenv("TEST_DB") == "1" {
			dbname = "contracts_manager_test"
		} else {
			dbname = "contracts_manager"
		}
	}
	return "postgres://" + user + ":" + password + "@" + host + ":" + port + "/" + dbname + "?sslmode=" + sslmode
}

func ConnectDB() (*sql.DB, error) {
	dsn := getPostgresDSN()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	// Testa conexão
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Opcional: rodar initDB se necessário (ex: para criar schema/tabelas)
	// err = initDB(db)
	// if err != nil {
	//     return nil, err
	// }

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
