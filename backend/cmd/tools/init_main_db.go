package main

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Configurações do banco principal
const (
	mainDBName     = "contracts_manager"
	mainDBUser     = "postgres"
	mainDBPassword = "postgres"
	mainDBPort     = "5432"
	mainContainer  = "contract_manager_postgres"
)

// InitMainDatabaseDocker sobe o container do banco principal e inicializa o schema
func InitMainDatabaseDocker() {
	fmt.Print("\033[H\033[2J")
	projectRoot, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Erro ao determinar raiz do projeto:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	initSQLPath := filepath.Join(projectRoot, "database", "init.sql")

	// Sobe o container principal se não estiver rodando
	if !isContainerRunning(mainContainer) {
		fmt.Println("▶ Subindo container do banco principal...")
		if err := runDockerComposeUp("postgres"); err != nil {
			fmt.Println("❌ Erro ao subir container do banco principal:", err)
			fmt.Print("Pressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	} else {
		fmt.Println("✓ Container do banco principal já está rodando.")
	}

	// Aguarda o banco ficar pronto
	fmt.Println("⏳ Aguardando banco principal ficar pronto...")
	if !waitForPostgresReady("localhost", mainDBPort, 60*time.Second) {
		fmt.Println("❌ Banco principal não ficou pronto no tempo esperado.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Banco principal está pronto!")

	// Exclui e recria o banco principal
	if err := dropAndCreateMainDB(); err != nil {
		fmt.Println("❌ Erro ao recriar banco principal:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Banco principal recriado!")

	// Inicializa o schema do banco principal
	fmt.Println("▶ Inicializando schema do banco principal...")
	if err := initializeMainDatabase(initSQLPath); err != nil {
		fmt.Println("❌ Erro ao inicializar schema:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Schema inicializado!")
	fmt.Print("Pressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// dropAndCreateMainDB exclui e recria o banco de dados principal
func dropAndCreateMainDB() error {
	dsn := fmt.Sprintf("postgres://%s:%s@localhost:%s/postgres?sslmode=disable", mainDBUser, mainDBPassword, mainDBPort)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("falha ao conectar ao postgres: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Termina conexões existentes
	_, _ = db.ExecContext(ctx, fmt.Sprintf(
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s';", mainDBName))

	// Drop database
	_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s;", mainDBName))

	// Create database
	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s;", mainDBName))
	if err != nil {
		return fmt.Errorf("falha ao criar banco principal: %w", err)
	}
	return nil
}

// initializeMainDatabase executa o schema de inicialização no banco principal
func initializeMainDatabase(initPath string) error {
	dsn := fmt.Sprintf("postgres://%s:%s@localhost:%s/%s?sslmode=disable", mainDBUser, mainDBPassword, mainDBPort, mainDBName)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("falha ao conectar ao banco principal: %w", err)
	}
	defer db.Close()

	// Lê o arquivo init.sql
	initSQL, err := os.ReadFile(initPath)
	if err != nil {
		return fmt.Errorf("falha ao ler init.sql: %w", err)
	}

	// Executa o schema
	_, err = db.Exec(string(initSQL))
	if err != nil {
		return fmt.Errorf("falha ao executar schema: %w", err)
	}

	return nil
}
