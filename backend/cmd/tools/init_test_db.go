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

// Configurações do banco de testes
const (
	testDBName     = "contracts_manager_test"
	testDBUser     = "postgres"
	testDBPassword = "postgres"
	testDBPort     = "65432"
	testContainer  = "contract_manager_postgres_test"
)

// Exclui o banco de dados de teste, derruba o container e recria tudo do zero
func InitTestDatabaseDocker() {
	clearTerminal()
	projectRoot, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Erro ao determinar raiz do projeto:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	initSQLPath := filepath.Join(projectRoot, "database", "init.sql")

	// Derruba o container de teste se estiver rodando
	if isContainerRunning(testContainer) {
		fmt.Println("▶ Parando container de teste...")
		if err := runDockerComposeDown(); err != nil {
			fmt.Println("❌ Erro ao derrubar container:", err)
			fmt.Print("Pressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	// Sobe o container de teste
	fmt.Println("▶ Subindo container de teste...")
	if err := runDockerComposeUp("postgres_test"); err != nil {
		fmt.Println("❌ Erro ao subir container de teste:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Aguarda o banco ficar pronto
	fmt.Println("⏳ Aguardando postgres_test ficar pronto...")
	if !waitForPostgresReady("localhost", testDBPort, 60*time.Second) {
		fmt.Println("❌ postgres_test não ficou pronto no tempo esperado.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ postgres_test está pronto!")

	// Exclui e recria o banco de teste
	if err := dropAndCreateTestDB(); err != nil {
		fmt.Println("❌ Erro ao recriar banco de teste:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Banco de teste recriado!")

	// Inicializa o schema do banco de testes
	fmt.Println("▶ Inicializando schema do banco de testes...")
	if err := initializeTestDatabase(initSQLPath); err != nil {
		fmt.Println("❌ Erro ao inicializar schema:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Schema inicializado!")
	fmt.Print("Pressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// dropAndCreateTestDB exclui e recria o banco de dados de teste
func dropAndCreateTestDB() error {
	dsn := fmt.Sprintf("postgres://%s:%s@localhost:%s/postgres?sslmode=disable", testDBUser, testDBPassword, testDBPort)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("falha ao conectar ao postgres: %w", err)
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Termina conexões existentes
	_, _ = db.ExecContext(ctx, fmt.Sprintf(
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '%s';", testDBName))

	// Drop database
	_, _ = db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s;", testDBName))

	// Create database
	_, err = db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE %s;", testDBName))
	if err != nil {
		return fmt.Errorf("falha ao criar banco de teste: %w", err)
	}
	return nil
}

// initializeTestDatabase executa o schema de inicialização no banco de testes
func initializeTestDatabase(initPath string) error {
	dsn := fmt.Sprintf("postgres://%s:%s@localhost:%s/%s?sslmode=disable", testDBUser, testDBPassword, testDBPort, testDBName)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("falha ao conectar ao banco de testes: %w", err)
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

// Funções utilitárias são importadas de utils.go
