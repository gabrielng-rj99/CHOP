package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// RunIntegrationTestsWithDockerPostgres executa todos os testes do projeto usando PostgreSQL via Docker Compose
// Utiliza um serviço separado na porta 65432 para não interferir com o banco principal
func RunIntegrationTestsWithDockerPostgres() {
	fmt.Println("\n=== Testes de Integração com PostgreSQL (porta 65432) ===")

	projectRoot, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Erro ao determinar raiz do projeto:", err)
		return
	}
	dockerComposePath := filepath.Join(projectRoot, "database", "docker-compose.yml")

	// Verifica se o container de teste já está rodando
	if isContainerRunning("contract_manager_postgres_test") {
		fmt.Println("ℹ Container postgres_test já está rodando. Aguardando ficar pronto...")
	} else {
		fmt.Println("▶ Iniciando serviço postgres_test (porta 65432)...")
		cmdUp := exec.Command("docker", "compose", "-f", dockerComposePath, "up", "-d", "postgres_test")
		cmdUp.Stdout = os.Stdout
		cmdUp.Stderr = os.Stderr
		if err := cmdUp.Run(); err != nil {
			fmt.Println("❌ Erro ao subir serviço postgres_test:", err)
			return
		}
	}

	// Aguarda o banco ficar pronto
	fmt.Println("⏳ Aguardando postgres_test ficar pronto...")
	if !waitForPostgresTestReady(60 * time.Second) {
		fmt.Println("❌ postgres_test não ficou pronto no tempo esperado.")
		stopTestContainer(dockerComposePath)
		return
	}
	fmt.Println("✓ postgres_test está pronto!")

	// Inicializa o schema do banco de testes
	fmt.Println("▶ Inicializando schema do banco de testes...")
	initPath := filepath.Join(projectRoot, "database", "init.sql")
	if err := initializeTestDatabase(initPath); err != nil {
		fmt.Println("❌ Erro ao inicializar schema:", err)
		stopTestContainer(dockerComposePath)
		return
	}
	fmt.Println("✓ Schema inicializado!")

	// Executa os testes
	fmt.Println("\n▶ Executando testes Go com cobertura...")
	fmt.Println("─────────────────────────────────────────────────────────────")

	backendPath := filepath.Join(projectRoot, "backend")
	os.Setenv("POSTGRES_PORT", "65432")

	testCmd := exec.Command("go", "test", "-v", "-cover", "./...")
	testCmd.Dir = backendPath
	testCmd.Stdout = os.Stdout
	testCmd.Stderr = os.Stderr
	testCmd.Stdin = os.Stdin

	err = testCmd.Run()

	fmt.Println("─────────────────────────────────────────────────────────────")

	if err != nil {
		fmt.Println("\n⚠ Alguns testes falharam.")
	} else {
		fmt.Println("\n✓ Todos os testes passaram com sucesso!")
	}

	stopTestContainer(dockerComposePath)
	fmt.Println("\n✓ Ambiente de testes finalizado e limpo!")
}

// stopTestContainer para o serviço de teste
func stopTestContainer(dockerComposePath string) {
	fmt.Println("\n▶ Encerrando serviço postgres_test...")
	cmdStop := exec.Command("docker", "compose", "-f", dockerComposePath, "stop", "postgres_test")
	cmdStop.Stdout = os.Stdout
	cmdStop.Stderr = os.Stderr
	if err := cmdStop.Run(); err != nil {
		fmt.Println("⚠ Erro ao parar postgres_test:", err)
	}
}

// waitForPostgresTestReady aguarda que o PostgreSQL de testes (porta 65432) esteja pronto
func waitForPostgresTestReady(maxWaitTime time.Duration) bool {
	start := time.Now()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	dsn := "postgres://postgres:postgres@localhost:65432/contracts_manager_test?sslmode=disable"

	for {
		if isPostgresTestReady(dsn) {
			return true
		}

		if time.Since(start) > maxWaitTime {
			return false
		}

		<-ticker.C
	}
}

// isPostgresTestReady tenta conectar ao PostgreSQL de testes
func isPostgresTestReady(dsn string) bool {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return false
	}
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	return err == nil
}

// initializeTestDatabase executa o schema de inicialização no banco de testes
func initializeTestDatabase(initPath string) error {
	dsn := "postgres://postgres:postgres@localhost:65432/contracts_manager_test?sslmode=disable"
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
