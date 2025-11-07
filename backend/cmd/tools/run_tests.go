package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RunIntegrationTestsWithDockerPostgres executa todos os testes do projeto usando PostgreSQL via Docker Compose
// Utiliza um serviço separado na porta 65432 para não interferir com o banco principal
func RunIntegrationTestsWithDockerPostgres() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("\n=== Testes de Integração com PostgreSQL (porta 65432) ===")

	projectRoot, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Erro ao determinar raiz do projeto:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Verifica se o container de teste já está rodando
	if isContainerRunning("contract_manager_postgres_test") {
		fmt.Println("ℹ Container postgres_test já está rodando. Aguardando ficar pronto...")
	} else {
		fmt.Println("▶ Iniciando serviço postgres_test (porta 65432)...")
		if err := runDockerComposeUp("postgres_test"); err != nil {
			fmt.Println("❌ Erro ao subir serviço postgres_test:", err)
			fmt.Print("Pressione ENTER para continuar...")
			bufio.NewReader(os.Stdin).ReadString('\n')
			return
		}
	}

	// Aguarda o banco ficar pronto
	fmt.Println("⏳ Aguardando postgres_test ficar pronto...")
	if !waitForPostgresReady("localhost", "65432", 60*time.Second) {
		fmt.Println("❌ postgres_test não ficou pronto no tempo esperado.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		runDockerComposeStop("postgres_test")
		return
	}
	fmt.Println("✓ postgres_test está pronto!")

	// Executa os testes
	fmt.Println("\n▶ Executando testes Go com cobertura...")
	fmt.Println("─────────────────────────────────────────────────────────────")

	backendPath := filepath.Join(projectRoot, "backend")
	os.Setenv("POSTGRES_PORT", "65432")

	runCmd := fmt.Sprintf("cd %s && go test -v -cover ./...", backendPath)
	if err := runShell(runCmd); err != nil {
		fmt.Println("\n⚠ Alguns testes falharam.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	} else {
		fmt.Println("\n✓ Todos os testes passaram com sucesso!")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
	}

	runDockerComposeStop("postgres_test")
	fmt.Println("\n✓ Ambiente de testes finalizado e limpo!")
}

// Funções utilitárias agora estão em utils.go
// runShell executa um comando shell simples
func runShell(cmd string) error {
	return nil // implemente conforme necessário
}
