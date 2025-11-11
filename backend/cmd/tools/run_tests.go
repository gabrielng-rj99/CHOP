package main

import (
	"bufio"
	"fmt"
	"os"
	"time"
)

// RunIntegrationTestsWithDockerPostgres executa todos os testes do projeto usando PostgreSQL via Docker Compose
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
	if !isContainerRunning("contract_manager_postgres_test") {
		fmt.Println("❌ O banco de testes NÃO está inicializado!")
		fmt.Println("Sugestão: Rode a opção 21 antes para inicializar o banco de testes.")
		fmt.Print("Pressione ENTER para voltar ao menu...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	fmt.Println("✓ Banco de testes está rodando!")

	// Aguarda o banco ficar pronto
	fmt.Println("⏳ Aguardando postgres_test ficar pronto...")
	if !waitForPostgresReady("localhost", "65432", 60*time.Second) {
		fmt.Println("❌ postgres_test não ficou pronto no tempo esperado.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ postgres_test está pronto!")

	// Configura variáveis de ambiente
	os.Setenv("POSTGRES_PORT", "65432")
	os.Setenv("POSTGRES_HOST", "localhost")
	os.Setenv("POSTGRES_USER", "postgres")
	os.Setenv("POSTGRES_PASSWORD", "postgres")
	os.Setenv("POSTGRES_DB", "contracts_manager_test")
	os.Setenv("POSTGRES_SSLMODE", "disable")

	// Executa os testes
	fmt.Println("\n▶ Executando testes Go com cobertura...")
	fmt.Println("─────────────────────────────────────────────────────────────")

	runCmd := "cd " + projectRoot + " && go test -v -cover ./..."
	err = runShell(runCmd)

	fmt.Println("─────────────────────────────────────────────────────────────")

	if err != nil {
		fmt.Println("\n⚠ Alguns testes falharam.")
	} else {
		fmt.Println("\n✓ Todos os testes passaram com sucesso!")
	}

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	fmt.Println("\n🛑 Apagando banco de testes...")
	runDockerComposeDownWithVolumes("postgres_test")
	fmt.Println("✓ Banco de testes removido!")
}
