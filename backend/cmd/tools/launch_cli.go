package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// LaunchCLI launches the main CLI application
func LaunchCLI() {
	clearTerminal()

	// Verifica se o banco principal está rodando
	if !isContainerRunning("contract_manager_postgres") {
		fmt.Println("❌ O banco de dados principal NÃO está inicializado!")
		fmt.Println("\nSugestão: Execute a opção 11 primeiro para inicializar o banco principal via Docker.")
		fmt.Println("\nOpção 11: Inicializar banco principal do zero via Docker")
		fmt.Print("\nPressione ENTER para voltar ao menu...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	fmt.Println("✓ Banco de dados principal está rodando!")
	fmt.Println("⏳ Aguardando postgres ficar pronto...")
	if !waitForPostgresReady("localhost", "5432", 30*time.Second) {
		fmt.Println("❌ Banco de dados não ficou pronto no tempo esperado.")
		fmt.Println("\nSugestão: Verifique a opção 11 ou verifique o status do Docker.")
		fmt.Print("Pressione ENTER para voltar ao menu...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Banco de dados está pronto!\n ")

	fmt.Println("▶ Iniciando CLI principal...")
	fmt.Println("─────────────────────────────────────────────────────────────\n ")

	// Get current working directory (should be backend directory)
	backendDir, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Erro ao determinar diretório de trabalho:", err)
		fmt.Print("\nPressione ENTER para voltar ao menu...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	// Execute: go run ./cmd/cli
	cmd := exec.Command("go", "run", "./cmd/cli")
	cmd.Dir = backendDir
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println("\n❌ Erro ao executar CLI:", err)
	}

	fmt.Println("\n─────────────────────────────────────────────────────────────")
	fmt.Print("Pressione ENTER para voltar ao menu...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
