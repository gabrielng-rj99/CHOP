package main

import (
	"bufio"
	"fmt"
	"os"
	"time"
)

// startupAll initializes everything: database, server, frontend, and creates an admin user
func startupAll() {
	clearTerminal()
	fmt.Println("=== Iniciar Aplicação Completa ===")
	fmt.Println("Este processo irá:")
	fmt.Println("  1. Inicializar o banco de dados principal via Docker")
	fmt.Println("  2. Iniciar o servidor HTTP API (porta 3000)")
	fmt.Println("  3. Iniciar o frontend Web (porta 8080)")
	fmt.Println("\n⚠️  Este processo pode levar alguns minutos...")
	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Initialize database
	clearTerminal()
	fmt.Println("=== [1/4] Inicializando banco de dados principal ===")
	InitMainDatabaseDocker()

	// Give database time to fully start
	fmt.Println("\n⏳ Aguardando banco estabilizar...")
	if !waitForPostgresReady("localhost", mainDBPort, 60*time.Second) {
		fmt.Println("❌ Banco principal não ficou pronto no tempo esperado.")
		fmt.Println("\nSugestão: Verifique a opção 11 ou verifique o status do Docker.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✓ Banco de dados principal está pronto!")

	// Step 2: Start server
	fmt.Println("=== [2/4] Iniciando servidor HTTP API ===")
	startServer()

	// Step 3: Start frontend
	fmt.Println("=== [3/4] Iniciando frontend Web ===")
	startFrontend()

	// Summary
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    ✅ APLICAÇÃO INICIADA COM SUCESSO ✅                    ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  🗄️  Banco de dados:  contract_manager_postgres (porta 5432)               ║")
	fmt.Println("║  📡 API Backend:      http://localhost:3000                                ║")
	fmt.Println("║  🌐 Frontend Web:     http://localhost:8080                                 ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  💡 Use a opção 02 para parar todos os serviços                            ║")
	fmt.Println("║  💡 Use a opção 93 para verificar o status dos serviços                    ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
