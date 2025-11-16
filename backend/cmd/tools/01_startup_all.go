package main

import (
	"bufio"
	"fmt"
	"os"
	"time"
)

// startupAll initializes everything: database, server, frontend
func startupAll() {
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              🚀 INICIAR APLICAÇÃO COMPLETA 🚀                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println("\nEste processo irá:")
	fmt.Println("  1. Inicializar o banco de dados principal via Docker")
	fmt.Println("  2. Iniciar o servidor HTTP API (porta 3000)")
	fmt.Println("  3. Iniciar o frontend Web (porta 8080)")
	fmt.Println("\n⏱️  Tempo estimado: 2-3 minutos")
	fmt.Println("⚠️  NÃO FECHE ESTE TERMINAL durante o processo")
	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Initialize database
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [1/3] Inicializando banco de dados principal                              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	InitMainDatabaseDocker()

	// Give database time to fully start
	fmt.Println("\n⏳ Aguardando banco estabilizar...")
	if !waitForPostgresReady("localhost", mainDBPort, 60*time.Second) {
		fmt.Println("❌ Banco principal não ficou pronto no tempo esperado.")
		fmt.Println("\n💡 Sugestões:")
		fmt.Println("  • Verifique a opção 11 para reinicializar o banco")
		fmt.Println("  • Verifique se o Docker está rodando")
		fmt.Println("  • Verifique o status com a opção 93")
		fmt.Print("\nPressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	fmt.Println("✅ Banco de dados principal está pronto!")

	// Step 2: Start server
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [2/3] Iniciando servidor HTTP API                                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	startServer()

	// Step 3: Start frontend
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [3/3] Iniciando frontend Web                                               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	startFrontend()

	// Summary
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    ✅ APLICAÇÃO INICIADA COM SUCESSO ✅                    ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  🗄️  Banco de dados:  contract_manager_postgres (porta 5432)               ║")
	fmt.Println("║  📡 API Backend:      http://localhost:3000                                ║")
	fmt.Println("║  🌐 Frontend Web:     http://localhost:8080                                ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  ⚡ Comandos úteis:                                                        ║")
	fmt.Println("║     • Parar tudo (preservar dados):      opção 02                          ║")
	fmt.Println("║     • Reiniciar serviços:                opção 04                          ║")
	fmt.Println("║     • Verificar status:                  opção 93                          ║")
	fmt.Println("║     • Validação completa:                opção 94                          ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
