package main

import (
	"bufio"
	"fmt"
	"os"
)

// restartAll stops and restarts all services (database, server, frontend) without removing data
func restartServer() {
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              🔄 REINICIAR APLICAÇÃO COMPLETA 🔄                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println("\nEste processo irá:")
	fmt.Println("  1. Reiniciar o servidor HTTP API")
	fmt.Println("  2. Reiniciar o frontend Web")
	fmt.Println("\n✓ Todos os dados serão preservados")
	fmt.Println("✓ Perfeito para limpar estado da aplicação")
	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Stop frontend
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [1/4] Parando frontend Web                                                ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	stopFrontend()

	// Step 2: Stop server
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [2/4] Parando servidor HTTP API                                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	stopServer()

	// Step 3: Start server
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [3/4] Reiniciando servidor HTTP API                                      ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	startServer()

	// Step 4: Start frontend
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [4/4] Reiniciando frontend Web                                           ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	startFrontend()

	// Summary
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    ✅ APLICAÇÃO REINICIADA COM SUCESSO ✅                  ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  📡 API Backend:      http://localhost:3000                                ║")
	fmt.Println("║  🌐 Frontend Web:     http://localhost:8080                                ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  ⚡ Comandos úteis:                                                        ║")
	fmt.Println("║     • Parar tudo (preservar dados):      opção 02                          ║")
	fmt.Println("║     • Verificar status:                  opção 93                          ║")
	fmt.Println("║     • Validação completa:                opção 94                          ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
