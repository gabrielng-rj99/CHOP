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
	fmt.Println("  4. Criar um usuário admin com senha aleatória")
	fmt.Println("\n⚠️  Este processo pode levar alguns minutos...")
	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Initialize database
	clearTerminal()
	fmt.Println("=== [1/4] Inicializando banco de dados principal ===")
	InitMainDatabaseDocker()

	// Give database time to fully start
	fmt.Println("\n⏳ Aguardando banco estabilizar...")
	time.Sleep(3 * time.Second)

	// Step 2: Start server
	clearTerminal()
	fmt.Println("=== [2/4] Iniciando servidor HTTP API ===")
	startServer()

	// Step 3: Start frontend
	clearTerminal()
	fmt.Println("=== [3/4] Iniciando frontend Web ===")
	startFrontend()

	// Step 4: Create admin user
	clearTerminal()
	fmt.Println("=== [4/4] Criando usuário admin ===")
	CreateAdminCLI()

	// Summary
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    ✅ APLICAÇÃO INICIADA COM SUCESSO ✅                      ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  🗄️  Banco de dados:  contract_manager_postgres (porta 5432)               ║")
	fmt.Println("║  📡 API Backend:      http://localhost:3000                                ║")
	fmt.Println("║  🌐 Frontend Web:     http://localhost:8080                                ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  💡 Use a opção 02 para parar todos os serviços                           ║")
	fmt.Println("║  💡 Use a opção 93 para verificar o status dos serviços                   ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// shutdownAll stops all services and optionally removes volumes
func shutdownAll(removeVolumes bool) {
	clearTerminal()
	if removeVolumes {
		fmt.Println("=== Derrubar e Apagar Tudo (DESTRUTIVO) ===")
		fmt.Println("⚠️  ATENÇÃO: Este processo irá:")
		fmt.Println("  1. Parar o frontend Web")
		fmt.Println("  2. Parar o servidor HTTP API")
		fmt.Println("  3. Parar e REMOVER o banco de dados com TODOS OS DADOS")
		fmt.Println("\n❌ TODOS OS DADOS SERÃO PERDIDOS PERMANENTEMENTE!")
	} else {
		fmt.Println("=== Derrubar Tudo (Sem Apagar Dados) ===")
		fmt.Println("Este processo irá:")
		fmt.Println("  1. Parar o frontend Web")
		fmt.Println("  2. Parar o servidor HTTP API")
		fmt.Println("  3. Parar o container do banco de dados (dados preservados)")
		fmt.Println("\n✓ Os dados serão preservados e estarão disponíveis no próximo start")
	}

	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Stop frontend
	clearTerminal()
	fmt.Println("=== [1/3] Parando frontend Web ===")
	stopFrontend()

	// Step 2: Stop server
	clearTerminal()
	fmt.Println("=== [2/3] Parando servidor HTTP API ===")
	stopServer()

	// Step 3: Stop/remove database
	clearTerminal()
	if removeVolumes {
		fmt.Println("=== [3/3] Removendo banco de dados e volumes ===")
		DropMainDatabaseWithVolumes()
	} else {
		fmt.Println("=== [3/3] Parando container do banco de dados ===")
		DropMainDatabase()
	}

	// Summary
	clearTerminal()
	if removeVolumes {
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║              ✅ APLICAÇÃO REMOVIDA COMPLETAMENTE ✅                         ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                                                                            ║")
		fmt.Println("║  ❌ Todos os serviços foram parados                                        ║")
		fmt.Println("║  ❌ Todos os dados foram removidos permanentemente                         ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║  💡 Use a opção 01 para iniciar tudo novamente do zero                    ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	} else {
		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                  ✅ APLICAÇÃO PARADA COM SUCESSO ✅                         ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║                                                                            ║")
		fmt.Println("║  ✓ Todos os serviços foram parados                                        ║")
		fmt.Println("║  ✓ Os dados foram preservados no volume Docker                           ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("║  💡 Use a opção 01 para iniciar tudo novamente (dados preservados)        ║")
		fmt.Println("║  💡 Use a opção 03 se quiser remover todos os dados                       ║")
		fmt.Println("║                                                                            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	}
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
