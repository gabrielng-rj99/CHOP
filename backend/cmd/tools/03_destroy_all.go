package main

import (
	"bufio"
	"fmt"
	"os"
)

// shutdownAll stops all services and optionally removes volumes
func shutdownAllwithVolumes() {
	clearTerminal()
	fmt.Println("=== Derrubar e Apagar Tudo (DESTRUTIVO) ===")
	fmt.Println("⚠️  ATENÇÃO: Este processo irá:")
	fmt.Println("  1. Parar o frontend Web")
	fmt.Println("  2. Parar o servidor HTTP API")
	fmt.Println("  3. Parar e REMOVER o banco de dados com TODOS OS DADOS")
	fmt.Println("\n❌ TODOS OS DADOS SERÃO PERDIDOS PERMANENTEMENTE!")

	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Stop frontend
	clearTerminal()
	fmt.Println("=== [1/3] Parando frontend Web ===")
	stopFrontend()

	// Step 2: Stop server
	fmt.Println("=== [2/3] Parando servidor HTTP API ===")
	stopServer()

	// Step 3: Stop/remove database
	fmt.Println("=== [3/3] Removendo banco de dados e volumes ===")
	DropMainDatabaseWithVolumes()

	// Summary
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║              ✅ APLICAÇÃO REMOVIDA COMPLETAMENTE ✅                        ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  ❌ Todos os serviços foram parados                                        ║")
	fmt.Println("║  ❌ Todos os dados foram removidos permanentemente                         ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  💡 Use a opção 01 para iniciar tudo novamente do zero                     ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
