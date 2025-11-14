package main

import (
	"bufio"
	"fmt"
	"os"
)

// shutdownAll stops all services and optionally removes volumes
func shutdownAll() {
	clearTerminal()
	fmt.Println("=== Derrubar Tudo (Sem Apagar Dados) ===")
	fmt.Println("Este processo irá:")
	fmt.Println("  1. Parar o frontend Web")
	fmt.Println("  2. Parar o servidor HTTP API")
	fmt.Println("  3. Parar o container do banco de dados (dados preservados)")
	fmt.Println("\n✓ Os dados serão preservados e estarão disponíveis no próximo start")

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
	fmt.Println("=== [3/3] Parando container do banco de dados ===")
	DropMainDatabase()

	// Summary
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  ✅ APLICAÇÃO PARADA COM SUCESSO ✅                        ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  ✓ Todos os serviços foram parados                                         ║")
	fmt.Println("║  ✓ Os dados foram preservados no volume Docker                             ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  💡 Use a opção 01 para iniciar tudo novamente (dados preservados)         ║")
	fmt.Println("║  💡 Use a opção 03 se quiser remover todos os dados                        ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
