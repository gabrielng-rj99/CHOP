package main

import (
	"bufio"
	"fmt"
	"os"
)

// shutdownAll stops all services without removing data
func shutdownAll() {
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           🛑 PARAR TUDO (SEM APAGAR DADOS) 🛑                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println("\nEste processo irá:")
	fmt.Println("  1. Parar o frontend Web")
	fmt.Println("  2. Parar o servidor HTTP API")
	fmt.Println("  3. Parar o container do banco de dados")
	fmt.Println("\n✅ Os dados serão preservados no volume Docker")
	fmt.Println("✅ Você pode reiniciar com a opção 01 mantendo os dados")

	fmt.Print("\nPressione ENTER para continuar ou CTRL+C para cancelar...")
	bufio.NewReader(os.Stdin).ReadString('\n')

	// Step 1: Stop frontend
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [1/3] Parando frontend Web                                               ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	stopFrontend()

	// Step 2: Stop server
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [2/3] Parando servidor HTTP API                                          ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	stopServer()

	// Step 3: Stop database
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [3/3] Parando banco de dados                                             ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	StopMainDatabase()

	// Summary
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                  ✅ APLICAÇÃO PARADA COM SUCESSO ✅                        ║")
	fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  ✓ Todos os serviços foram parados                                         ║")
	fmt.Println("║  ✓ Os dados foram preservados no volume Docker                             ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("║  ⚡ Próximos passos:                                                       ║")
	fmt.Println("║     • Reiniciar tudo:      opção 01                                        ║")
	fmt.Println("║     • Apagar tudo:         opção 03 (DESTRUTIVO)                           ║")
	fmt.Println("║     • Verificar status:    opção 93                                        ║")
	fmt.Println("║                                                                            ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
