package main

import (
	"bufio"
	"fmt"
	"os"
)

// fullSystemValidation executes validations 92 and 93 in sequence
func fullSystemValidation() {
	clearTerminal()
	fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║           VALIDACAO COMPLETA DO SISTEMA                                   ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
	fmt.Println("\nEste processo irá executar:")
	fmt.Println("  1. Validação de separação dos bancos de dados")
	fmt.Println("  2. Verificação de status dos serviços (HTTP e Frontend)")

	// Step 1: Validate DB Separation
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [1/2] Validando separação de bancos de dados                              ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	simulateEnterForNextFunction(ValidateDBSeparation)

	// Step 2: Check Services Status
	fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║ [2/2] Verificando status dos serviços                                      ║")
	fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
	simulateEnterForNextFunction(checkServices)

	fmt.Print("\nPressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
