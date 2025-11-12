package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

func main() {
	// Limpa o terminal ao iniciar o CLI
	for {
		clearTerminal()
		fmt.Println("=== Ferramentas de Administração ===")
		fmt.Println("\nEscolha uma função para executar:")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                        APLICAÇÃO PRINCIPAL                                 ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 10 - Executar CLI principal (requer banco principal UP)                   ║")
		fmt.Println("║ 12 - Criar usuário admin com senha aleatória (requer banco principal UP)  ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")

		fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                         BANCO PRINCIPAL                                    ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 11 - Inicializar banco principal do zero via Docker                       ║")
		fmt.Println("║ 13 - Derrubar banco principal (parar container)                           ║")
		fmt.Println("║ 19 - Excluir banco principal com dados e volumes (DESTRUTIVO)             ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")

		fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                          BANCO DE TESTES                                   ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 21 - Inicializar banco de testes do zero via Docker                       ║")
		fmt.Println("║ 22 - Rodar testes automatizados (requer banco de testes UP)               ║")
		fmt.Println("║ 23 - Excluir banco de teste (remover dados e volumes)                     ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")

		fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                            DIAGNÓSTICO                                     ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 99 - Validar separação dos bancos de dados                                ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")

		fmt.Println("\n╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║ 00 - Sair                                                                  ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝")
		fmt.Print("\nOpção: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "10":
			LaunchCLI()
		case "11":
			InitMainDatabaseDocker()
		case "12":
			CreateAdminCLI()
		case "13":
			DropMainDatabase()
		case "19":
			DropMainDatabaseWithVolumes()
		case "21":
			InitTestDatabaseDocker()
		case "22":
			RunIntegrationTestsWithDockerPostgres()
		case "23":
			DropTestDatabase()
		case "99":
			ValidateDBSeparation()
		case "0", "00":
			fmt.Println("Saindo...")
			<-time.After(1200 * time.Millisecond)
			clearTerminal()
			return
		default:
			fmt.Println("Opção inválida.")
		}
	}
}
