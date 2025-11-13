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
		fmt.Println("║                      💻  APLICAÇÃO PRINCIPAL  💻                           ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 11 - Executar CLI principal (requer banco principal UP)                    ║")
		fmt.Println("║ 12 - Criar usuário admin com senha aleatória (requer banco principal UP)   ║")
		fmt.Println("║ 13 - Iniciar servidor HTTP API (porta 3000)                                ║")
		fmt.Println("║ 14 - Parar servidor HTTP API                                               ║")
		fmt.Println("║ 15 - Iniciar frontend Web (porta 8080)                                     ║")
		fmt.Println("║ 16 - Parar frontend Web                                                    ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                      🗄️  BANCO PRINCIPAL  🗄️                                 ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 21 - Inicializar banco principal do zero via Docker                        ║")
		fmt.Println("║ 28 - Derrubar banco principal (parar container)                            ║")
		fmt.Println("║ 29 - Excluir banco principal com dados e volumes (DESTRUTIVO)              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                      📝  BANCO DE TESTES  📝                               ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 31 - Inicializar banco de testes do zero via Docker                        ║")
		fmt.Println("║ 39 - Excluir banco de teste (remover dados e volumes)                      ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                       🔍   DIAGNÓSTICO  🔍                                 ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 91 - Rodar testes automatizados (requer banco de testes UP)                ║")
		fmt.Println("║ 92 - Validar separação dos bancos de dados                                 ║")
		fmt.Println("║ 93 - Verificar status dos serviços (HTTP e Frontend)                       ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║ 00 - Sair                                                              ❌  ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
		fmt.Print("Opção: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "11":
			LaunchCLI()
		case "12":
			CreateAdminCLI()
		case "13":
			startServer()
		case "14":
			stopServer()
		case "15":
			startFrontend()
		case "16":
			stopFrontend()
		case "21":
			InitMainDatabaseDocker()
		case "28":
			DropMainDatabase()
		case "29":
			DropMainDatabaseWithVolumes()
		case "31":
			InitTestDatabaseDocker()
		case "39":
			DropTestDatabase()
		case "91":
			RunIntegrationTestsWithDockerPostgres()
		case "92":
			ValidateDBSeparation()
		case "93":
			checkServices()
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
