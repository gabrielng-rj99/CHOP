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
		fmt.Println("║                      💻 INICIALIZAR APLICAÇÃO 💻                           ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 10 - Executar CLI principal (requer banco principal UP)                    ║")
		fmt.Println("║ 11 - Inicializar banco principal do zero via Docker                        ║")
		fmt.Println("║ 12 - Iniciar servidor HTTP API (porta 3000)                                ║")
		fmt.Println("║ 13 - Iniciar frontend Web (porta 8080)                                     ║")
		fmt.Println("║ 19 - Criar usuário admin com senha aleatória (requer banco principal UP)   ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                      🗄️  PARAR APLICAÇÃO  🗄️                                 ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 21 - Derrubar banco principal (parar container)                            ║")
		fmt.Println("║ 22 - Parar servidor HTTP API                                               ║")
		fmt.Println("║ 23 - Parar frontend Web                                                    ║")
		fmt.Println("║ 29 - Excluir banco principal com dados e volumes (DESTRUTIVO)              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                      📝  STACK DE TESTES  📝                               ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 31 - Inicializar banco de testes do zero via Docker                        ║")
		fmt.Println("║ 32 - Rodar testes (requer banco de testes UP, e o remove no final)         ║")
		fmt.Println("║ 39 - Excluir banco de teste (remover dados e volumes)                      ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║                       🔍    VALIDAÇÃO   🔍                                 ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║ 32 - Rodar testes (requer banco de testes UP, e o remove no final)         ║")
		fmt.Println("║ 91 - Validar separação dos bancos de dados                                 ║")
		fmt.Println("║ 92 - Verificar status dos serviços (HTTP e Frontend)                       ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")

		fmt.Println("╔════════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║ 00 - Sair                                                              ❌  ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════════╝\n ")
		fmt.Print("Opção: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "10":
			LaunchCLI()
		case "11":
			InitMainDatabaseDocker()
		case "12":
			startServer()
		case "13":
			startFrontend()
		case "19":
			CreateAdminCLI()
		case "21":
			DropMainDatabase()
		case "22":
			stopServer()
		case "23":
			stopFrontend()
		case "29":
			DropMainDatabaseWithVolumes()
		case "31":
			InitTestDatabaseDocker()
		case "32":
			RunIntegrationTestsWithDockerPostgres()
		case "39":
			DropTestDatabase()
		case "91":
			ValidateDBSeparation()
		case "92":
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
