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
		fmt.Print("\033[H\033[2J")
		fmt.Println("=== Ferramentas de Administração ===")
		fmt.Println("\nEscolha uma função para executar:")

		fmt.Println("----------------------------------------------------------------------------")
		fmt.Println("==== BANCO PRINCIPAL ====")
		fmt.Println("11 - Inicializar banco principal do zero via Docker")
		fmt.Println("12 - Criar usuário admin com senha aleatória")
		fmt.Println("13 - Derrubar banco principal (parar container)")
		fmt.Println("19 - Excluir banco principal com dados e volumes (DESTRUTIVO)")

		fmt.Println("\n----------------------------------------------------------------------------")
		fmt.Println("==== BANCO DE TESTE ====")
		fmt.Println("\n21 - Inicializar banco de testes do zero via Docker")
		fmt.Println("22 - Rodar testes automatizados do projeto com PostgreSQL via Docker Compose")
		fmt.Println("23 - Excluir banco de teste (remover dados e volumes)")

		fmt.Println("\n----------------------------------------------------------------------------")
		fmt.Println("00 - Sair")
		fmt.Println("----------------------------------------------------------------------------")
		fmt.Print("\nOpção: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
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
		case "0", "00":
			fmt.Println("Saindo...")
			<-time.After(1200 * time.Millisecond)
			fmt.Print("\033[H\033[2J")
			return
		default:
			fmt.Println("Opção inválida.")
		}
	}
}
