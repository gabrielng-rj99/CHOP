// Licenses-Manager/backend/cmd/tools/main.go

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"Licenses-Manager/backend/database"
	"Licenses-Manager/backend/store"
)

// CreateAdminUser cria um usuário admin com uma senha aleatória.
func main() {
	fmt.Println("Iniciando terminal de ferramentas...")
	db, err := database.ConnectDB()
	if err != nil {
		fmt.Println("Erro ao conectar ao banco de dados:", err)
		return
	}
	defer db.Close()

	userStore := store.NewUserStore(db)

	fmt.Println("=== Ferramentas de Administração ===")
	for {
		fmt.Println("\nEscolha uma função para executar:")
		fmt.Println("1 - Criar usuário admin com senha aleatória")
		// Futuras opções podem ser adicionadas aqui
		fmt.Println("0 - Sair")
		fmt.Print("Opção: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			fmt.Print("Username do admin (deixe vazio para auto gerar admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Display Name do admin: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			fmt.Print("Role do admin (admin/full_admin): ")
			role, _ := reader.ReadString('\n')
			role = strings.TrimSpace(role)
			if role == "" {
				role = "admin"
			}
			genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, role)
			if err != nil {
				fmt.Println("Erro ao criar admin:", err)
			} else {
				fmt.Printf("Usuário admin criado: %s\nDisplay Name: %s\nSenha: %s\n", genUsername, genDisplayName, genPassword)
			}
		case "0":
			fmt.Println("Saindo...")
			return
		default:
			fmt.Println("Opção inválida.")
		}
	}
}
