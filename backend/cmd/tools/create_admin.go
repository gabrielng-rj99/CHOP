// Licenses-Manager/backend/cmd/cli/create_admin.go

package main

import (
	"Licenses-Manager/backend/store"
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// CreateAdminUser cria um usuário admin com senha aleatória de 64 caracteres.
// Imprime a senha gerada no terminal para ser guardada com segurança.
// Use esta função apenas manualmente, nunca em produção ou no fluxo normal do sistema.
func CreateAdminUser(userStore *store.UserStore) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>/?"
	rand.Seed(time.Now().UnixNano())
	password := make([]byte, 64)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}

	// Pergunta o role
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Role do admin (admin/full_admin): ")
	role, _ := reader.ReadString('\n')
	role = strings.TrimSpace(role)
	if role == "" {
		role = "admin"
	}
	id, err := userStore.CreateUser("admin", "Administrador", string(password), role)
	if err != nil {
		fmt.Println("Erro ao criar usuário admin:", err)
		return
	}
	fmt.Println("Usuário admin criado com sucesso!")
	fmt.Printf("Role: %s\n", role)
	fmt.Printf("Senha gerada (guarde com segurança):\n%s\n", string(password))
	fmt.Printf("ID do usuário: %s\n", id)
}
