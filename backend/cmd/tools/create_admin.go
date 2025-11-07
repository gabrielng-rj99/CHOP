package main

import (
	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/store"
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"
)

// PrintOptionalFieldHint prints instructions for optional field handling
// This should be called once before displaying Current/New field prompts
func PrintOptionalFieldHint() {
	fmt.Println("(Use '-' to set blank, leave empty to keep current value)")
}

// CreateAdminCLI executa o fluxo de criação de admin via CLI
func CreateAdminCLI() {
	fmt.Print("\033[H\033[2J")

	// Garante que o banco principal está rodando
	db, err := database.ConnectDB()
	if err != nil {
		fmt.Println("Erro ao conectar ao banco de dados:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
	defer func() {
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		db.Close()
	}()

	userStore := store.NewUserStore(db)

	reader := bufio.NewReader(os.Stdin)
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
	genID, genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, role)
	if err != nil {
		fmt.Println("Erro ao criar admin:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	} else {
		fmt.Printf("Usuário admin criado: %s\nDisplay Name: %s\nSenha: %s\nUser ID: %s\n", genUsername, genDisplayName, genPassword, genID)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}
}

// CreateAdminUser creates an admin user with a randomly generated 64-character password.
// Prints the generated password to the terminal to be saved securely.
// Use this function only manually, never in production or in the normal system flow.
func CreateAdminUser(userStore *store.UserStore) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>/?"
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	password := make([]byte, 64)
	for i := range password {
		password[i] = charset[rng.Intn(len(charset))]
	}

	// Ask for the role
	reader := bufio.NewReader(os.Stdin)
	PrintOptionalFieldHint()
	fmt.Print("Admin role (admin/full_admin, leave empty for 'admin'): ")
	role, _ := reader.ReadString('\n')
	role = strings.TrimSpace(role)
	if role == "" {
		role = "admin"
	}

	// Validate role
	if role != "admin" && role != "full_admin" {
		fmt.Println("Error: Invalid role. Use 'admin' or 'full_admin'.")
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	id, err := userStore.CreateUser("admin", "Administrador", string(password), role)
	if err != nil {
		fmt.Println("Error creating admin user:", err)
		fmt.Print("Pressione ENTER para continuar...")
		bufio.NewReader(os.Stdin).ReadString('\n')
		return
	}

	fmt.Println("Admin user created successfully!")
	fmt.Printf("Role: %s\n", role)
	fmt.Printf("Generated password (store it securely):\n%s\n", string(password))
	fmt.Printf("User ID: %s\n", id)
	fmt.Print("Pressione ENTER para continuar...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}
