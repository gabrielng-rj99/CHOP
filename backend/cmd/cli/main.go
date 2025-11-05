package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/store"
)

func main() {
	db, err := database.ConnectDB()
	if err != nil {
		fmt.Println("Error connecting to the database:", err)
		return
	}
	defer db.Close()

	userStore := store.NewUserStore(db)
	clientStore := store.NewClientStore(db)
	contractStore := store.NewContractStore(db)
	dependentStore := store.NewDependentStore(db)
	categoryStore := store.NewCategoryStore(db)
	lineStore := store.NewLineStore(db)

	fmt.Println("=== contracts Manager CLI ===")
	fmt.Println("Lista de usuários no banco:")
	rows, err := db.Query("SELECT id, username, display_name FROM users")
	if err != nil {
		fmt.Println("Erro ao consultar usuários:", err)
	} else {
		for rows.Next() {
			var id, username, displayName string
			if err := rows.Scan(&id, &username, &displayName); err == nil {
				fmt.Printf("ID: %s | Username: %s | Display Name: %s\n", id, username, displayName)
			}
		}
		rows.Close()
	}
	fmt.Println("Please log in to continue.")

	username, password := promptLogin()
	fmt.Printf("Tentando login com username: '%s'\n", username)
	user, err := userStore.AuthenticateUser(username, password)
	if err != nil {
		fmt.Println("Login failed:", err)
		return
	}
	fmt.Printf("Welcome, %s!\n\n", user.DisplayName)

	for {
		switch mainMenu() {
		case "1":
			ClientsFlow(clientStore, dependentStore, contractStore, lineStore, categoryStore)
		case "2":
			ContractsFlow(contractStore, clientStore, dependentStore, lineStore, categoryStore)
		case "3":
			AdministrationFlow(categoryStore, lineStore, userStore, user)
		case "4":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// promptLogin prompts the user for username and password
func promptLogin() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Password: ")
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

// mainMenu displays the main menu options
func mainMenu() string {
	fmt.Println("Select an option:")
	fmt.Println("1 - Clients")
	fmt.Println("2 - contracts (overview)")
	fmt.Println("3 - Administration (categories, lines, users)")
	fmt.Println("4 - Exit")
	fmt.Print("Option: ")
	reader := bufio.NewReader(os.Stdin)
	opt, _ := reader.ReadString('\n')
	return strings.TrimSpace(opt)
}
