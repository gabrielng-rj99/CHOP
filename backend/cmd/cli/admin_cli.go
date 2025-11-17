package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	domain "Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"
)

// AdministrationFlow handles the administration menu and routes to subcategories
func AdministrationFlow(categoryStore *store.CategoryStore, lineStore *store.LineStore, userStore *store.UserStore, user *domain.User) {
	for {
		clearTerminal()
		fmt.Println("\n--- Administration ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - Categories")
		fmt.Println("2 - Lines")
		fmt.Println("3 - Users")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			CategoriesMenu(categoryStore, lineStore)
		case "2":
			LinesMenu(lineStore, categoryStore)
		case "3":
			UsersMenu(userStore, user)
		default:
			fmt.Println("Invalid option.")
		}
	}
}
