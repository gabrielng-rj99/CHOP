package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"
)

// UsersMenu handles the users administration menu
func UsersMenu(userStore *store.UserStore, user *domain.User) {
	for {
		clearTerminal()
		fmt.Println("\n--- Users Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all users")
		fmt.Println("2 - Search/Filter users")
		fmt.Println("3 - Select user")
		fmt.Println("4 - Create regular user (admin or full_admin only)")
		fmt.Println("5 - Create admin user (admin or full_admin only)")
		fmt.Println("6 - Create full_admin user (full_admin only)")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			users, err := userStore.ListUsers()
			if err != nil {
				fmt.Println("Error listing users:", err)
				waitForEnter()
				continue
			}
			displayUsersList(users)
			waitForEnter()
		case "2":
			clearTerminal()
			fmt.Println("\n=== Search/Filter Users ===")
			fmt.Print("Enter search term (username or display name): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm == "" {
				fmt.Println("Search term cannot be empty.")
				waitForEnter()
				continue
			}

			users, err := userStore.ListUsers()
			if err != nil {
				fmt.Println("Error listing users:", err)
				waitForEnter()
				continue
			}

			filtered := filterUsers(users, searchTerm)
			displayUsersList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
			fmt.Println("\n=== Select User ===")
			fmt.Print("Search term (or leave empty for all): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			users, err := userStore.ListUsers()
			if err != nil || len(users) == 0 {
				fmt.Println("No users found.")
				waitForEnter()
				continue
			}

			if searchTerm != "" {
				users = filterUsers(users, searchTerm)
			}

			if len(users) == 0 {
				fmt.Println("No users match your search.")
				waitForEnter()
				continue
			}

			displayUsersList(users)
			fmt.Print("\nEnter the number of the user (0 to cancel): ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(users) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			selectedUser := users[idx-1]
			UserSubmenu(&selectedUser, userStore, user)
		case "4":
			clearTerminal()
			// Create regular user (admin or full_admin only)
			if user.Role != "admin" && user.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can create new users.")
				waitForEnter()
				break
			}
			fmt.Print("User's username: ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("User's display name: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			fmt.Print("User's password: ")
			password, _ := reader.ReadString('\n')
			password = strings.TrimSpace(password)
			if username == "" {
				fmt.Println("Error: Username cannot be empty.")
				waitForEnter()
				continue
			}
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				waitForEnter()
				continue
			}
			if password == "" {
				fmt.Println("Error: Password cannot be empty.")
				waitForEnter()
				continue
			}
			id, err := userStore.CreateUser(username, displayName, password, "user")
			if err != nil {
				fmt.Println("Error creating user:", err)
				waitForEnter()
			} else {
				fmt.Printf("User created with ID: %s\n", id)
				waitForEnter()
			}
		case "5":
			clearTerminal()
			// Create admin user (admin or full_admin only)
			if user.Role != "admin" && user.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can create new admins.")
				waitForEnter()
				break
			}
			fmt.Print("Admin username (leave empty to auto-generate admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Admin display name: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				waitForEnter()
				continue
			}
			genID, genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, "admin")
			if err != nil {
				fmt.Println("Error creating admin:", err)
				waitForEnter()
			} else {
				fmt.Printf("Admin user created: %s\nDisplay Name: %s\nPassword: %s\nUser ID: %s\n", genUsername, genDisplayName, genPassword, genID)
				waitForEnter()
			}
		case "6":
			clearTerminal()
			// Create full_admin user (full_admin only)
			if user.Role != "full_admin" {
				fmt.Println("Only full_admin users can create other full_admin users.")
				waitForEnter()
				break
			}
			fmt.Print("Full_admin username (leave empty to auto-generate admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Full_admin display name: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				waitForEnter()
				continue
			}
			genID, genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, "full_admin")
			if err != nil {
				fmt.Println("Error creating full_admin:", err)
				waitForEnter()
			} else {
				fmt.Printf("Full_admin user created: %s\nDisplay Name: %s\nPassword: %s\nUser ID: %s\n", genUsername, genDisplayName, genPassword, genID)
				waitForEnter()
			}

		default:
			fmt.Println("Invalid option.")
		}
	}
}

// displayUsersList shows a compact list of users with essential information
func displayUsersList(users []domain.User) {
	fmt.Println("\n=== Users ===")
	if len(users) == 0 {
		fmt.Println("No users found.")
		return
	}

	fmt.Printf("\n%-4s | %-25s | %-30s | %-15s | %-20s\n", "#", "Username", "Display Name", "Role", "Created At")
	fmt.Println(strings.Repeat("-", 100))

	for i, u := range users {
		username := u.Username
		if len(username) > 25 {
			username = username[:22] + "..."
		}

		displayName := u.DisplayName
		if len(displayName) > 30 {
			displayName = displayName[:27] + "..."
		}

		createdAt := u.CreatedAt.Format("2006-01-02 15:04:05")

		fmt.Printf("%-4d | %-25s | %-30s | %-15s | %-20s\n", i+1, username, displayName, u.Role, createdAt)
	}
	fmt.Println()
}

// filterUsers filters users by username or display name
func filterUsers(users []domain.User, searchTerm string) []domain.User {
	var filtered []domain.User
	searchTerm = normalizeString(searchTerm)

	for _, u := range users {
		if strings.Contains(normalizeString(u.Username), searchTerm) {
			filtered = append(filtered, u)
			continue
		}

		if strings.Contains(normalizeString(u.DisplayName), searchTerm) {
			filtered = append(filtered, u)
			continue
		}
	}

	return filtered
}

// UserSubmenu handles operations for a specific user
func UserSubmenu(selectedUser *domain.User, userStore *store.UserStore, currentUser *domain.User) {
	for {
		clearTerminal()
		fmt.Printf("\n--- User: %s ---\n", selectedUser.Username)
		fmt.Println("0 - Back")
		fmt.Println("1 - Edit username")
		fmt.Println("2 - Edit display name")
		fmt.Println("3 - Edit password")
		fmt.Println("4 - Edit role (full_admin only)")
		fmt.Println("5 - Unlock user (full_admin only)")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			if currentUser.Role != "admin" && currentUser.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can change usernames.")
				waitForEnter()
				continue
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current username: %s | New username: ", selectedUser.Username)
			newUsername, _ := reader.ReadString('\n')
			newUsername = strings.TrimSpace(newUsername)
			if newUsername == "" {
				fmt.Println("Username unchanged.")
				waitForEnter()
				continue
			}
			err := userStore.UpdateUsername(selectedUser.Username, newUsername)
			if err != nil {
				fmt.Println("Error changing username:", err)
				waitForEnter()
			} else {
				fmt.Println("Username changed successfully!")
				selectedUser.Username = newUsername
				waitForEnter()
			}
		case "2":
			clearTerminal()
			PrintOptionalFieldHint()
			fmt.Printf("Current display name: %s | New display name: ", selectedUser.DisplayName)
			newDisplayName, _ := reader.ReadString('\n')
			newDisplayName = strings.TrimSpace(newDisplayName)
			if newDisplayName == "" {
				newDisplayName = selectedUser.DisplayName
			}
			err := userStore.EditUserDisplayName(selectedUser.Username, newDisplayName)
			if err != nil {
				fmt.Println("Error changing display name:", err)
				waitForEnter()
			} else {
				fmt.Println("Display name changed successfully!")
				selectedUser.DisplayName = newDisplayName
				waitForEnter()
			}
		case "3":
			clearTerminal()
			fmt.Print("New password: ")
			newPassword, _ := reader.ReadString('\n')
			newPassword = strings.TrimSpace(newPassword)

			if newPassword == "" {
				fmt.Println("Password cannot be empty.")
				waitForEnter()
				continue
			}

			// Password requirements: min 12 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
			var (
				hasMinLen  = len(newPassword) >= 12
				hasUpper   = false
				hasLower   = false
				hasDigit   = false
				hasSpecial = false
			)
			for _, c := range newPassword {
				switch {
				case c >= 'A' && c <= 'Z':
					hasUpper = true
				case c >= 'a' && c <= 'z':
					hasLower = true
				case c >= '0' && c <= '9':
					hasDigit = true
				case (c >= 33 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126):
					hasSpecial = true
				}
			}
			if !hasMinLen || !hasUpper || !hasLower || !hasDigit || !hasSpecial {
				fmt.Println("Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
				waitForEnter()
				continue
			}

			err := userStore.EditUserPassword(selectedUser.Username, newPassword)
			if err != nil {
				fmt.Println("Error changing password:", err)
				waitForEnter()
			} else {
				fmt.Println("Password changed successfully!")
				waitForEnter()
			}
		case "4":
			clearTerminal()
			if currentUser.Role != "full_admin" {
				fmt.Println("Only full_admin users can change the role of other users.")
				waitForEnter()
				continue
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current role: %s | New role (user/admin/full_admin): ", selectedUser.Role)
			newRole, _ := reader.ReadString('\n')
			newRole = strings.TrimSpace(newRole)
			if newRole == "" {
				newRole = selectedUser.Role
			}
			err := userStore.EditUserRole(currentUser.Username, selectedUser.Username, newRole)
			if err != nil {
				fmt.Println("Error changing role:", err)
				waitForEnter()
			} else {
				fmt.Println("Role changed successfully!")
				selectedUser.Role = newRole
				waitForEnter()
			}
		case "5":
			clearTerminal()
			if currentUser.Role != "full_admin" {
				fmt.Println("Only full_admin users can unlock users.")
				waitForEnter()
				continue
			}
			err := userStore.UnlockUser(selectedUser.Username)
			if err != nil {
				fmt.Println("Error unlocking user:", err)
				waitForEnter()
			} else {
				fmt.Println("User unlocked successfully!")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}
