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
		fmt.Println("\n--- Users ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List users")
		fmt.Println("2 - Create regular user (admin or full_admin only)")
		fmt.Println("3 - Create admin user (admin or full_admin only)")
		fmt.Println("4 - Create full_admin user (full_admin only)")
		fmt.Println("5 - Change display name")
		fmt.Println("6 - Change password")
		fmt.Println("7 - Change your own username (admin or full_admin only)")
		fmt.Println("8 - Change user role (full_admin only)")
		fmt.Println("9 - Unlock user (full_admin only)")
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
			fmt.Println("Registered users:")
			for i, u := range users {
				fmt.Printf("%d - Username: %s | Display Name: %s | Role: %s | Created at: %s\n", i+1, u.Username, u.DisplayName, u.Role, u.CreatedAt.Format("2006-01-02 15:04:05"))
			}
			waitForEnter()
		case "2":
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
		case "3":
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
		case "4":
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
		case "5":
			clearTerminal()
			// Change your display name
			PrintOptionalFieldHint()
			fmt.Printf("Current display name: %s | New display name: ", user.DisplayName)
			newDisplayName, _ := reader.ReadString('\n')
			newDisplayName = strings.TrimSpace(newDisplayName)
			if newDisplayName == "" {
				newDisplayName = user.DisplayName
			}
			err := userStore.EditUserDisplayName(user.Username, newDisplayName)
			if err != nil {
				fmt.Println("Error changing display name:", err)
				waitForEnter()
			} else {
				fmt.Println("Display name changed successfully!")
				waitForEnter()
			}
		case "6":
			clearTerminal()
			// Change your password
			PrintOptionalFieldHint()
			fmt.Print("New password (leave empty to keep current): ")
			newPassword, _ := reader.ReadString('\n')
			newPassword = strings.TrimSpace(newPassword)

			if newPassword == "" {
				fmt.Println("Password unchanged.")
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
				fmt.Println("Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.")
				waitForEnter()
				break
			}

			err := userStore.EditUserPassword(user.Username, newPassword)
			if err != nil {
				fmt.Println("Error changing password:", err)
				waitForEnter()
			} else {
				fmt.Println("Password changed successfully!")
				waitForEnter()
			}
		case "7":
			clearTerminal()
			// Change your own username (admin or full_admin only)
			if user.Role != "admin" && user.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can change their own username.")
				waitForEnter()
				break
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current username: %s | New username: ", user.Username)
			newUsername, _ := reader.ReadString('\n')
			newUsername = strings.TrimSpace(newUsername)
			if newUsername == "" {
				fmt.Println("Username unchanged.")
				waitForEnter()
				continue
			}
			err := userStore.UpdateUsername(user.Username, newUsername)
			if err != nil {
				fmt.Println("Error changing your username:", err)
				waitForEnter()
			} else {
				fmt.Println("Your username was changed successfully! Please log in again with your new username.")
				waitForEnter()
				return
			}
		case "8":
			clearTerminal()
			// Change user role (full_admin only)
			if user.Role != "full_admin" {
				fmt.Println("Only full_admin users can change the role of other users.")
				waitForEnter()
				break
			}
			users, err := userStore.ListUsers()
			if err != nil || len(users) == 0 {
				fmt.Println("No users found.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a user to change role by number:")
			for i, u := range users {
				fmt.Printf("%d - Username: %s | Display Name: %s | Role: %s\n", i+1, u.Username, u.DisplayName, u.Role)
			}
			fmt.Print("Enter the number of the user: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(users) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			targetUsername := users[idx-1].Username
			targetUser := users[idx-1]
			PrintOptionalFieldHint()
			fmt.Printf("Current role: %s | New role (user/admin/full_admin): ", targetUser.Role)
			newRole, _ := reader.ReadString('\n')
			newRole = strings.TrimSpace(newRole)
			if targetUsername == "" {
				fmt.Println("Error: Target username cannot be empty.")
				waitForEnter()
				continue
			}
			if newRole == "" {
				newRole = targetUser.Role
			}
			err = userStore.EditUserRole(user.Username, targetUsername, newRole)
			if err != nil {
				fmt.Println("Error changing role:", err)
				waitForEnter()
			} else {
				fmt.Println("Role changed successfully!")
				waitForEnter()
			}
		case "9":
			clearTerminal()
			// Unlock user (full_admin only)
			if user.Role != "full_admin" {
				fmt.Println("Only full_admin users can unlock users.")
				waitForEnter()
				break
			}
			users, err := userStore.ListUsers()
			if err != nil || len(users) == 0 {
				fmt.Println("No users found.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a user to unlock by number:")
			for i, u := range users {
				fmt.Printf("%d - Username: %s | Display Name: %s | Role: %s\n", i+1, u.Username, u.DisplayName, u.Role)
			}
			fmt.Print("Enter the number of the user: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(users) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			targetUsername := users[idx-1].Username
			if targetUsername == "" {
				fmt.Println("Error: Target username cannot be empty.")
				waitForEnter()
				continue
			}
			err = userStore.UnlockUser(targetUsername)
			if err != nil {
				fmt.Println("Error unlocking user:", err)
				waitForEnter()
			} else {
				fmt.Println("User unlocked successfully!")
				waitForEnter()
			}
		case "10":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}
