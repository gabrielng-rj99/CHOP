package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"Contracts-Manager/backend/domain"
	"Contracts-Manager/backend/store"
)

// Helper functions to safely dereference user pointer fields
func getUsername(u *domain.User) string {
	if u.Username == nil {
		return ""
	}
	return *u.Username
}

func getDisplayName(u *domain.User) string {
	if u.DisplayName == nil {
		return ""
	}
	return *u.DisplayName
}

func getRole(u *domain.User) string {
	if u.Role == nil {
		return ""
	}
	return *u.Role
}

// UsersMenu handles the users administration menu
func UsersMenu(userStore *store.UserStore, user *domain.User) {
	for {
		clearTerminal()
		fmt.Println("\n--- Users Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all users")
		fmt.Println("2 - Search/Filter users")
		fmt.Println("3 - Select user")
		fmt.Println("4 - Create regular user (admin or root only)")
		fmt.Println("5 - Create admin user (admin or root only)")
		fmt.Println("6 - Create root user (root only)")
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
			// Create regular user (admin or root only)
			if getRole(user) != "admin" && getRole(user) != "root" {
				fmt.Println("Only admin or root users can create new users.")
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
			// Create admin user (admin or root only)
			if getRole(user) != "admin" && getRole(user) != "root" {
				fmt.Println("Only admin or root users can create new admins.")
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
			// Create root user (root only)
			if getRole(user) != "root" {
				fmt.Println("Only root users can create other root users.")
				waitForEnter()
				break
			}
			fmt.Print("Root username (leave empty to auto-generate admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Root display name: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				waitForEnter()
				continue
			}
			genID, genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, "root")
			if err != nil {
				fmt.Println("Error creating root:", err)
				waitForEnter()
			} else {
				fmt.Printf("Root user created: %s\nDisplay Name: %s\nPassword: %s\nUser ID: %s\n", genUsername, genDisplayName, genPassword, genID)
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

	fmt.Printf("\n%-4s | %-25s | %-30s | %-15s | %-20s | %-12s | %-10s\n", "#", "Username", "Display Name", "Role", "Created At", "Deleted", "Status")
	fmt.Println(strings.Repeat("-", 126))

	for i, u := range users {
		username := getUsername(&u)
		if len(username) == 0 {
			username = "(vazio)"
		}
		if len(username) > 25 {
			username = username[:22] + "..."
		}

		displayName := getDisplayName(&u)
		if len(displayName) == 0 {
			displayName = "(vazio)"
		}
		if len(displayName) > 30 {
			displayName = displayName[:27] + "..."
		}

		role := getRole(&u)
		if len(role) == 0 {
			role = "(vazio)"
		}

		createdAt := u.CreatedAt.Format("2006-01-02 15:04:05")

		// Status de bloqueio
		status := "Ativo"
		if u.LockLevel >= 3 && u.LockedUntil != nil && u.LockedUntil.After(time.Now()) {
			status = "Bloqueado"
		}
		if u.DeletedAt != nil {
			status = "Deletado"
		}

		deleted := ""
		if u.DeletedAt != nil {
			deleted = u.DeletedAt.Format("2006-01-02 15:04:05")
		} else {
			deleted = "-"
		}

		fmt.Printf("%-4d | %-25s | %-30s | %-15s | %-20s | %-12s | %-10s\n", i+1, username, displayName, role, createdAt, deleted, status)
	}
	fmt.Println()
}

// filterUsers filters users by username or display name
func filterUsers(users []domain.User, searchTerm string) []domain.User {
	var filtered []domain.User
	searchTerm = normalizeString(searchTerm)

	for _, u := range users {
		username := getUsername(&u)
		displayName := getDisplayName(&u)

		if strings.Contains(normalizeString(username), searchTerm) {
			filtered = append(filtered, u)
			continue
		}

		if strings.Contains(normalizeString(displayName), searchTerm) {
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
		fmt.Printf("\n--- User: %s ---\n", getUsername(selectedUser))
		if selectedUser.DeletedAt != nil {
			fmt.Println("⚠️  This user is deleted (soft-delete). Most operations are disabled.")
		}
		fmt.Println("0 - Back")
		fmt.Println("1 - Edit username")
		fmt.Println("2 - Edit display name")
		fmt.Println("3 - Edit password")
		fmt.Println("4 - Edit role (root only)")
		fmt.Println("5 - Unlock user (root only)")
		fmt.Println("6 - Block user (root only)")
		fmt.Println("7 - Delete user (soft-delete, admin/root only)")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("Cannot edit deleted user.")
				waitForEnter()
				continue
			}
			if getRole(currentUser) != "admin" && getRole(currentUser) != "root" {
				fmt.Println("Only admin or root users can change usernames.")
				waitForEnter()
				continue
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current username: %s | New username: ", getUsername(selectedUser))
			newUsername, _ := reader.ReadString('\n')
			newUsername = strings.TrimSpace(newUsername)
			if newUsername == "" {
				fmt.Println("Username unchanged.")
				waitForEnter()
				continue
			}
			err := userStore.UpdateUsername(getUsername(selectedUser), newUsername)
			if err != nil {
				fmt.Println("Error changing username:", err)
				waitForEnter()
			} else {
				fmt.Println("Username changed successfully!")
				selectedUser.Username = &newUsername
				waitForEnter()
			}
		case "2":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("Cannot edit deleted user.")
				waitForEnter()
				continue
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current display name: %s | New display name: ", getDisplayName(selectedUser))
			newDisplayName, _ := reader.ReadString('\n')
			newDisplayName = strings.TrimSpace(newDisplayName)
			if newDisplayName == "" {
				newDisplayName = getDisplayName(selectedUser)
			}
			if err := userStore.EditUserDisplayName(getUsername(selectedUser), newDisplayName); err != nil {
				fmt.Println("Error changing display name:", err)
				waitForEnter()
			} else {
				fmt.Println("Display name changed successfully!")
				selectedUser.DisplayName = &newDisplayName
				waitForEnter()
			}
		case "3":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("Cannot edit deleted user.")
				waitForEnter()
				continue
			}
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

			if err := userStore.EditUserPassword(getUsername(selectedUser), newPassword); err != nil {
				fmt.Println("Error changing password:", err)
				waitForEnter()
			} else {
				fmt.Println("Password changed successfully!")
				waitForEnter()
			}
		case "4":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("Cannot edit deleted user.")
				waitForEnter()
				continue
			}
			if getRole(currentUser) != "root" {
				fmt.Println("Only root users can change the role of other users.")
				waitForEnter()
				continue
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current role: %s | New role (user/admin/root): ", getRole(selectedUser))
			newRole, _ := reader.ReadString('\n')
			newRole = strings.TrimSpace(newRole)
			if newRole == "" {
				newRole = getRole(selectedUser)
			}
			if err := userStore.EditUserRole(getUsername(currentUser), getUsername(selectedUser), newRole); err != nil {
				fmt.Println("Error changing role:", err)
				waitForEnter()
			} else {
				fmt.Println("Role changed successfully!")
				selectedUser.Role = &newRole
				waitForEnter()
			}
		case "5":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("Cannot unlock deleted user.")
				waitForEnter()
				continue
			}
			if getRole(currentUser) != "root" {
				fmt.Println("Only root users can unlock users.")
				waitForEnter()
				continue
			}
			err := userStore.UnlockUser(getUsername(selectedUser))
			if err != nil {
				fmt.Println("Error unlocking user:", err)
				waitForEnter()
			} else {
				fmt.Println("User unlocked successfully!")
				waitForEnter()
			}
		case "6":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("Cannot block deleted user.")
				waitForEnter()
				continue
			}
			if getRole(currentUser) != "root" {
				fmt.Println("Only root users can block users.")
				waitForEnter()
				continue
			}
			if getUsername(selectedUser) == getUsername(currentUser) {
				fmt.Println("You cannot block yourself!")
				waitForEnter()
				continue
			}
			fmt.Printf("⚠️  WARNING: Are you sure you want to block user '%s'? (yes/no): ", getUsername(selectedUser))
			confirmation, _ := reader.ReadString('\n')
			confirmation = strings.TrimSpace(strings.ToLower(confirmation))
			if confirmation == "yes" {
				err := userStore.BlockUser(getUsername(selectedUser))
				if err != nil {
					fmt.Println("Error blocking user:", err)
					waitForEnter()
				} else {
					fmt.Println("User blocked successfully!")
					waitForEnter()
				}
			} else {
				fmt.Println("User block cancelled.")
				waitForEnter()
			}
		case "7":
			clearTerminal()
			if selectedUser.DeletedAt != nil {
				fmt.Println("User is already deleted.")
				waitForEnter()
				continue
			}
			if getRole(currentUser) != "admin" && getRole(currentUser) != "root" {
				fmt.Println("Only admin or root users can delete users.")
				waitForEnter()
				continue
			}
			if getUsername(selectedUser) == getUsername(currentUser) {
				fmt.Println("You cannot delete yourself!")
				waitForEnter()
				continue
			}
			fmt.Printf("⚠️  WARNING: Are you sure you want to delete user '%s'? This is a soft-delete and cannot be undone. (yes/no): ", getUsername(selectedUser))
			confirmation, _ := reader.ReadString('\n')
			confirmation = strings.TrimSpace(strings.ToLower(confirmation))
			if confirmation == "yes" {
				err := userStore.DeleteUser(currentUser.ID, getUsername(currentUser), getUsername(selectedUser))
				if err != nil {
					fmt.Println("Error deleting user:", err)
					waitForEnter()
				} else {
					fmt.Println("User deleted successfully (soft-delete)!")
					selectedUser.DeletedAt = new(time.Time)
					*selectedUser.DeletedAt = time.Now()
					waitForEnter()
				}
			} else {
				fmt.Println("User deletion cancelled.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}
