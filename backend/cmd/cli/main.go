package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"Licenses-Manager/backend/database"
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
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
	licenseStore := store.NewLicenseStore(db)
	entityStore := store.NewEntityStore(db)
	categoryStore := store.NewCategoryStore(db)
	lineStore := store.NewLineStore(db)

	fmt.Println("=== Licenses Manager CLI ===")
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
			clientsFlow(clientStore, entityStore, licenseStore, lineStore, categoryStore)
		case "2":
			licensesFlow(licenseStore, clientStore, entityStore, lineStore, categoryStore)
		case "3":
			administrationFlow(categoryStore, lineStore, userStore, user)
		case "4":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Licenses Menu (Overview)
func licensesFlow(licenseStore *store.LicenseStore, clientStore *store.ClientStore, entityStore *store.EntityStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- Licenses (Overview) ---")
		fmt.Println("1 - List all licenses")
		fmt.Println("2 - Filter by client")
		fmt.Println("3 - Filter by line")
		fmt.Println("4 - Filter by category")
		fmt.Println("5 - Create license")
		fmt.Println("6 - Edit license")
		fmt.Println("7 - Delete license")
		fmt.Println("8 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			// List all licenses
			licenses, err := licenseStore.GetAllLicenses()
			if err != nil {
				fmt.Println("Error listing licenses:", err)
				continue
			}
			if len(licenses) == 0 {
				fmt.Println("No licenses found.")
				continue
			}
			fmt.Println("\n=== All Licenses ===")
			for _, l := range licenses {
				entity := ""
				if l.EntityID != nil {
					entity = *l.EntityID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Entity: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), entity)
			}

		case "2":
			fmt.Print("Client ID: ")
			clientID, _ := reader.ReadString('\n')
			clientID = strings.TrimSpace(clientID)
			licenses, err := licenseStore.GetLicensesByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing licenses:", err)
				continue
			}
			if len(licenses) == 0 {
				fmt.Println("No licenses found for this client.")
				continue
			}
			fmt.Println("\n=== Licenses by Client ===")
			for _, l := range licenses {
				entity := ""
				if l.EntityID != nil {
					entity = *l.EntityID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Entity: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), entity)
			}
		case "3":
			fmt.Print("Line ID: ")
			lineID, _ := reader.ReadString('\n')
			lineID = strings.TrimSpace(lineID)
			licenses, err := licenseStore.GetLicensesByLineID(lineID)
			if err != nil {
				fmt.Println("Error listing licenses:", err)
				continue
			}
			if len(licenses) == 0 {
				fmt.Println("No licenses found for this line.")
				continue
			}
			fmt.Println("\n=== Licenses by Line ===")
			for _, l := range licenses {
				entity := ""
				if l.EntityID != nil {
					entity = *l.EntityID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Entity: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), entity)
			}
		case "4":
			fmt.Print("Category ID: ")
			categoryID, _ := reader.ReadString('\n')
			categoryID = strings.TrimSpace(categoryID)
			licenses, err := licenseStore.GetLicensesByCategoryID(categoryID)
			if err != nil {
				fmt.Println("Error listing licenses:", err)
				continue
			}
			if len(licenses) == 0 {
				fmt.Println("No licenses found for this category.")
				continue
			}
			fmt.Println("\n=== Licenses by Category ===")
			for _, l := range licenses {
				entity := ""
				if l.EntityID != nil {
					entity = *l.EntityID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Entity: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), entity)
			}


		case "5":
			fmt.Print("Client ID: ")
			clientID, _ := reader.ReadString('\n')
			clientID = strings.TrimSpace(clientID)
			licensesSubmenu(clientID, licenseStore, entityStore, lineStore, categoryStore)
		case "6":
			fmt.Print("License ID to edit: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			license, err := licenseStore.GetLicenseByID(id)
			if err != nil || license == nil {
				fmt.Println("License not found.")
				continue
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Current name: %s | New name: ", license.Model)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current key: %s | New key: ", license.ProductKey)
			productKey, _ := reader.ReadString('\n')
			fmt.Printf("Current start date: %s | New date (YYYY-MM-DD): ", license.StartDate.Format("2006-01-02"))
			startStr, _ := reader.ReadString('\n')
			fmt.Printf("Current end date: %s | New date (YYYY-MM-DD): ", license.EndDate.Format("2006-01-02"))
			endStr, _ := reader.ReadString('\n')
			fmt.Printf("Current type ID: %s | New type ID: ", license.LineID)
			lineID, _ := reader.ReadString('\n')
			fmt.Printf("Current entity ID: ")
			if license.EntityID != nil {
				fmt.Printf("%s | New entity (optional): ", *license.EntityID)
			} else {
				fmt.Print("(none) | New entity (optional): ")
			}
			entityID, _ := reader.ReadString('\n')
			startDate := license.StartDate
			endDate := license.EndDate
			if strings.TrimSpace(startStr) != "" {
				startDate, _ = time.Parse("2006-01-02", strings.TrimSpace(startStr))
			}
			if strings.TrimSpace(endStr) != "" {
				endDate, _ = time.Parse("2006-01-02", strings.TrimSpace(endStr))
			}
			var entityPtr *string
			entityID = strings.TrimSpace(entityID)
			if entityID != "" {
				entityPtr = &entityID
			}
			license.Model = strings.TrimSpace(name)
			license.ProductKey = strings.TrimSpace(productKey)
			license.StartDate = startDate
			license.EndDate = endDate
			license.LineID = strings.TrimSpace(lineID)
			license.EntityID = entityPtr
			err = licenseStore.UpdateLicense(*license)
			if err != nil {
				fmt.Println("Error updating license:", err)
			} else {
				fmt.Println("License updated.")
			}
		case "7":
			fmt.Print("License ID to delete: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			err := licenseStore.DeleteLicense(id)
			if err != nil {
				fmt.Println("Error deleting license:", err)
			} else {
				fmt.Println("License deleted.")
			}
		case "8":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Licenses Submenu for Client
func licensesSubmenu(clientID string, licenseStore *store.LicenseStore, entityStore *store.EntityStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("License name: ")
	name, _ := reader.ReadString('\n')
	fmt.Print("Product key: ")
	productKey, _ := reader.ReadString('\n')
	fmt.Print("Start date (YYYY-MM-DD): ")
	startStr, _ := reader.ReadString('\n')
	fmt.Print("End date (YYYY-MM-DD): ")
	endStr, _ := reader.ReadString('\n')
	fmt.Print("Line ID: ")
	lineID, _ := reader.ReadString('\n')
	fmt.Print("Entity ID: ")
	entityID, _ := reader.ReadString('\n')
	startDate, _ := time.Parse("2006-01-02", strings.TrimSpace(startStr))
	endDate, _ := time.Parse("2006-01-02", strings.TrimSpace(endStr))
	var entityPtr *string
	entityID = strings.TrimSpace(entityID)
	if entityID != "" {
		entityPtr = &entityID
	}
	license := domain.License{
		Model:      strings.TrimSpace(name),
		ProductKey: strings.TrimSpace(productKey),
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     strings.TrimSpace(lineID),
		ClientID:   clientID,
		EntityID:   entityPtr,
	}
	id, err := licenseStore.CreateLicense(license)
	if err != nil {
		fmt.Println("Error creating license:", err)
	} else {
		fmt.Println("License created with ID:", id)
	}
}

// Administration Menu (Categories, Lines, Users)
func administrationFlow(categoryStore *store.CategoryStore, lineStore *store.LineStore, userStore *store.UserStore, user *domain.User) {
	for {
		fmt.Println("\n--- Administration ---")
		fmt.Println("1 - Categories")
		fmt.Println("2 - Lines")
		fmt.Println("3 - Users")
		fmt.Println("4 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			categoriesMenu(categoryStore)
		case "2":
			linesMenu(lineStore, categoryStore)
		case "3":
			usuariosMenu(userStore, user)
		case "4":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Categories Submenu
func categoriesMenu(categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- Categories ---")
		fmt.Println("1 - List categories")
		fmt.Println("2 - Create category")
		fmt.Println("3 - Edit category")
		fmt.Println("4 - Delete category")
		fmt.Println("5 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			categories, err := categoryStore.GetAllCategories()
			if err != nil {
				fmt.Println("Error listing categories:", err)
				continue
			}
			for _, c := range categories {
				fmt.Printf("ID: %s | Name: %s\n", c.ID, c.Name)
			}
		case "2":
			fmt.Print("Category name: ")
			name, _ := reader.ReadString('\n')
			id, err := categoryStore.CreateCategory(domain.Category{Name: strings.TrimSpace(name)})
			if err != nil {
				fmt.Println("Error creating category:", err)
			} else {
				fmt.Println("Category created with ID:", id)
			}
		case "3":
			fmt.Print("Category ID to edit: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			category, err := categoryStore.GetCategoryByID(id)
			if err != nil || category == nil {
				fmt.Println("Category not found.")
				continue
			}
			fmt.Printf("Current name: %s | New name: ", category.Name)
			newName, _ := reader.ReadString('\n')
			category.Name = strings.TrimSpace(newName)
			err = categoryStore.UpdateCategory(*category)
			if err != nil {
				fmt.Println("Error updating category:", err)
			} else {
				fmt.Println("Category updated.")
			}
		case "4":
			fmt.Print("Category ID to delete: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			err := categoryStore.DeleteCategory(id)
			if err != nil {
				fmt.Println("Error deleting category:", err)
			} else {
				fmt.Println("Category deleted.")
			}
		case "5":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Lines Submenu
func linesMenu(lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- License Lines ---")
		fmt.Println("1 - List lines")
		fmt.Println("2 - Create line")
		fmt.Println("3 - Edit line")
		fmt.Println("4 - Delete line")
		fmt.Println("5 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			lines, err := lineStore.GetAllLines()
			if err != nil {
				fmt.Println("Error listing lines:", err)
				continue
			}
			for _, t := range lines {
				fmt.Printf("ID: %s | Name: %s | Category: %s\n", t.ID, t.Line, t.CategoryID)
			}
		case "2":
			fmt.Print("Line name: ")
			line, _ := reader.ReadString('\n')
			fmt.Print("Category ID: ")
			categoryID, _ := reader.ReadString('\n')
			id, err := lineStore.CreateLine(domain.Line{
				Line:       strings.TrimSpace(line),
				CategoryID: strings.TrimSpace(categoryID),
			})
			if err != nil {
				fmt.Println("Error creating line:", err)
			} else {
				fmt.Println("Line created with ID:", id)
			}
		case "3":
			fmt.Print("Line ID to edit: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			fmt.Print("New type name: ")
			line, _ := reader.ReadString('\n')
			fmt.Print("New category for line: ")
			categoryID, _ := reader.ReadString('\n')
			err := lineStore.UpdateLine(domain.Line{
				ID:         id,
				Line:       strings.TrimSpace(line),
				CategoryID: strings.TrimSpace(categoryID),
			})
			if err != nil {
				fmt.Println("Error updating line:", err)
			} else {
				fmt.Println("Line updated.")
			}
		case "4":
			fmt.Print("Line ID to delete: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			err := lineStore.DeleteLine(id)
			if err != nil {
				fmt.Println("Error deleting line:", err)
			} else {
				fmt.Println("Line deleted.")
			}
		case "5":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Users Submenu
func usuariosMenu(userStore *store.UserStore, user *domain.User) {
	for {
		fmt.Println("\n--- Users ---")
		fmt.Println("1 - List users")
		fmt.Println("2 - Create regular user (admin or full_admin only)")
		fmt.Println("3 - Create admin user (admin or full_admin only)")
		fmt.Println("4 - Create full_admin user (full_admin only)")
		fmt.Println("5 - Change display name")
		fmt.Println("6 - Change password")
		fmt.Println("7 - Change your own username (admin or full_admin only)")
		fmt.Println("8 - Change user role (full_admin only)")
		fmt.Println("9 - Unlock user (full_admin only)")
		fmt.Println("10 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			users, err := userStore.ListUsers()
			if err != nil {
				fmt.Println("Error listing users:", err)
				continue
			}
			fmt.Println("Registered users:")
			for _, u := range users {
				fmt.Printf("ID: %s | Username: %s | Display Name: %s | Role: %s | Password Hash: %s | Created at: %s\n", u.ID, u.Username, u.DisplayName, u.Role, u.PasswordHash, u.CreatedAt.Format("2006-01-02 15:04:05"))
			}
		case "2":
			// Create regular user (admin or full_admin only)
			if user.Role != "admin" && user.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can create new users.")
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
			id, err := userStore.CreateUser(username, displayName, password, "user")
			if err != nil {
				fmt.Println("Error creating user:", err)
			} else {
				fmt.Printf("User created with ID: %s\n", id)
			}
		case "3":
			// Create admin user (admin or full_admin only)
			if user.Role != "admin" && user.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can create new admins.")
				break
			}
			fmt.Print("Admin username (leave empty to auto-generate admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Admin display name: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, "admin")
			if err != nil {
				fmt.Println("Error creating admin:", err)
			} else {
				fmt.Printf("Admin user created: %s\nDisplay Name: %s\nPassword: %s\n", genUsername, genDisplayName, genPassword)
			}
		case "4":
			// Create full_admin user (full_admin only)
			if user.Role != "full_admin" {
				fmt.Println("Only full_admin users can create other full_admin users.")
				break
			}
			fmt.Print("Full_admin username (leave empty to auto-generate admin-n): ")
			username, _ := reader.ReadString('\n')
			username = strings.TrimSpace(username)
			fmt.Print("Full_admin display name: ")
			displayName, _ := reader.ReadString('\n')
			displayName = strings.TrimSpace(displayName)
			genUsername, genDisplayName, genPassword, err := userStore.CreateAdminUser(username, displayName, "full_admin")
			if err != nil {
				fmt.Println("Error creating full_admin:", err)
			} else {
				fmt.Printf("Full_admin user created: %s\nDisplay Name: %s\nPassword: %s\n", genUsername, genDisplayName, genPassword)
			}
		case "5":
			// Change your display name
			fmt.Print("New display name for you: ")
			newDisplayName, _ := reader.ReadString('\n')
			newDisplayName = strings.TrimSpace(newDisplayName)
			err := userStore.EditUserDisplayName(user.Username, newDisplayName)
			if err != nil {
				fmt.Println("Error changing display name:", err)
			} else {
				fmt.Println("Display name changed successfully!")
			}
		case "6":
			// Change your password
			fmt.Print("New password: ")
			newPassword, _ := reader.ReadString('\n')
			newPassword = strings.TrimSpace(newPassword)

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
				break
			}

			err := userStore.EditUserPassword(user.Username, newPassword)
			if err != nil {
				fmt.Println("Error changing password:", err)
			} else {
				fmt.Println("Password changed successfully!")
			}
		case "7":
			// Change your own username (admin or full_admin only)
			if user.Role != "admin" && user.Role != "full_admin" {
				fmt.Println("Only admin or full_admin users can change their own username.")
				break
			}
			fmt.Print("New username for you: ")
			newUsername, _ := reader.ReadString('\n')
			newUsername = strings.TrimSpace(newUsername)
			err := userStore.UpdateUsername(user.Username, newUsername)
			if err != nil {
				fmt.Println("Error changing your username:", err)
			} else {
				fmt.Println("Your username was changed successfully! Please log in again with your new username.")
				return
			}
		case "8":
			// Change user role (full_admin only)
			if user.Role != "full_admin" {
				fmt.Println("Only full_admin users can change the role of other users.")
				break
			}
			fmt.Print("Username to change role: ")
			targetUsername, _ := reader.ReadString('\n')
			targetUsername = strings.TrimSpace(targetUsername)
			fmt.Print("New role (user/admin/full_admin): ")
			newRole, _ := reader.ReadString('\n')
			newRole = strings.TrimSpace(newRole)
			err := userStore.EditUserRole(user.Username, targetUsername, newRole)
			if err != nil {
				fmt.Println("Error changing role:", err)
			} else {
				fmt.Println("Role changed successfully!")
			}
		case "9":
			// Unlock user (full_admin only)
			if user.Role != "full_admin" {
				fmt.Println("Only full_admin users can unlock users.")
				break
			}
			fmt.Print("Username to unlock: ")
			targetUsername, _ := reader.ReadString('\n')
			targetUsername = strings.TrimSpace(targetUsername)
			err := userStore.UnlockUser(targetUsername)
			if err != nil {
				fmt.Println("Error unlocking user:", err)
			} else {
				fmt.Println("User unlocked successfully!")
			}
		case "10":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func promptLogin() (string, string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	username, _ := reader.ReadString('\n')
	fmt.Print("Password: ")
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(username), strings.TrimSpace(password)
}

func mainMenu() string {
	fmt.Println("Select an option:")
	fmt.Println("1 - Clients")
	fmt.Println("2 - Licenses (overview)")
	fmt.Println("3 - Administration (categories, lines, users)")
	fmt.Println("4 - Exit")
	fmt.Print("Option: ")
	reader := bufio.NewReader(os.Stdin)
	opt, _ := reader.ReadString('\n')
	return strings.TrimSpace(opt)
}

func clientsFlow(clientStore *store.ClientStore, entityStore *store.EntityStore, licenseStore *store.LicenseStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- Clients Menu ---")
		fmt.Println("1 - List clients")
		fmt.Println("2 - Create client")
		fmt.Println("3 - Select client")
		fmt.Println("4 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			clients, err := clientStore.GetAllClients()
			if err != nil {
				fmt.Println("Error listing clients:", err)
				continue
			}
			fmt.Println("Active clients:")
			for _, c := range clients {
				fmt.Printf("ID: %s | Name: %s | Registration ID: %s\n", c.ID, c.Name, c.RegistrationID)
			}
		case "2":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Client name: ")
			name, _ := reader.ReadString('\n')
			fmt.Print("Registration ID: ")
			registrationID, _ := reader.ReadString('\n')
			client := domain.Client{
				Name:           strings.TrimSpace(name),
				RegistrationID: strings.TrimSpace(registrationID),
			}
			id, err := clientStore.CreateClient(client)
			if err != nil {
				fmt.Println("Error creating client:", err)
			} else {
				fmt.Println("Client created with ID:", id)
			}
		case "3":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Client ID: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			clientSubmenu(id, clientStore, entityStore, licenseStore, lineStore, categoryStore)
		case "4":
			return
		default:
			fmt.Println("Invalid Option.")
		}
	}
}

func entitiesSubmenu(clientID string, entityStore *store.EntityStore) {
	for {
		fmt.Printf("\n--- Entities of Client %s ---\n", clientID)
		fmt.Println("1 - List entities")
		fmt.Println("2 - Create entity")
		fmt.Println("3 - Edit entity")
		fmt.Println("4 - Delete entity")
		fmt.Println("5 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			entities, err := entityStore.GetEntitiesByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing entities:", err)
				continue
			}
			for _, e := range entities {
				fmt.Printf("ID: %s | Name: %s\n", e.ID, e.Name)
			}
		case "2":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Entity name: ")
			name, _ := reader.ReadString('\n')
			entity := domain.Entity{
				Name:     strings.TrimSpace(name),
				ClientID: clientID,
			}
			id, err := entityStore.CreateEntity(entity)
			if err != nil {
				fmt.Println("Error creating entity:", err)
			} else {
				fmt.Println("Entity created with ID:", id)
			}
		case "3":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Entity ID to edit: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			entities, err := entityStore.GetEntitiesByClientID(clientID)
			if err != nil {
				fmt.Println("Error fetching entity:", err)
				continue
			}
			var entity *domain.Entity
			for _, e := range entities {
				if e.ID == id {
					entity = &e
					break
				}
			}
			if entity == nil {
				fmt.Println("Entity not found.")
				continue
			}
			fmt.Printf("Current name: %s | New name: ", entity.Name)
			name, _ := reader.ReadString('\n')
			entity.Name = strings.TrimSpace(name)
			err = entityStore.UpdateEntity(*entity)
			if err != nil {
				fmt.Println("Error updating entity:", err)
			} else {
				fmt.Println("Entity updated.")
			}
		case "4":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Entity ID to delete: ")
			id, _ := reader.ReadString('\n')
			id = strings.TrimSpace(id)
			err := entityStore.DeleteEntity(id)
			if err != nil {
				fmt.Println("Error deleting entity:", err)
			} else {
				fmt.Println("Entity deleted.")
			}
		case "5":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func clientSubmenu(clientID string,
	clientStore *store.ClientStore,
	entityStore *store.EntityStore,
	licenseStore *store.LicenseStore,
	lineStore *store.LineStore,
	categoryStore *store.CategoryStore) {
	clientName, _ := clientStore.GetClientNameByID(clientID)
	for {
		fmt.Printf("\n--- Client %s ---\n", clientName)
		fmt.Println("1 - Edit client")
		fmt.Println("2 - Archive client")
		fmt.Println("3 - Delete client")
		fmt.Println("4 - Entities")
		fmt.Println("5 - Licenses")
		fmt.Println("6 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			client, err := clientStore.GetClientByID(clientID)
			if err != nil || client == nil {
				fmt.Println("Client not found.")
				continue
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Current name: %s | New name: ", client.Name)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current Registration ID: %s | New Registration ID: ", client.RegistrationID)
			registrationID, _ := reader.ReadString('\n')
			client.Name = strings.TrimSpace(name)
			client.RegistrationID = strings.TrimSpace(registrationID)
			err = clientStore.UpdateClient(*client)
			if err != nil {
				fmt.Println("Error updating client:", err)
			} else {
				fmt.Println("Client updated.")
			}
		case "2":
			err := clientStore.ArchiveClient(clientID)
			if err != nil {
				fmt.Println("Error archiving client:", err)
			} else {
				fmt.Println("Client archived.")
			}
		case "3":
			err := clientStore.DeleteClientPermanently(clientID)
			if err != nil {
				fmt.Println("Error deleting client:", err)
			} else {
				fmt.Println("Client permanently deleted.")
			}
		case "4":
			entitiesSubmenu(clientID, entityStore)
		case "5":
			licensesSubmenu(clientID, licenseStore, entityStore, lineStore, categoryStore)
		case "6":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}
