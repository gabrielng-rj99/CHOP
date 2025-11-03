package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"Contracts-Manager/backend/database"
	"Contracts-Manager/backend/domain"
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
			clientsFlow(clientStore, dependentStore, contractStore, lineStore, categoryStore)
		case "2":
			contractsFlow(contractStore, clientStore, dependentStore, lineStore, categoryStore)
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

// contracts Menu (Overview)
func contractsFlow(contractStore *store.ContractStore, clientStore *store.ClientStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- contracts (Overview) ---")
		fmt.Println("1 - List all contracts")
		fmt.Println("2 - Filter by client")
		fmt.Println("3 - Filter by line")
		fmt.Println("4 - Filter by category")
		fmt.Println("5 - Create contract")
		fmt.Println("6 - Edit contract")
		fmt.Println("7 - Delete contract")
		fmt.Println("8 - Back")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "1":
			// List all contracts
			contracts, err := contractStore.GetAllContracts()
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found.")
				continue
			}
			fmt.Println("\n=== All contracts ===")
			for _, l := range contracts {
				dependent := ""
				if l.DependentID != nil {
					dependent = *l.DependentID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Dependent: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), dependent)
			}

		case "2":
			fmt.Print("Client ID: ")
			clientID, _ := reader.ReadString('\n')
			clientID = strings.TrimSpace(clientID)
			if clientID == "" {
				fmt.Println("Error: Client ID cannot be empty.")
				continue
			}
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				continue
			}
			fmt.Println("\n=== contracts by Client ===")
			for _, l := range contracts {
				dependent := ""
				if l.DependentID != nil {
					dependent = *l.DependentID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Dependent: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), dependent)
			}
		case "3":
			fmt.Print("Line ID: ")
			lineID, _ := reader.ReadString('\n')
			lineID = strings.TrimSpace(lineID)
			if lineID == "" {
				fmt.Println("Error: Line ID cannot be empty.")
				continue
			}
			contracts, err := contractStore.GetContractsByLineID(lineID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found for this line.")
				continue
			}
			fmt.Println("\n=== contracts by Line ===")
			for _, l := range contracts {
				dependent := ""
				if l.DependentID != nil {
					dependent = *l.DependentID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Dependent: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), dependent)
			}
		case "4":
			fmt.Print("Category ID: ")
			categoryID, _ := reader.ReadString('\n')
			categoryID = strings.TrimSpace(categoryID)
			if categoryID == "" {
				fmt.Println("Error: Category ID cannot be empty.")
				continue
			}
			contracts, err := contractStore.GetContractsByCategoryID(categoryID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found for this category.")
				continue
			}
			fmt.Println("\n=== contracts by Category ===")
			for _, l := range contracts {
				dependent := ""
				if l.DependentID != nil {
					dependent = *l.DependentID
				}
				status := l.Status()
				fmt.Printf("ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Dependent: %s\n",
					l.ID, l.Model, l.ProductKey, status, l.StartDate.Format("2006-01-02"), l.EndDate.Format("2006-01-02"), dependent)
			}

		case "5":
			fmt.Print("Client ID: ")
			clientID, _ := reader.ReadString('\n')
			clientID = strings.TrimSpace(clientID)
			if clientID == "" {
				fmt.Println("Error: Client ID cannot be empty.")
				continue
			}
			contractsSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
		case "6":
			fmt.Print("Buscar contrato para editar por (1) ID ou (2) nome/modelo? ")
			searchOpt, _ := reader.ReadString('\n')
			searchOpt = strings.TrimSpace(searchOpt)
			var contract *domain.Contract
			if searchOpt == "2" {
				fmt.Print("Digite parte do nome/modelo: ")
				searchName, _ := reader.ReadString('\n')
				searchName = strings.TrimSpace(searchName)
				contracts, err := contractStore.GetContractsByName(searchName)
				if err != nil || len(contracts) == 0 {
					fmt.Println("Nenhum contrato encontrado.")
					continue
				}
				for i, c := range contracts {
					fmt.Printf("%d - ID: %s | Modelo: %s | Produto: %s\n", i+1, c.ID, c.Model, c.ProductKey)
				}
				fmt.Print("Escolha o número do contrato: ")
				idxStr, _ := reader.ReadString('\n')
				idxStr = strings.TrimSpace(idxStr)
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > len(contracts) {
					fmt.Println("Opção inválida.")
					continue
				}
				contract = &contracts[idx-1]
			} else {
				fmt.Print("contract ID to edit: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: contract ID cannot be empty.")
					continue
				}
				c, err := contractStore.GetContractByID(id)
				if err != nil || c == nil {
					fmt.Println("contract not found.")
					continue
				}
				contract = c
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Current name: %s | New name: ", contract.Model)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current key: %s | New key: ", contract.ProductKey)
			productKey, _ := reader.ReadString('\n')
			fmt.Printf("Current start date: %s | New date (YYYY-MM-DD): ", contract.StartDate.Format("2006-01-02"))
			startStr, _ := reader.ReadString('\n')
			fmt.Printf("Current end date: %s | New date (YYYY-MM-DD): ", contract.EndDate.Format("2006-01-02"))
			endStr, _ := reader.ReadString('\n')
			fmt.Printf("Current type ID: %s | New type ID: ", contract.LineID)
			lineID, _ := reader.ReadString('\n')
			fmt.Printf("Current dependent ID: ")
			if contract.DependentID != nil {
				fmt.Printf("%s | New dependent (optional): ", *contract.DependentID)
			} else {
				fmt.Print("(none) | New dependent (optional): ")
			}
			dependentID, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			productKey = strings.TrimSpace(productKey)
			lineID = strings.TrimSpace(lineID)

			if name == "" {
				fmt.Println("Error: contract name cannot be empty.")
				continue
			}
			if productKey == "" {
				fmt.Println("Error: Product key cannot be empty.")
				continue
			}
			if lineID == "" {
				fmt.Println("Error: Line ID cannot be empty.")
				continue
			}

			startDate := contract.StartDate
			endDate := contract.EndDate
			if strings.TrimSpace(startStr) != "" {
				parsedStart, errStart := time.Parse("2006-01-02", strings.TrimSpace(startStr))
				if errStart != nil {
					fmt.Println("Error: Invalid start date format. Use YYYY-MM-DD.")
					continue
				}
				startDate = parsedStart
			}
			if strings.TrimSpace(endStr) != "" {
				parsedEnd, errEnd := time.Parse("2006-01-02", strings.TrimSpace(endStr))
				if errEnd != nil {
					fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
					continue
				}
				endDate = parsedEnd
			}
			var dependentPtr *string
			dependentID = strings.TrimSpace(dependentID)
			if dependentID != "" {
				dependentPtr = &dependentID
			}
			contract.Model = name
			contract.ProductKey = productKey
			contract.StartDate = startDate
			contract.EndDate = endDate
			contract.LineID = lineID
			contract.DependentID = dependentPtr
			err := contractStore.UpdateContract(*contract)
			if err != nil {
				fmt.Println("Error updating contract:", err)
			} else {
				fmt.Println("contract updated.")
			}
		case "7":
			fmt.Print("Buscar contrato para excluir por (1) ID ou (2) nome/modelo? ")
			searchOpt, _ := reader.ReadString('\n')
			searchOpt = strings.TrimSpace(searchOpt)
			var contractID string
			if searchOpt == "2" {
				fmt.Print("Digite parte do nome/modelo: ")
				searchName, _ := reader.ReadString('\n')
				searchName = strings.TrimSpace(searchName)
				contracts, err := contractStore.GetContractsByName(searchName)
				if err != nil || len(contracts) == 0 {
					fmt.Println("Nenhum contrato encontrado.")
					continue
				}
				for i, c := range contracts {
					fmt.Printf("%d - ID: %s | Modelo: %s | Produto: %s\n", i+1, c.ID, c.Model, c.ProductKey)
				}
				fmt.Print("Escolha o número do contrato para excluir: ")
				idxStr, _ := reader.ReadString('\n')
				idxStr = strings.TrimSpace(idxStr)
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > len(contracts) {
					fmt.Println("Opção inválida.")
					continue
				}
				contractID = contracts[idx-1].ID
			} else {
				fmt.Print("contract ID to delete: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: contract ID cannot be empty.")
					continue
				}
				contractID = id
			}
			err := contractStore.DeleteContract(contractID)
			if err != nil {
				fmt.Println("Error deleting contract:", err)
			} else {
				fmt.Println("contract deleted.")
			}
		case "8":
			return
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// contracts Submenu for Client
func contractsSubmenu(clientID string, contractStore *store.ContractStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	reader := bufio.NewReader(os.Stdin)

	// 1. Select Category
	fmt.Println("Select a category for the contract:")
	categories, err := categoryStore.GetAllCategories()
	if err != nil || len(categories) == 0 {
		fmt.Println("Error: No categories available.")
		return
	}
	for i, c := range categories {
		fmt.Printf("%d - %s\n", i+1, c.Name)
	}
	fmt.Print("Enter the number of the category: ")
	catIdxStr, _ := reader.ReadString('\n')
	catIdxStr = strings.TrimSpace(catIdxStr)
	catIdx, err := strconv.Atoi(catIdxStr)
	if err != nil || catIdx < 1 || catIdx > len(categories) {
		fmt.Println("Error: Invalid category selection.")
		return
	}
	categoryID := categories[catIdx-1].ID

	// 2. Select Line
	fmt.Println("Select a line (type) for the contract:")
	lines, err := lineStore.GetLinesByCategoryID(categoryID)
	if err != nil || len(lines) == 0 {
		fmt.Println("Error: No lines available for this category.")
		return
	}
	for i, l := range lines {
		fmt.Printf("%d - %s\n", i+1, l.Line)
	}
	fmt.Print("Enter the number of the line: ")
	lineIdxStr, _ := reader.ReadString('\n')
	lineIdxStr = strings.TrimSpace(lineIdxStr)
	lineIdx, err := strconv.Atoi(lineIdxStr)
	if err != nil || lineIdx < 1 || lineIdx > len(lines) {
		fmt.Println("Error: Invalid line selection.")
		return
	}
	lineID := lines[lineIdx-1].ID

	// 3. Enter contract model/name
	fmt.Print("Contract model/name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Error: Contract model/name cannot be empty.")
		return
	}

	// 4. Enter product key
	fmt.Print("Product key: ")
	productKey, _ := reader.ReadString('\n')
	productKey = strings.TrimSpace(productKey)
	if productKey == "" {
		fmt.Println("Error: Product key cannot be empty.")
		return
	}

	// 5. Dates
	fmt.Print("Start date (YYYY-MM-DD): ")
	startStr, _ := reader.ReadString('\n')
	fmt.Print("End date (YYYY-MM-DD): ")
	endStr, _ := reader.ReadString('\n')
	startDate, errStart := time.Parse("2006-01-02", strings.TrimSpace(startStr))
	if errStart != nil {
		fmt.Println("Error: Invalid start date format. Use YYYY-MM-DD.")
		return
	}
	endDate, errEnd := time.Parse("2006-01-02", strings.TrimSpace(endStr))
	if errEnd != nil {
		fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
		return
	}

	// 6. Select dependents (optional, comma-separated for multiple, or Enter for global)
	dependents, err := dependentStore.GetDependentsByClientID(clientID)
	var dependentPtr *string
	if err == nil && len(dependents) > 0 {
		fmt.Println("Select dependents for this contract (optional).")
		fmt.Println("Enter the numbers separated by commas for multiple selection, or press Enter for global contract (no dependents):")
		for i, d := range dependents {
			fmt.Printf("%d - %s\n", i+1, d.Name)
		}
		fmt.Print("Dependents: ")
		depIdxStr, _ := reader.ReadString('\n')
		depIdxStr = strings.TrimSpace(depIdxStr)
		if depIdxStr != "" {
			depIdxList := strings.Split(depIdxStr, ",")
			if len(depIdxList) > 1 {
				fmt.Println("Warning: Only one dependent can be associated per contract. Using the first selected.")
			}
			idxStr := strings.TrimSpace(depIdxList[0])
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Error: Invalid dependent selection.")
				return
			}
			depID := dependents[idx-1].ID
			dependentPtr = &depID
		}
	}

	contract := domain.Contract{
		Model:       name,
		ProductKey:  productKey,
		StartDate:   startDate,
		EndDate:     endDate,
		LineID:      lineID,
		ClientID:    clientID,
		DependentID: dependentPtr,
	}
	id, err := contractStore.CreateContract(contract)
	if err != nil {
		fmt.Println("Error creating contract:", err)
	} else {
		fmt.Println("Contract created with ID:", id)
	}
}

// Administration Menu (Categories, Lines, Users)
func administrationFlow(categoryStore *store.CategoryStore, lineStore *store.LineStore, userStore *store.UserStore, user *domain.User) {
	for {
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
		fmt.Println("\n--- Categories Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List categories")
		fmt.Println("2 - Create category")
		fmt.Println("3 - Edit category")
		fmt.Println("4 - Delete category")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			categories, err := categoryStore.GetAllCategories()
			if err != nil {
				fmt.Println("Error listing categories:", err)
				continue
			}
			if len(categories) == 0 {
				fmt.Println("No categories found.")
				continue
			}
			fmt.Println("Categories:")
			for i, c := range categories {
				fmt.Printf("%d - %s\n", i+1, c.Name)
			}
		case "2":
			fmt.Print("Enter category name: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Category name cannot be empty.")
				continue
			}
			category := domain.Category{
				Name: name,
			}
			id, err := categoryStore.CreateCategory(category)
			if err != nil {
				fmt.Println("Error creating category:", err)
			} else {
				fmt.Println("Category created with ID:", id)
			}
		case "3":
			categories, err := categoryStore.GetAllCategories()
			if err != nil || len(categories) == 0 {
				fmt.Println("No categories found.")
				continue
			}
			fmt.Println("Select a category to edit by number:")
			for i, c := range categories {
				fmt.Printf("%d - %s\n", i+1, c.Name)
			}
			fmt.Print("Enter the number of the category: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(categories) {
				fmt.Println("Invalid selection.")
				continue
			}
			category := categories[idx-1]
			fmt.Printf("Current name: %s | New name: ", category.Name)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Category name cannot be empty.")
				continue
			}
			category.Name = name
			err = categoryStore.UpdateCategory(category)
			if err != nil {
				fmt.Println("Error updating category:", err)
			} else {
				fmt.Println("Category updated.")
			}
		case "4":
			categories, err := categoryStore.GetAllCategories()
			if err != nil || len(categories) == 0 {
				fmt.Println("No categories found.")
				continue
			}
			fmt.Println("Select a category to delete by number:")
			for i, c := range categories {
				fmt.Printf("%d - %s\n", i+1, c.Name)
			}
			fmt.Print("Enter the number of the category: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(categories) {
				fmt.Println("Invalid selection.")
				continue
			}
			categoryID := categories[idx-1].ID
			err = categoryStore.DeleteCategory(categoryID)
			if err != nil {
				fmt.Println("Error deleting category:", err)
			} else {
				fmt.Println("Category deleted.")
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Lines Submenu
func linesMenu(lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- contract Lines ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List lines")
		fmt.Println("2 - Create line")
		fmt.Println("3 - Edit line")
		fmt.Println("4 - Delete line")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			lines, err := lineStore.GetAllLines()
			if err != nil {
				fmt.Println("Error listing lines:", err)
				continue
			}
			if len(lines) == 0 {
				fmt.Println("No lines found.")
				continue
			}
			fmt.Println("Lines:")
			for i, t := range lines {
				fmt.Printf("%d - %s (Category: %s)\n", i+1, t.Line, t.CategoryID)
			}
		case "2":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Line name: ")
			line, _ := reader.ReadString('\n')
			fmt.Print("Category ID: ")
			categoryID, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			categoryID = strings.TrimSpace(categoryID)
			if line == "" {
				fmt.Println("Error: Line name cannot be empty.")
				continue
			}
			if categoryID == "" {
				fmt.Println("Error: Category ID cannot be empty.")
				continue
			}
			id, err := lineStore.CreateLine(domain.Line{
				Line:       line,
				CategoryID: categoryID,
			})
			if err != nil {
				fmt.Println("Error creating line:", err)
			} else {
				fmt.Println("Line created with ID:", id)
			}
		case "3":
			fmt.Print("Buscar linha para editar por (1) ID ou (2) nome? ")
			searchOpt, _ := reader.ReadString('\n')
			searchOpt = strings.TrimSpace(searchOpt)
			var lineObj *domain.Line
			if searchOpt == "2" {
				fmt.Print("Digite parte do nome da linha: ")
				searchName, _ := reader.ReadString('\n')
				searchName = strings.TrimSpace(searchName)
				lines, err := lineStore.GetLinesByName(searchName)
				if err != nil || len(lines) == 0 {
					fmt.Println("Nenhuma linha encontrada.")
					continue
				}
				for i, l := range lines {
					fmt.Printf("%d - ID: %s | Nome: %s | Categoria: %s\n", i+1, l.ID, l.Line, l.CategoryID)
				}
				fmt.Print("Escolha o número da linha: ")
				idxStr, _ := reader.ReadString('\n')
				idxStr = strings.TrimSpace(idxStr)
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > len(lines) {
					fmt.Println("Opção inválida.")
					continue
				}
				lineObj = &lines[idx-1]
			} else {
				fmt.Print("Line ID to edit: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: Line ID cannot be empty.")
					continue
				}
				l, err := lineStore.GetLineByID(id)
				if err != nil || l == nil {
					fmt.Println("Linha não encontrada.")
					continue
				}
				lineObj = l
			}
			fmt.Printf("Current name: %s | New name: ", lineObj.Line)
			line, _ := reader.ReadString('\n')
			fmt.Printf("Current category: %s | New category for line: ", lineObj.CategoryID)
			categoryID, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			categoryID = strings.TrimSpace(categoryID)
			if line == "" {
				fmt.Println("Error: Line name cannot be empty.")
				continue
			}
			if categoryID == "" {
				fmt.Println("Error: Category ID cannot be empty.")
				continue
			}
			lineObj.Line = line
			lineObj.CategoryID = categoryID
			err := lineStore.UpdateLine(*lineObj)
			if err != nil {
				fmt.Println("Error updating line:", err)
			} else {
				fmt.Println("Line updated.")
			}
		case "4":
			lines, err := lineStore.GetAllLines()
			if err != nil || len(lines) == 0 {
				fmt.Println("No lines found.")
				continue
			}
			fmt.Println("Select a line to delete by number:")
			for i, t := range lines {
				fmt.Printf("%d - %s (Category: %s)\n", i+1, t.Line, t.CategoryID)
			}
			fmt.Print("Enter the number of the line: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(lines) {
				fmt.Println("Invalid selection.")
				continue
			}
			lineID := lines[idx-1].ID
			err = lineStore.DeleteLine(lineID)
			if err != nil {
				fmt.Println("Error deleting line:", err)
			} else {
				fmt.Println("Line deleted.")
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Users Submenu
func usuariosMenu(userStore *store.UserStore, user *domain.User) {
	for {
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
			users, err := userStore.ListUsers()
			if err != nil {
				fmt.Println("Error listing users:", err)
				continue
			}
			fmt.Println("Registered users:")
			for i, u := range users {
				fmt.Printf("%d - Username: %s | Display Name: %s | Role: %s | Created at: %s\n", i+1, u.Username, u.DisplayName, u.Role, u.CreatedAt.Format("2006-01-02 15:04:05"))
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
			if username == "" {
				fmt.Println("Error: Username cannot be empty.")
				continue
			}
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				continue
			}
			if password == "" {
				fmt.Println("Error: Password cannot be empty.")
				continue
			}
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
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				continue
			}
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
			if displayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				continue
			}
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
			if newDisplayName == "" {
				fmt.Println("Error: Display name cannot be empty.")
				continue
			}
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

			if newPassword == "" {
				fmt.Println("Error: Password cannot be empty.")
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
			if newUsername == "" {
				fmt.Println("Error: Username cannot be empty.")
				continue
			}
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
			users, err := userStore.ListUsers()
			if err != nil || len(users) == 0 {
				fmt.Println("No users found.")
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
				continue
			}
			targetUsername := users[idx-1].Username
			fmt.Print("New role (user/admin/full_admin): ")
			newRole, _ := reader.ReadString('\n')
			newRole = strings.TrimSpace(newRole)
			if targetUsername == "" {
				fmt.Println("Error: Target username cannot be empty.")
				continue
			}
			if newRole == "" {
				fmt.Println("Error: New role cannot be empty.")
				continue
			}
			err = userStore.EditUserRole(user.Username, targetUsername, newRole)
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
			users, err := userStore.ListUsers()
			if err != nil || len(users) == 0 {
				fmt.Println("No users found.")
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
				continue
			}
			targetUsername := users[idx-1].Username
			if targetUsername == "" {
				fmt.Println("Error: Target username cannot be empty.")
				continue
			}
			err = userStore.UnlockUser(targetUsername)
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
	fmt.Println("2 - contracts (overview)")
	fmt.Println("3 - Administration (categories, lines, users)")
	fmt.Println("4 - Exit")
	fmt.Print("Option: ")
	reader := bufio.NewReader(os.Stdin)
	opt, _ := reader.ReadString('\n')
	return strings.TrimSpace(opt)
}

func clientsFlow(clientStore *store.ClientStore, dependentStore *store.DependentStore, contractStore *store.ContractStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- Clients Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List clients")
		fmt.Println("2 - Create client")
		fmt.Println("3 - Select client")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
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
			name = strings.TrimSpace(name)
			registrationID = strings.TrimSpace(registrationID)
			if name == "" {
				fmt.Println("Error: Client name cannot be empty.")
				continue
			}
			if registrationID == "" {
				fmt.Println("Error: Registration ID cannot be empty.")
				continue
			}
			client := domain.Client{
				Name:           name,
				RegistrationID: registrationID,
			}
			id, err := clientStore.CreateClient(client)
			if err != nil {
				fmt.Println("Error creating client:", err)
			} else {
				fmt.Println("Client created with ID:", id)
			}
			continue
		case "3":
			clients, err := clientStore.GetAllClients()
			if err != nil || len(clients) == 0 {
				fmt.Println("No clients found.")
				continue
			}
			fmt.Println("Select a client by number:")
			for i, c := range clients {
				fmt.Printf("%d - %s | %s\n", i+1, c.Name, c.RegistrationID)
			}
			fmt.Print("Enter the number of the client: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(clients) {
				fmt.Println("Invalid selection.")
				continue
			}
			clientID := clients[idx-1].ID
			clientSubmenu(clientID, clientStore, dependentStore, contractStore, lineStore, categoryStore)
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func dependentsSubmenu(clientID string, dependentStore *store.DependentStore) {
	for {
		fmt.Printf("\n--- Dependents of Client %s ---\n", clientID)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List dependents")
		fmt.Println("2 - Create dependent")
		fmt.Println("3 - Edit dependent")
		fmt.Println("4 - Delete dependent")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing dependents:", err)
				continue
			}
			for _, e := range dependents {
				fmt.Printf("ID: %s | Name: %s\n", e.ID, e.Name)
			}
		case "2":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Dependent name: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Dependent name cannot be empty.")
				continue
			}
			dependent := domain.Dependent{
				Name:     name,
				ClientID: clientID,
			}
			id, err := dependentStore.CreateDependent(dependent)
			if err != nil {
				fmt.Println("Error creating dependent:", err)
			} else {
				fmt.Println("Dependent created with ID:", id)
			}
		case "3":
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil || len(dependents) == 0 {
				fmt.Println("No dependents found.")
				continue
			}
			fmt.Println("Select a dependent to edit by number:")
			for i, d := range dependents {
				fmt.Printf("%d - %s\n", i+1, d.Name)
			}
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Invalid selection.")
				continue
			}
			dependent := &dependents[idx-1]
			fmt.Printf("Current name: %s | New name: ", dependent.Name)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Dependent name cannot be empty.")
				continue
			}
			dependent.Name = name
			err = dependentStore.UpdateDependent(*dependent)
			if err != nil {
				fmt.Println("Error updating dependent:", err)
			} else {
				fmt.Println("Dependent updated.")
			}
		case "4":
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil || len(dependents) == 0 {
				fmt.Println("No dependents found.")
				continue
			}
			fmt.Println("Select a dependent to delete by number:")
			for i, d := range dependents {
				fmt.Printf("%d - %s\n", i+1, d.Name)
			}
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Invalid selection.")
				continue
			}
			dependentID := dependents[idx-1].ID
			err = dependentStore.DeleteDependent(dependentID)
			if err != nil {
				fmt.Println("Error deleting dependent:", err)
			} else {
				fmt.Println("Dependent deleted.")
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

func clientSubmenu(clientID string,
	clientStore *store.ClientStore,
	dependentStore *store.DependentStore,
	contractStore *store.ContractStore,
	lineStore *store.LineStore,
	categoryStore *store.CategoryStore) {
	if clientID == "" {
		fmt.Println("Error: Client ID cannot be empty.")
		return
	}
	clientName, err := clientStore.GetClientNameByID(clientID)
	if err != nil {
		fmt.Println("Error: Client not found.")
		return
	}
	for {
		fmt.Printf("\n--- Client %s ---\n", clientName)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - Edit client")
		fmt.Println("2 - Archive client")
		fmt.Println("3 - Delete client")
		fmt.Println("4 - Dependents")
		fmt.Println("5 - Contracts")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
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
			name = strings.TrimSpace(name)
			registrationID = strings.TrimSpace(registrationID)
			if name == "" {
				fmt.Println("Error: Client name cannot be empty.")
				continue
			}
			if registrationID == "" {
				fmt.Println("Error: Registration ID cannot be empty.")
				continue
			}
			client.Name = name
			client.RegistrationID = registrationID
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
			dependentsSubmenu(clientID, dependentStore)
		case "5":
			contractsClientSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// Contracts Submenu for Client
func contractsClientSubmenu(clientID string, contractStore *store.ContractStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		fmt.Println("\n--- Contracts ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List contracts")
		fmt.Println("2 - Create contract")
		fmt.Println("3 - Edit contract")
		fmt.Println("4 - Delete contract")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				continue
			}
			fmt.Println("\n=== Contracts for Client ===")
			for i, c := range contracts {
				dependent := ""
				if c.DependentID != nil {
					dependent = *c.DependentID
				}
				status := c.Status()
				fmt.Printf("%d - ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Dependent: %s\n",
					i+1, c.ID, c.Model, c.ProductKey, status, c.StartDate.Format("2006-01-02"), c.EndDate.Format("2006-01-02"), dependent)
			}
		case "2":
			contractsSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
		case "3":
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil || len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				continue
			}
			fmt.Println("Select a contract to edit by number:")
			for i, c := range contracts {
				fmt.Printf("%d - %s | %s\n", i+1, c.Model, c.ProductKey)
			}
			fmt.Print("Enter the number of the contract: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(contracts) {
				fmt.Println("Invalid selection.")
				continue
			}
			contract := &contracts[idx-1]
			fmt.Printf("Current model: %s | New model: ", contract.Model)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current key: %s | New key: ", contract.ProductKey)
			productKey, _ := reader.ReadString('\n')
			fmt.Printf("Current start date: %s | New date (YYYY-MM-DD): ", contract.StartDate.Format("2006-01-02"))
			startStr, _ := reader.ReadString('\n')
			fmt.Printf("Current end date: %s | New date (YYYY-MM-DD): ", contract.EndDate.Format("2006-01-02"))
			endStr, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			productKey = strings.TrimSpace(productKey)

			if name == "" {
				fmt.Println("Error: Contract model cannot be empty.")
				continue
			}
			if productKey == "" {
				fmt.Println("Error: Product key cannot be empty.")
				continue
			}

			startDate := contract.StartDate
			endDate := contract.EndDate
			if strings.TrimSpace(startStr) != "" {
				parsedStart, errStart := time.Parse("2006-01-02", strings.TrimSpace(startStr))
				if errStart != nil {
					fmt.Println("Error: Invalid start date format. Use YYYY-MM-DD.")
					continue
				}
				startDate = parsedStart
			}
			if strings.TrimSpace(endStr) != "" {
				parsedEnd, errEnd := time.Parse("2006-01-02", strings.TrimSpace(endStr))
				if errEnd != nil {
					fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
					continue
				}
				endDate = parsedEnd
			}

			contract.Model = name
			contract.ProductKey = productKey
			contract.StartDate = startDate
			contract.EndDate = endDate
			err = contractStore.UpdateContract(*contract)
			if err != nil {
				fmt.Println("Error updating contract:", err)
			} else {
				fmt.Println("Contract updated.")
			}
		case "4":
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil || len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				continue
			}
			fmt.Println("Select a contract to delete by number:")
			for i, c := range contracts {
				fmt.Printf("%d - %s | %s\n", i+1, c.Model, c.ProductKey)
			}
			fmt.Print("Enter the number of the contract: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(contracts) {
				fmt.Println("Invalid selection.")
				continue
			}
			contractID := contracts[idx-1].ID
			err = contractStore.DeleteContract(contractID)
			if err != nil {
				fmt.Println("Error deleting contract:", err)
			} else {
				fmt.Println("Contract deleted.")
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}
