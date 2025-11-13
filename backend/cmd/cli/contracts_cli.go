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

// ContractsFlow handles the contracts overview menu (list, filter, create, edit, delete)
func ContractsFlow(contractStore *store.ContractStore, clientStore *store.ClientStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- Contracts (Overview) ---")
		fmt.Println("0 - Back")
		fmt.Println("1 - List all contracts")
		fmt.Println("2 - Search/Filter contracts")
		fmt.Println("3 - Filter by client")
		fmt.Println("4 - Filter by line")
		fmt.Println("5 - Filter by category")
		fmt.Println("6 - Create contract")
		fmt.Println("7 - Edit contract")
		fmt.Println("8 - Delete contract")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			contracts, err := contractStore.GetAllContracts()
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				waitForEnter()
				continue
			}
			displayContractsList(contracts)
			waitForEnter()

		case "2":
			clearTerminal()
			fmt.Println("\n=== Search/Filter Contracts ===")
			fmt.Print("Enter search term (model, product key): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm == "" {
				fmt.Println("Search term cannot be empty.")
				waitForEnter()
				continue
			}

			contracts, err := contractStore.GetAllContracts()
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				waitForEnter()
				continue
			}

			filtered := filterContracts(contracts, searchTerm)
			displayContractsList(filtered)
			waitForEnter()

		case "3":
			clearTerminal()
			clients, err := clientStore.GetAllClients()
			if err != nil || len(clients) == 0 {
				fmt.Println("No clients found.")
				waitForEnter()
				continue
			}

			fmt.Println("\n=== Select Client ===")
			fmt.Print("Search term (or leave empty for all): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm != "" {
				clients = filterClients(clients, searchTerm)
			}

			if len(clients) == 0 {
				fmt.Println("No clients match your search.")
				waitForEnter()
				continue
			}

			displayClientsList(clients)
			fmt.Print("\nEnter the number of the client (0 to cancel): ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(clients) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			clientID := clients[idx-1].ID

			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				waitForEnter()
				continue
			}
			displayContractsList(contracts)
			waitForEnter()
		case "4":
			clearTerminal()
			lines, err := lineStore.GetAllLines()
			if err != nil || len(lines) == 0 {
				fmt.Println("No lines found.")
				waitForEnter()
				continue
			}

			fmt.Println("\n=== Select Line ===")
			displayLinesList(lines)
			fmt.Print("\nEnter the number of the line (0 to cancel): ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(lines) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			lineID := lines[idx-1].ID

			contracts, err := contractStore.GetContractsByLineID(lineID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				waitForEnter()
				continue
			}
			displayContractsList(contracts)
			waitForEnter()
		case "5":
			clearTerminal()
			categories, err := categoryStore.GetAllCategories()
			if err != nil || len(categories) == 0 {
				fmt.Println("No categories found.")
				waitForEnter()
				continue
			}

			fmt.Println("\n=== Select Category ===")
			displayCategoriesList(categories)
			fmt.Print("\nEnter the number of the category (0 to cancel): ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(categories) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			categoryID := categories[idx-1].ID

			contracts, err := contractStore.GetContractsByCategoryID(categoryID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				waitForEnter()
				continue
			}
			displayContractsList(contracts)
			waitForEnter()
		case "7":
			clearTerminal()
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
					waitForEnter()
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
					waitForEnter()
					continue
				}
				contract = &contracts[idx-1]
			} else {
				fmt.Print("contract ID to edit: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: contract ID cannot be empty.")
					waitForEnter()
					continue
				}
				c, err := contractStore.GetContractByID(id)
				if err != nil || c == nil {
					fmt.Println("contract not found.")
					waitForEnter()
					continue
				}
				contract = c
			}
			reader := bufio.NewReader(os.Stdin)
			PrintOptionalFieldHint()
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
			currentDependentID := "-"
			if contract.DependentID != nil {
				currentDependentID = *contract.DependentID
			}
			fmt.Printf("Current dependent ID: %s | New dependent (optional): ", currentDependentID)
			dependentID, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			productKey = strings.TrimSpace(productKey)
			lineID = strings.TrimSpace(lineID)

			// Handle required fields: empty keeps current value
			if name == "" {
				name = contract.Model
			}
			if productKey == "" {
				productKey = contract.ProductKey
			}
			if lineID == "" {
				lineID = contract.LineID
			}

			startDate := contract.StartDate
			endDate := contract.EndDate
			if strings.TrimSpace(startStr) != "" {
				parsedStart, errStart := time.Parse("2006-01-02", strings.TrimSpace(startStr))
				if errStart != nil {
					fmt.Println("Error: Invalid start date format. Use YYYY-MM-DD.")
					waitForEnter()
					continue
				}
				startDate = parsedStart
			}
			if strings.TrimSpace(endStr) != "" {
				parsedEnd, errEnd := time.Parse("2006-01-02", strings.TrimSpace(endStr))
				if errEnd != nil {
					fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
					waitForEnter()
					continue
				}
				endDate = parsedEnd
			}
			contract.Model = name
			contract.ProductKey = productKey
			contract.StartDate = startDate
			contract.EndDate = endDate
			contract.LineID = lineID
			// Handle optional dependent ID: "-" clears it, empty keeps it, other value updates it
			depVal, depUpdate, depClear := HandleOptionalField(dependentID)
			if depUpdate {
				if depClear {
					contract.DependentID = nil
				} else {
					contract.DependentID = &depVal
				}
			}
			err := contractStore.UpdateContract(*contract)
			if err != nil {
				fmt.Println("Error updating contract:", err)
				waitForEnter()
			} else {
				fmt.Println("contract updated.")
				waitForEnter()
			}
		case "8":
			clearTerminal()
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
					waitForEnter()
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
					waitForEnter()
					continue
				}
				contractID = contracts[idx-1].ID
			} else {
				fmt.Print("contract ID to delete: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: contract ID cannot be empty.")
					waitForEnter()
					continue
				}
				contractID = id
			}
			err := contractStore.DeleteContract(contractID)
			if err != nil {
				fmt.Println("Error deleting contract:", err)
				waitForEnter()
			} else {
				fmt.Println("contract deleted.")
				waitForEnter()
			}

		default:
			fmt.Println("Invalid option.")
		}
	}
}

// ContractsSubmenu handles contract creation for a specific client
func ContractsSubmenu(clientID string, contractStore *store.ContractStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	clearTerminal()
	reader := bufio.NewReader(os.Stdin)

	// 1. Select Category
	fmt.Println("Select a category for the contract:")
	categories, err := categoryStore.GetAllCategories()
	if err != nil || len(categories) == 0 {
		fmt.Println("Error: No categories available.")
		waitForEnter()
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
		waitForEnter()
		return
	}
	categoryID := categories[catIdx-1].ID

	// 2. Select Line
	fmt.Println("Select a line (type) for the contract:")
	lines, err := lineStore.GetLinesByCategoryID(categoryID)
	if err != nil || len(lines) == 0 {
		fmt.Println("Error: No lines available for this category.")
		waitForEnter()
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
		waitForEnter()
		return
	}
	lineID := lines[lineIdx-1].ID

	// 3. Enter contract model/name
	fmt.Print("Contract model/name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Error: Contract model/name cannot be empty.")
		waitForEnter()
		return
	}

	// 4. Enter product key
	fmt.Print("Product key: ")
	productKey, _ := reader.ReadString('\n')
	productKey = strings.TrimSpace(productKey)
	if productKey == "" {
		fmt.Println("Error: Product key cannot be empty.")
		waitForEnter()
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
		waitForEnter()
		return
	}
	endDate, errEnd := time.Parse("2006-01-02", strings.TrimSpace(endStr))
	if errEnd != nil {
		fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
		waitForEnter()
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
				waitForEnter()
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
		waitForEnter()
	} else {
		fmt.Println("Contract created with ID:", id)
		waitForEnter()
	}
}

// displayContractsList shows a compact list of contracts with essential information
func displayContractsList(contracts []domain.Contract) {
	fmt.Println("\n=== Contracts ===")
	if len(contracts) == 0 {
		fmt.Println("No contracts found.")
		return
	}

	fmt.Printf("\n%-4s | %-25s | %-25s | %-12s | %-12s | %-12s\n", "#", "Model", "Product Key", "Status", "Start Date", "End Date")
	fmt.Println(strings.Repeat("-", 100))

	for i, c := range contracts {
		model := c.Model
		if len(model) > 25 {
			model = model[:22] + "..."
		}

		productKey := c.ProductKey
		if len(productKey) > 25 {
			productKey = productKey[:22] + "..."
		}

		status := c.Status()
		startDate := c.StartDate.Format("2006-01-02")
		endDate := c.EndDate.Format("2006-01-02")

		fmt.Printf("%-4d | %-25s | %-25s | %-12s | %-12s | %-12s\n", i+1, model, productKey, status, startDate, endDate)
	}
	fmt.Println()
}

// filterContracts filters contracts by model or product key
func filterContracts(contracts []domain.Contract, searchTerm string) []domain.Contract {
	var filtered []domain.Contract
	searchTerm = normalizeString(searchTerm)

	for _, c := range contracts {
		if strings.Contains(normalizeString(c.Model), searchTerm) {
			filtered = append(filtered, c)
			continue
		}

		if strings.Contains(normalizeString(c.ProductKey), searchTerm) {
			filtered = append(filtered, c)
			continue
		}
	}

	return filtered
}

// displayLinesList shows a compact list of lines
func displayLinesList(lines []domain.Line) {
	fmt.Println("\n=== Lines ===")
	if len(lines) == 0 {
		fmt.Println("No lines found.")
		return
	}

	fmt.Printf("\n%-4s | %-40s | %-30s\n", "#", "Name", "Category")
	fmt.Println(strings.Repeat("-", 80))

	for i, l := range lines {
		name := l.Line
		if len(name) > 40 {
			name = name[:37] + "..."
		}

		category := l.CategoryID
		if len(category) > 30 {
			category = category[:27] + "..."
		}

		fmt.Printf("%-4d | %-40s | %-30s\n", i+1, name, category)
	}
	fmt.Println()
}

// displayCategoriesList shows a compact list of categories
func displayCategoriesList(categories []domain.Category) {
	fmt.Println("\n=== Categories ===")
	if len(categories) == 0 {
		fmt.Println("No categories found.")
		return
	}

	fmt.Printf("\n%-4s | %-50s\n", "#", "Name")
	fmt.Println(strings.Repeat("-", 60))

	for i, c := range categories {
		name := c.Name
		if len(name) > 50 {
			name = name[:47] + "..."
		}

		fmt.Printf("%-4d | %-50s\n", i+1, name)
	}
	fmt.Println()
}
