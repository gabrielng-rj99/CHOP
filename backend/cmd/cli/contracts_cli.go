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
			ContractsSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
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

// ContractsSubmenu handles contract creation for a specific client
func ContractsSubmenu(clientID string, contractStore *store.ContractStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
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
