/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

// ContractsFlow handles the agreements overview menu (list, filter, create, edit, delete)
func ContractsFlow(agreementStore *store.AgreementStore, entityStore *store.EntityStore, subEntityStore *store.SubEntityStore, subcategoryStore *store.SubcategoryStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- Contracts (Overview) ---")
		fmt.Println("0 - Back")
		fmt.Println("1 - List all agreements")
		fmt.Println("2 - Search/Filter agreements")
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
			agreements, err := agreementStore.GetAllAgreements()
			if err != nil {
				fmt.Println("Error listing agreements:", err)
				waitForEnter()
				continue
			}
			displayContractsList(agreements)
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

			agreements, err := agreementStore.GetAllAgreements()
			if err != nil {
				fmt.Println("Error listing agreements:", err)
				waitForEnter()
				continue
			}

			filtered := filterContracts(agreements, searchTerm)
			displayContractsList(filtered)
			waitForEnter()

		case "3":
			clearTerminal()
			entities, err := entityStore.GetAllEntities()
			if err != nil || len(entities) == 0 {
				fmt.Println("No entities found.")
				waitForEnter()
				continue
			}

			fmt.Println("\n=== Select Entity ===")
			fmt.Print("Search term (or leave empty for all): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm != "" {
				entities = filterClients(entities, searchTerm)
			}

			if len(entities) == 0 {
				fmt.Println("No entities match your search.")
				waitForEnter()
				continue
			}

			displayClientsList(entities)
			fmt.Print("\nEnter the number of the client (0 to cancel): ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(entities) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			entityID := entities[idx-1].ID

			agreements, err := agreementStore.GetAgreementsByEntityID(entityID)
			if err != nil {
				fmt.Println("Error listing agreements:", err)
				waitForEnter()
				continue
			}
			displayContractsList(agreements)
			waitForEnter()
		case "4":
			clearTerminal()
			subcategories, err := subcategoryStore.GetAllSubcategories()
			if err != nil || len(subcategories) == 0 {
				fmt.Println("No subcategories found.")
				waitForEnter()
				continue
			}

			fmt.Println("\n=== Select Subcategory ===")
			displayLinesList(subcategories)
			fmt.Print("\nEnter the number of the line (0 to cancel): ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(subcategories) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			subcategoryID := subcategories[idx-1].ID

			agreements, err := agreementStore.GetAgreementsBySubcategoryID(subcategoryID)
			if err != nil {
				fmt.Println("Error listing agreements:", err)
				waitForEnter()
				continue
			}
			displayContractsList(agreements)
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

			agreements, err := agreementStore.GetAgreementsByCategoryID(categoryID)
			if err != nil {
				fmt.Println("Error listing agreements:", err)
				waitForEnter()
				continue
			}
			displayContractsList(agreements)
			waitForEnter()
		case "7":
			clearTerminal()
			fmt.Print("Buscar contrato para editar por (1) ID ou (2) nome/modelo? ")
			searchOpt, _ := reader.ReadString('\n')
			searchOpt = strings.TrimSpace(searchOpt)
			var agreement *domain.Agreement
			if searchOpt == "2" {
				fmt.Print("Digite parte do nome/modelo: ")
				searchName, _ := reader.ReadString('\n')
				searchName = strings.TrimSpace(searchName)
				agreements, err := agreementStore.GetAgreementsByName(searchName)
				if err != nil || len(agreements) == 0 {
					fmt.Println("Nenhum contrato encontrado.")
					waitForEnter()
					continue
				}
				for i, c := range agreements {
					fmt.Printf("%d - ID: %s | Modelo: %s | Produto: %s\n", i+1, c.ID, c.Model, c.ItemKey)
				}
				fmt.Print("Escolha o número do contrato: ")
				idxStr, _ := reader.ReadString('\n')
				idxStr = strings.TrimSpace(idxStr)
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > len(agreements) {
					fmt.Println("Opção inválida.")
					waitForEnter()
					continue
				}
				agreement = &agreements[idx-1]
			} else {
				fmt.Print("agreement ID to edit: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: agreement ID cannot be empty.")
					waitForEnter()
					continue
				}
				c, err := agreementStore.GetAgreementByID(id)
				if err != nil || c == nil {
					fmt.Println("agreement not found.")
					waitForEnter()
					continue
				}
				agreement = c
			}
			reader := bufio.NewReader(os.Stdin)
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", agreement.Model)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current key: %s | New key: ", agreement.ItemKey)
			itemKey, _ := reader.ReadString('\n')
			fmt.Printf("Current start date: %s | New date (YYYY-MM-DD): ", agreement.StartDate.Format("2006-01-02"))
			startStr, _ := reader.ReadString('\n')
			fmt.Printf("Current end date: %s | New date (YYYY-MM-DD): ", agreement.EndDate.Format("2006-01-02"))
			endStr, _ := reader.ReadString('\n')
			fmt.Printf("Current type ID: %s | New type ID: ", agreement.SubcategoryID)
			subcategoryID, _ := reader.ReadString('\n')
			currentSubEntityID := "-"
			if agreement.SubEntityID != nil {
				currentSubEntityID = *agreement.SubEntityID
			}
			fmt.Printf("Current dependent ID: %s | New dependent (optional): ", currentSubEntityID)
			subEntityID, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			itemKey = strings.TrimSpace(itemKey)
			subcategoryID = strings.TrimSpace(subcategoryID)

			// Handle required fields: empty keeps current value
			if name == "" {
				name = agreement.Model
			}
			if itemKey == "" {
				itemKey = agreement.ItemKey
			}
			if subcategoryID == "" {
				subcategoryID = agreement.SubcategoryID
			}

			startDate := agreement.StartDate
			endDate := agreement.EndDate
			if strings.TrimSpace(startStr) != "" {
				parsedStart, errStart := time.Parse("2006-01-02", strings.TrimSpace(startStr))
				if errStart != nil {
					fmt.Println("Error: Invalid start date format. Use YYYY-MM-DD.")
					waitForEnter()
					continue
				}
				startDate = &parsedStart
			}
			if strings.TrimSpace(endStr) != "" {
				parsedEnd, errEnd := time.Parse("2006-01-02", strings.TrimSpace(endStr))
				if errEnd != nil {
					fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
					waitForEnter()
					continue
				}
				endDate = &parsedEnd
			}
			agreement.Model = name
			agreement.ItemKey = itemKey
			agreement.StartDate = startDate
			agreement.EndDate = endDate
			agreement.SubcategoryID = subcategoryID
			// Handle optional dependent ID: "-" clears it, empty keeps it, other value updates it
			depVal, depUpdate, depClear := HandleOptionalField(subEntityID)
			if depUpdate {
				if depClear {
					agreement.SubEntityID = nil
				} else {
					agreement.SubEntityID = &depVal
				}
			}
			err := agreementStore.UpdateAgreement(*agreement)
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
				agreements, err := agreementStore.GetAgreementsByName(searchName)
				if err != nil || len(agreements) == 0 {
					fmt.Println("Nenhum contrato encontrado.")
					waitForEnter()
					continue
				}
				for i, c := range agreements {
					fmt.Printf("%d - ID: %s | Modelo: %s | Produto: %s\n", i+1, c.ID, c.Model, c.ItemKey)
				}
				fmt.Print("Escolha o número do contrato para excluir: ")
				idxStr, _ := reader.ReadString('\n')
				idxStr = strings.TrimSpace(idxStr)
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > len(agreements) {
					fmt.Println("Opção inválida.")
					waitForEnter()
					continue
				}
				contractID = agreements[idx-1].ID
			} else {
				fmt.Print("agreement ID to delete: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: agreement ID cannot be empty.")
					waitForEnter()
					continue
				}
				contractID = id
			}
			err := agreementStore.DeleteAgreement(contractID)
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
func ContractsSubmenu(entityID string, agreementStore *store.AgreementStore, subEntityStore *store.SubEntityStore, subcategoryStore *store.SubcategoryStore, categoryStore *store.CategoryStore) {
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

	// 2. Select Subcategory
	fmt.Println("Select a line (type) for the contract:")
	subcategories, err := subcategoryStore.GetSubcategoriesByCategoryID(categoryID)
	if err != nil || len(subcategories) == 0 {
		fmt.Println("Error: No subcategories available for this category.")
		waitForEnter()
		return
	}
	for i, l := range subcategories {
		fmt.Printf("%d - %s\n", i+1, l.Name)
	}
	fmt.Print("Enter the number of the line: ")
	lineIdxStr, _ := reader.ReadString('\n')
	lineIdxStr = strings.TrimSpace(lineIdxStr)
	lineIdx, err := strconv.Atoi(lineIdxStr)
	if err != nil || lineIdx < 1 || lineIdx > len(subcategories) {
		fmt.Println("Error: Invalid line selection.")
		waitForEnter()
		return
	}
	subcategoryID := subcategories[lineIdx-1].ID

	// 3. Enter contract model/name
	fmt.Print("Agreement model/name: ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("Error: Agreement model/name cannot be empty.")
		waitForEnter()
		return
	}

	// 4. Enter product key
	fmt.Print("Product key: ")
	itemKey, _ := reader.ReadString('\n')
	itemKey = strings.TrimSpace(itemKey)
	if itemKey == "" {
		fmt.Println("Error: Product key cannot be empty.")
		waitForEnter()
		return
	}

	// 5. Dates (optional - press Enter to skip)
	fmt.Print("Start date (YYYY-MM-DD, or press Enter for no start date): ")
	startStr, _ := reader.ReadString('\n')
	fmt.Print("End date (YYYY-MM-DD, or press Enter for no end date/never expires): ")
	endStr, _ := reader.ReadString('\n')

	var startDate, endDate *time.Time
	startStr = strings.TrimSpace(startStr)
	if startStr != "" {
		parsed, errStart := time.Parse("2006-01-02", startStr)
		if errStart != nil {
			fmt.Println("Error: Invalid start date format. Use YYYY-MM-DD.")
			waitForEnter()
			return
		}
		startDate = &parsed
	}

	endStr = strings.TrimSpace(endStr)
	if endStr != "" {
		parsed, errEnd := time.Parse("2006-01-02", endStr)
		if errEnd != nil {
			fmt.Println("Error: Invalid end date format. Use YYYY-MM-DD.")
			waitForEnter()
			return
		}
		endDate = &parsed
	}

	// 6. Select sub_entities (optional, comma-separated for multiple, or Enter for global)
	sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(entityID)
	var dependentPtr *string
	if err == nil && len(sub_entities) > 0 {
		fmt.Println("Select sub_entities for this contract (optional).")
		fmt.Println("Enter the numbers separated by commas for multiple selection, or press Enter for global contract (no sub_entities):")
		for i, d := range sub_entities {
			fmt.Printf("%d - %s\n", i+1, d.Name)
		}
		fmt.Print("Dependents: ")
		depIdxStr, _ := reader.ReadString('\n')
		depIdxStr = strings.TrimSpace(depIdxStr)
		if depIdxStr != "" {
			depIdxList := strings.Split(depIdxStr, ",")
			if len(depIdxList) > 1 {
				fmt.Println("Warning: Only one dependent can be associated per agreement. Using the first selected.")
			}
			idxStr := strings.TrimSpace(depIdxList[0])
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(sub_entities) {
				fmt.Println("Error: Invalid dependent selection.")
				waitForEnter()
				return
			}
			depID := sub_entities[idx-1].ID
			dependentPtr = &depID
		}
	}

	contract := domain.Agreement{
		Model:       name,
		ItemKey:  itemKey,
		StartDate:   startDate,
		EndDate:     endDate,
		SubcategoryID:      subcategoryID,
		EntityID:    entityID,
		SubEntityID: dependentPtr,
	}
	id, err := agreementStore.CreateAgreement(contract)
	if err != nil {
		fmt.Println("Error creating contract:", err)
		waitForEnter()
	} else {
		fmt.Println("Agreement created with ID:", id)
		waitForEnter()
	}
}

// displayContractsList shows a compact list of agreements with essential information
func displayContractsList(agreements []domain.Agreement) {
	fmt.Println("\n=== Contracts ===")
	if len(agreements) == 0 {
		fmt.Println("No agreements found.")
		return
	}

	fmt.Printf("\n%-4s | %-25s | %-25s | %-12s | %-12s | %-12s\n", "#", "Model", "Product Key", "Status", "Start Date", "End Date")
	fmt.Println(strings.Repeat("-", 100))

	for i, c := range agreements {
		model := c.Model
		if len(model) > 25 {
			model = model[:22] + "..."
		}

		itemKey := c.ItemKey
		if len(itemKey) > 25 {
			itemKey = itemKey[:22] + "..."
		}

		status := c.Status()
		startDate := "N/A"
		if c.StartDate != nil {
			startDate = c.StartDate.Format("2006-01-02")
		}
		endDate := "Never"
		if c.EndDate != nil {
			endDate = c.EndDate.Format("2006-01-02")
		}

		fmt.Printf("%-4d | %-25s | %-25s | %-12s | %-12s | %-12s\n", i+1, model, itemKey, status, startDate, endDate)
	}
	fmt.Println()
}

// filterContracts filters agreements by model or product key
func filterContracts(agreements []domain.Agreement, searchTerm string) []domain.Agreement {
	var filtered []domain.Agreement
	searchTerm = normalizeString(searchTerm)

	for _, c := range agreements {
		if strings.Contains(normalizeString(c.Model), searchTerm) {
			filtered = append(filtered, c)
			continue
		}

		if strings.Contains(normalizeString(c.ItemKey), searchTerm) {
			filtered = append(filtered, c)
			continue
		}
	}

	return filtered
}

// displayLinesList shows a compact list of subcategories sorted by category
func displayLinesList(subcategories []domain.Subcategory) {
	fmt.Println("\n=== Lines ===")
	if len(subcategories) == 0 {
		fmt.Println("No subcategories found.")
		return
	}

	// Group subcategories by category
	categoryMap := make(map[string][]domain.Subcategory)
	for _, l := range subcategories {
		categoryMap[l.CategoryID] = append(categoryMap[l.CategoryID], l)
	}

	// Sort categories
	categories := make([]string, 0, len(categoryMap))
	for cat := range categoryMap {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	fmt.Printf("\n%-4s | %-40s | %-30s\n", "#", "Subcategory Name", "Category")
	fmt.Println(strings.Repeat("-", 80))

	count := 0
	for _, cat := range categories {
		categoryLines := categoryMap[cat]

		// Sort subcategories within category
		sort.Slice(categoryLines, func(i, j int) bool {
			return categoryLines[i].Name < categoryLines[j].Name
		})

		for _, l := range categoryLines {
			count++
			name := l.Name
			if len(name) > 40 {
				name = name[:37] + "..."
			}

			category := cat
			if len(category) > 30 {
				category = category[:27] + "..."
			}

			fmt.Printf("%-4d | %-40s | %-30s\n", count, name, category)
		}
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
