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
	"strconv"
	"strings"

	domain "Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

// LinesMenu handles the subcategories (contract types) administration menu
func LinesMenu(subcategoryStore *store.SubcategoryStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- contract Lines ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all subcategories")
		fmt.Println("2 - Search/Filter subcategories")
		fmt.Println("3 - Edit line")
		fmt.Println("4 - Create line")
		fmt.Println("5 - Delete line")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			subcategories, err := subcategoryStore.GetAllSubcategories()
			if err != nil {
				fmt.Println("Error listing subcategories:", err)
				waitForEnter()
				continue
			}
			displayLinesList(subcategories)
			waitForEnter()
		case "2":
			clearTerminal()
			fmt.Println("\n=== Search/Filter Lines ===")
			fmt.Print("Enter search term (line name): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm == "" {
				fmt.Println("Search term cannot be empty.")
				waitForEnter()
				continue
			}

			subcategories, err := subcategoryStore.GetAllSubcategories()
			if err != nil {
				fmt.Println("Error listing subcategories:", err)
				waitForEnter()
				continue
			}

			filtered := filterLines(subcategories, searchTerm)
			displayLinesList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
			fmt.Print("Buscar linha para editar por (1) ID ou (2) nome? ")
			searchOpt, _ := reader.ReadString('\n')
			searchOpt = strings.TrimSpace(searchOpt)
			var lineObj *domain.Subcategory
			if searchOpt == "2" {
				fmt.Print("Digite parte do nome da linha: ")
				searchName, _ := reader.ReadString('\n')
				searchName = strings.TrimSpace(searchName)
				subcategories, err := subcategoryStore.GetSubcategoriesByName(searchName)
				if err != nil || len(subcategories) == 0 {
					fmt.Println("Nenhuma linha encontrada.")
					waitForEnter()
					continue
				}
				for i, l := range subcategories {
					fmt.Printf("%d - ID: %s | Nome: %s | Categoria: %s\n", i+1, l.ID, l.Name, l.CategoryID)
				}
				fmt.Print("Escolha o número da linha: ")
				idxStr, _ := reader.ReadString('\n')
				idxStr = strings.TrimSpace(idxStr)
				idx, err := strconv.Atoi(idxStr)
				if err != nil || idx < 1 || idx > len(subcategories) {
					fmt.Println("Opção inválida.")
					waitForEnter()
					continue
				}
				lineObj = &subcategories[idx-1]
			} else {
				fmt.Print("Subcategory ID to edit: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: Subcategory ID cannot be empty.")
					waitForEnter()
					continue
				}
				l, err := subcategoryStore.GetSubcategoryByID(id)
				if err != nil || l == nil {
					fmt.Println("Linha não encontrada.")
					waitForEnter()
					continue
				}
				lineObj = l
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", lineObj.Name)
			line, _ := reader.ReadString('\n')
			fmt.Printf("Current category: %s | New category for line: ", lineObj.CategoryID)
			categoryID, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			categoryID = strings.TrimSpace(categoryID)
			// Handle required fields: empty keeps current value
			if line == "" {
				line = lineObj.Name
			}
			if categoryID == "" {
				categoryID = lineObj.CategoryID
			}
			lineObj.Name = line
			lineObj.CategoryID = categoryID
			err := subcategoryStore.UpdateSubcategory(*lineObj)
			if err != nil {
				fmt.Println("Error updating line:", err)
				waitForEnter()
			} else {
				fmt.Println("Subcategory updated.")
				waitForEnter()
			}
		case "4":
			clearTerminal()
			reader := bufio.NewReader(os.Stdin)

			categories, err := categoryStore.GetAllCategories()
			if err != nil || len(categories) == 0 {
				fmt.Println("No categories found. Please create a category first.")
				waitForEnter()
				continue
			}

			fmt.Println("\n=== Select Category ===")
			displayCategoriesList(categories)
			fmt.Print("\nEnter the number of the category: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(categories) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			categoryID := categories[idx-1].ID

			fmt.Print("Subcategory name: ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				fmt.Println("Error: Subcategory name cannot be empty.")
				waitForEnter()
				continue
			}

			id, err := subcategoryStore.CreateSubcategory(domain.Subcategory{
				Name:       line,
				CategoryID: categoryID,
			})
			if err != nil {
				fmt.Println("Error creating line:", err)
				waitForEnter()
			} else {
				fmt.Println("Subcategory created with ID:", id)
				waitForEnter()
			}
		case "5":
			clearTerminal()
			subcategories, err := subcategoryStore.GetAllSubcategories()
			if err != nil || len(subcategories) == 0 {
				fmt.Println("No subcategories found.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a line to delete by number:")
			for i, t := range subcategories {
				fmt.Printf("%d - %s (Category: %s)\n", i+1, t.Name, t.CategoryID)
			}
			fmt.Print("Enter the number of the line: ")
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
			err = subcategoryStore.DeleteSubcategory(subcategoryID)
			if err != nil {
				fmt.Println("Error deleting line:", err)
				waitForEnter()
			} else {
				fmt.Println("Subcategory deleted.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// filterLines filters subcategories by name
func filterLines(subcategories []domain.Subcategory, searchTerm string) []domain.Subcategory {
	var filtered []domain.Subcategory
	searchTerm = normalizeString(searchTerm)

	for _, l := range subcategories {
		if strings.Contains(normalizeString(l.Name), searchTerm) {
			filtered = append(filtered, l)
			continue
		}
	}

	return filtered
}
