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

// LinesMenu handles the lines (contract types) administration menu
func LinesMenu(lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- contract Lines ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all lines")
		fmt.Println("2 - Search/Filter lines")
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
			lines, err := lineStore.GetAllLines()
			if err != nil {
				fmt.Println("Error listing lines:", err)
				waitForEnter()
				continue
			}
			displayLinesList(lines)
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

			lines, err := lineStore.GetAllLines()
			if err != nil {
				fmt.Println("Error listing lines:", err)
				waitForEnter()
				continue
			}

			filtered := filterLines(lines, searchTerm)
			displayLinesList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
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
					waitForEnter()
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
					waitForEnter()
					continue
				}
				lineObj = &lines[idx-1]
			} else {
				fmt.Print("Line ID to edit: ")
				id, _ := reader.ReadString('\n')
				id = strings.TrimSpace(id)
				if id == "" {
					fmt.Println("Error: Line ID cannot be empty.")
					waitForEnter()
					continue
				}
				l, err := lineStore.GetLineByID(id)
				if err != nil || l == nil {
					fmt.Println("Linha não encontrada.")
					waitForEnter()
					continue
				}
				lineObj = l
			}
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", lineObj.Line)
			line, _ := reader.ReadString('\n')
			fmt.Printf("Current category: %s | New category for line: ", lineObj.CategoryID)
			categoryID, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			categoryID = strings.TrimSpace(categoryID)
			// Handle required fields: empty keeps current value
			if line == "" {
				line = lineObj.Line
			}
			if categoryID == "" {
				categoryID = lineObj.CategoryID
			}
			lineObj.Line = line
			lineObj.CategoryID = categoryID
			err := lineStore.UpdateLine(*lineObj)
			if err != nil {
				fmt.Println("Error updating line:", err)
				waitForEnter()
			} else {
				fmt.Println("Line updated.")
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

			fmt.Print("Line name: ")
			line, _ := reader.ReadString('\n')
			line = strings.TrimSpace(line)
			if line == "" {
				fmt.Println("Error: Line name cannot be empty.")
				waitForEnter()
				continue
			}

			id, err := lineStore.CreateLine(domain.Line{
				Line:       line,
				CategoryID: categoryID,
			})
			if err != nil {
				fmt.Println("Error creating line:", err)
				waitForEnter()
			} else {
				fmt.Println("Line created with ID:", id)
				waitForEnter()
			}
		case "5":
			clearTerminal()
			lines, err := lineStore.GetAllLines()
			if err != nil || len(lines) == 0 {
				fmt.Println("No lines found.")
				waitForEnter()
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
				waitForEnter()
				continue
			}
			lineID := lines[idx-1].ID
			err = lineStore.DeleteLine(lineID)
			if err != nil {
				fmt.Println("Error deleting line:", err)
				waitForEnter()
			} else {
				fmt.Println("Line deleted.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// filterLines filters lines by name
func filterLines(lines []domain.Line, searchTerm string) []domain.Line {
	var filtered []domain.Line
	searchTerm = normalizeString(searchTerm)

	for _, l := range lines {
		if strings.Contains(normalizeString(l.Line), searchTerm) {
			filtered = append(filtered, l)
			continue
		}
	}

	return filtered
}
