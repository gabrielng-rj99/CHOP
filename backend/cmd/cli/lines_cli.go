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
