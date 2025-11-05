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

// CategoriesMenu handles the categories CRUD operations
func CategoriesMenu(categoryStore *store.CategoryStore, lineStore *store.LineStore) {
	for {
		fmt.Println("\n--- Categories Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List categories")
		fmt.Println("2 - Create category")
		fmt.Println("3 - Select category")
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
			fmt.Println("Select a category by number:")
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
			CategorySubmenu(category, categoryStore, lineStore)
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

// CategorySubmenu handles operations for a selected category
func CategorySubmenu(category domain.Category, categoryStore *store.CategoryStore, lineStore *store.LineStore) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Printf("\n--- Category: %s ---\n", category.Name)
		fmt.Println("0 - Back")
		fmt.Println("1 - Edit category")
		fmt.Println("2 - View lines in this category")
		fmt.Println("3 - Add line to this category")
		fmt.Println("4 - Edit line in this category")
		fmt.Println("5 - Delete line from this category")
		fmt.Print("Option: ")
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			// Edit category
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", category.Name)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				name = category.Name
			}
			category.Name = name
			err := categoryStore.UpdateCategory(category)
			if err != nil {
				fmt.Println("Error updating category:", err)
			} else {
				fmt.Println("Category updated.")
			}
		case "2":
			// View lines in this category
			lines, err := lineStore.GetLinesByCategoryID(category.ID)
			if err != nil {
				fmt.Println("Error retrieving lines:", err)
				continue
			}
			if len(lines) == 0 {
				fmt.Println("No lines found in this category.")
				continue
			}
			fmt.Println("Lines in this category:")
			for i, line := range lines {
				fmt.Printf("%d - ID: %s | Name: %s\n", i+1, line.ID, line.Line)
			}
		case "3":
			// Add line to this category
			fmt.Print("Line name: ")
			lineName, _ := reader.ReadString('\n')
			lineName = strings.TrimSpace(lineName)
			if lineName == "" {
				fmt.Println("Error: Line name cannot be empty.")
				continue
			}
			id, err := lineStore.CreateLine(domain.Line{
				Line:       lineName,
				CategoryID: category.ID,
			})
			if err != nil {
				fmt.Println("Error creating line:", err)
			} else {
				fmt.Println("Line created with ID:", id)
			}
		case "4":
			// Edit line in this category
			lines, err := lineStore.GetLinesByCategoryID(category.ID)
			if err != nil || len(lines) == 0 {
				fmt.Println("No lines found in this category.")
				continue
			}
			fmt.Println("Select a line to edit by number:")
			for i, line := range lines {
				fmt.Printf("%d - ID: %s | Name: %s\n", i+1, line.ID, line.Line)
			}
			fmt.Print("Enter the number of the line: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(lines) {
				fmt.Println("Invalid selection.")
				continue
			}
			lineObj := lines[idx-1]
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", lineObj.Line)
			lineName, _ := reader.ReadString('\n')
			lineName = strings.TrimSpace(lineName)
			if lineName == "" {
				lineName = lineObj.Line
			}
			lineObj.Line = lineName
			err = lineStore.UpdateLine(lineObj)
			if err != nil {
				fmt.Println("Error updating line:", err)
			} else {
				fmt.Println("Line updated.")
			}
		case "5":
			// Delete line from this category
			lines, err := lineStore.GetLinesByCategoryID(category.ID)
			if err != nil || len(lines) == 0 {
				fmt.Println("No lines found in this category.")
				continue
			}
			fmt.Println("Select a line to delete by number:")
			for i, line := range lines {
				fmt.Printf("%d - ID: %s | Name: %s\n", i+1, line.ID, line.Line)
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
