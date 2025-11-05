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
func CategoriesMenu(categoryStore *store.CategoryStore) {
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
