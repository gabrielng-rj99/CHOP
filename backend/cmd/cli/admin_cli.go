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
	"strings"

	domain "Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

// AdministrationFlow handles the administration menu and routes to subcategories
func AdministrationFlow(categoryStore *store.CategoryStore, subcategoryStore *store.SubcategoryStore, userStore *store.UserStore, user *domain.User) {
	for {
		clearTerminal()
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
			CategoriesMenu(categoryStore, subcategoryStore)
		case "2":
			LinesMenu(subcategoryStore, categoryStore)
		case "3":
			UsersMenu(userStore, user)
		default:
			fmt.Println("Invalid option.")
		}
	}
}
