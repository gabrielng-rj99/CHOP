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
	"time"

	"Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/store"
)

// ClientsFlow handles the entities menu, allowing listing, creation, and selection
func ClientsFlow(entityStore *store.EntityStore, subEntityStore *store.SubEntityStore, agreementStore *store.AgreementStore, subcategoryStore *store.SubcategoryStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- Clients Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all entities")
		fmt.Println("2 - Search/Filter entities")
		fmt.Println("3 - Create client")
		fmt.Println("4 - Select client")
		fmt.Println("5 - List archived entities")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			entities, err := entityStore.GetAllEntities()
			if err != nil {
				fmt.Println("Error listing entities:", err)
				waitForEnter()
				continue
			}
			displayClientsList(entities)
			waitForEnter()
		case "2":
			clearTerminal()
			fmt.Println("\n=== Search/Filter Clients ===")
			fmt.Print("Enter search term (name, nickname, or registration ID): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm == "" {
				fmt.Println("Search term cannot be empty.")
				waitForEnter()
				continue
			}

			entities, err := entityStore.GetAllEntities()
			if err != nil {
				fmt.Println("Error listing entities:", err)
				waitForEnter()
				continue
			}

			filtered := filterClients(entities, searchTerm)
			displayClientsList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("=== Create New Entity ===")
			fmt.Print("Entity name (required): ")
			name, _ := reader.ReadString('\n')
			fmt.Print("Registration ID (optional, CPF/CNPJ): ")
			registrationID, _ := reader.ReadString('\n')
			fmt.Print("Nickname/Trade name (optional): ")
			nickname, _ := reader.ReadString('\n')
			fmt.Print("Birth/Foundation date (optional, YYYY-MM-DD): ")
			birthDateStr, _ := reader.ReadString('\n')
			fmt.Print("Email (optional): ")
			email, _ := reader.ReadString('\n')
			fmt.Print("Phone (optional, E.164 format): ")
			phone, _ := reader.ReadString('\n')
			fmt.Print("Address (optional): ")
			address, _ := reader.ReadString('\n')
			fmt.Print("Notes (optional): ")
			notes, _ := reader.ReadString('\n')
			fmt.Print("Contact preference (optional: whatsapp/email/phone/sms/outros): ")
			contactPref, _ := reader.ReadString('\n')
			fmt.Print("Tags (optional, comma-separated): ")
			tags, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			registrationID = strings.TrimSpace(registrationID)
			nickname = strings.TrimSpace(nickname)
			birthDateStr = strings.TrimSpace(birthDateStr)
			email = strings.TrimSpace(email)
			phone = strings.TrimSpace(phone)
			address = strings.TrimSpace(address)
			notes = strings.TrimSpace(notes)
			contactPref = strings.TrimSpace(contactPref)
			tags = strings.TrimSpace(tags)

			if name == "" {
				fmt.Println("Error: Entity name cannot be empty.")
				waitForEnter()
				continue
			}

			var emailPtr, phonePtr, regIDPtr, nicknamePtr, addressPtr, notesPtr, contactPrefPtr, tagsPtr *string
			if email != "" {
				emailPtr = &email
			}
			if phone != "" {
				phonePtr = &phone
			}
			if registrationID != "" {
				regIDPtr = &registrationID
			}
			if nickname != "" {
				nicknamePtr = &nickname
			}
			if address != "" {
				addressPtr = &address
			}
			if notes != "" {
				notesPtr = &notes
			}
			if contactPref != "" {
				contactPrefPtr = &contactPref
			}
			if tags != "" {
				tagsPtr = &tags
			}

			var birthDate *time.Time
			if birthDateStr != "" {
				parsedDate, err := time.Parse("2006-01-02", birthDateStr)
				if err != nil {
					fmt.Printf("Warning: Invalid date format '%s'. Ignoring birth date.\n", birthDateStr)
				} else {
					birthDate = &parsedDate
				}
			}

			client := domain.Entity{
				Name:              name,
				RegistrationID:    regIDPtr,
				Nickname:          nicknamePtr,
				BirthDate:         birthDate,
				Status:            "ativo",
				Email:             emailPtr,
				Phone:             phonePtr,
				Address:           addressPtr,
				Notes:             notesPtr,
				ContactPreference: contactPrefPtr,
				Tags:              tagsPtr,
			}
			validationErrors := domain.ValidateEntity(&client)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				waitForEnter()
				continue
			}
			id, err := entityStore.CreateEntity(client)
			if err != nil {
				fmt.Println("Error creating client:", err)
				waitForEnter()
			} else {
				fmt.Println("Entity created with ID:", id)
				waitForEnter()
			}
			continue
		case "4":
			clearTerminal()
			fmt.Println("\n=== Select Entity ===")
			fmt.Print("Search term (or leave empty for all): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			entities, err := entityStore.GetAllEntities()
			if err != nil || len(entities) == 0 {
				fmt.Println("No entities found.")
				waitForEnter()
				continue
			}

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
			ClientSubmenu(entityID, entityStore, subEntityStore, agreementStore, subcategoryStore, categoryStore)
		case "5":
			clearTerminal()
			entities, err := entityStore.GetArchivedEntities()
			if err != nil {
				fmt.Println("Error listing archived entities:", err)
				waitForEnter()
				continue
			}
			if len(entities) == 0 {
				fmt.Println("No archived entities found.")
				waitForEnter()
				continue
			}
			displayClientsList(entities)
			fmt.Print("\nEnter the number of the client to unarchive (0 to cancel): ")
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
			err = entityStore.UnarchiveEntity(entityID)
			if err != nil {
				fmt.Println("Error unarchiving client:", err)
				waitForEnter()
			} else {
				fmt.Println("Entity unarchived successfully.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// displayClientsList shows a compact list of entities with essential information
func displayClientsList(entities []domain.Entity) {
	fmt.Println("\n=== Clients ===")
	if len(entities) == 0 {
		fmt.Println("No entities found.")
		return
	}

	fmt.Printf("\n%-4s | %-30s | %-25s | %-20s\n", "#", "Name", "Nickname", "Registration ID")
	fmt.Println(strings.Repeat("-", 85))

	for i, c := range entities {
		nickname := "-"
		if c.Nickname != nil && *c.Nickname != "" {
			nickname = *c.Nickname
			if len(nickname) > 25 {
				nickname = nickname[:22] + "..."
			}
		}

		regID := "-"
		if c.RegistrationID != nil && *c.RegistrationID != "" {
			regID = *c.RegistrationID
		}

		name := c.Name
		if len(name) > 30 {
			name = name[:27] + "..."
		}

		fmt.Printf("%-4d | %-30s | %-25s | %-20s\n", i+1, name, nickname, regID)
	}
	fmt.Println()
}

// filterClients filters entities by name, nickname, or registration ID
func filterClients(entities []domain.Entity, searchTerm string) []domain.Entity {
	var filtered []domain.Entity
	searchTerm = normalizeString(searchTerm)

	for _, c := range entities {
		if strings.Contains(normalizeString(c.Name), searchTerm) {
			filtered = append(filtered, c)
			continue
		}

		if c.Nickname != nil && strings.Contains(normalizeString(*c.Nickname), searchTerm) {
			filtered = append(filtered, c)
			continue
		}

		if c.RegistrationID != nil && strings.Contains(normalizeString(*c.RegistrationID), searchTerm) {
			filtered = append(filtered, c)
			continue
		}
	}

	return filtered
}

// DependentsSubmenu handles the sub_entities management for a specific client
func DependentsSubmenu(entityID string, subEntityStore *store.SubEntityStore) {
	for {
		clearTerminal()
		fmt.Printf("\n--- Dependents of Entity %s ---\n", entityID)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all sub_entities")
		fmt.Println("2 - Search/Filter sub_entities")
		fmt.Println("3 - Create dependent")
		fmt.Println("4 - Edit dependent")
		fmt.Println("5 - Delete dependent")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(entityID)
			if err != nil {
				fmt.Println("Error listing sub_entities:", err)
				waitForEnter()
				continue
			}
			displayDependentsList(sub_entities)
			waitForEnter()
		case "2":
			clearTerminal()
			fmt.Println("\n=== Search/Filter Dependents ===")
			fmt.Print("Enter search term (name, email, or description): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			if searchTerm == "" {
				fmt.Println("Search term cannot be empty.")
				waitForEnter()
				continue
			}

			sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(entityID)
			if err != nil {
				fmt.Println("Error listing sub_entities:", err)
				waitForEnter()
				continue
			}

			filtered := filterDependents(sub_entities, searchTerm)
			displayDependentsList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("=== Create New SubEntity ===")
			fmt.Print("SubEntity name (required): ")
			name, _ := reader.ReadString('\n')
			fmt.Print("Description (optional): ")
			description, _ := reader.ReadString('\n')
			fmt.Print("Birth/Foundation date (optional, YYYY-MM-DD): ")
			birthDateStr, _ := reader.ReadString('\n')
			fmt.Print("Email (optional): ")
			email, _ := reader.ReadString('\n')
			fmt.Print("Phone (optional, E.164 format): ")
			phone, _ := reader.ReadString('\n')
			fmt.Print("Address (optional): ")
			address, _ := reader.ReadString('\n')
			fmt.Print("Notes (optional): ")
			notes, _ := reader.ReadString('\n')
			fmt.Print("Contact preference (optional: whatsapp/email/phone/sms/outros): ")
			contactPref, _ := reader.ReadString('\n')
			fmt.Print("Tags (optional, comma-separated): ")
			tags, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			description = strings.TrimSpace(description)
			birthDateStr = strings.TrimSpace(birthDateStr)
			email = strings.TrimSpace(email)
			phone = strings.TrimSpace(phone)
			address = strings.TrimSpace(address)
			notes = strings.TrimSpace(notes)
			contactPref = strings.TrimSpace(contactPref)
			tags = strings.TrimSpace(tags)

			if name == "" {
				fmt.Println("Error: SubEntity name cannot be empty.")
				waitForEnter()
				continue
			}

			var descPtr, emailPtr, phonePtr, addressPtr, notesPtr, contactPrefPtr, tagsPtr *string
			if description != "" {
				descPtr = &description
			}
			if email != "" {
				emailPtr = &email
			}
			if phone != "" {
				phonePtr = &phone
			}
			if address != "" {
				addressPtr = &address
			}
			if notes != "" {
				notesPtr = &notes
			}
			if contactPref != "" {
				contactPrefPtr = &contactPref
			}
			if tags != "" {
				tagsPtr = &tags
			}

			var birthDate *time.Time
			if birthDateStr != "" {
				parsedDate, err := time.Parse("2006-01-02", birthDateStr)
				if err != nil {
					fmt.Printf("Warning: Invalid date format '%s'. Ignoring birth date.\n", birthDateStr)
				} else {
					birthDate = &parsedDate
				}
			}

			dependent := domain.SubEntity{
				Name:              name,
				EntityID:          entityID,
				Description:       descPtr,
				BirthDate:         birthDate,
				Email:             emailPtr,
				Phone:             phonePtr,
				Address:           addressPtr,
				Notes:             notesPtr,
				Status:            "ativo",
				ContactPreference: contactPrefPtr,
				Tags:              tagsPtr,
			}

			validationErrors := domain.ValidateSubEntity(&dependent)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				waitForEnter()
				continue
			}

			id, err := subEntityStore.CreateSubEntity(dependent)
			if err != nil {
				fmt.Println("Error creating dependent:", err)
				waitForEnter()
			} else {
				fmt.Println("SubEntity created with ID:", id)
				waitForEnter()
			}
		case "4":
			clearTerminal()
			sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(entityID)
			if err != nil || len(sub_entities) == 0 {
				fmt.Println("No sub_entities found.")
				waitForEnter()
				continue
			}
			displayDependentsList(sub_entities)
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(sub_entities) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			subEntity := &sub_entities[idx-1]
			fmt.Printf("Current name: %s | New name: ", subEntity.Name)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: SubEntity name cannot be empty.")
				waitForEnter()
				continue
			}
			subEntity.Name = name
			err = subEntityStore.UpdateSubEntity(*subEntity)
			if err != nil {
				fmt.Println("Error updating dependent:", err)
				waitForEnter()
			} else {
				fmt.Println("SubEntity updated.")
				waitForEnter()
			}
		case "5":
			clearTerminal()
			sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(entityID)
			if err != nil || len(sub_entities) == 0 {
				fmt.Println("No sub_entities found.")
				waitForEnter()
				continue
			}
			displayDependentsList(sub_entities)
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(sub_entities) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			subEntityID := sub_entities[idx-1].ID
			err = subEntityStore.DeleteSubEntity(subEntityID)
			if err != nil {
				fmt.Println("Error deleting dependent:", err)
				waitForEnter()
			} else {
				fmt.Println("SubEntity deleted.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// ClientSubmenu handles operations for a specific client
func ClientSubmenu(entityID string,
	entityStore *store.EntityStore,
	subEntityStore *store.SubEntityStore,
	agreementStore *store.AgreementStore,
	subcategoryStore *store.SubcategoryStore,
	categoryStore *store.CategoryStore) {
	if entityID == "" {
		fmt.Println("Error: Entity ID cannot be empty.")
		waitForEnter()
		return
	}
	clientName, err := entityStore.GetEntityNameByID(entityID)
	if err != nil {
		fmt.Println("Error: Entity not found.")
		waitForEnter()
		return
	}
	for {
		clearTerminal()
		fmt.Printf("\n--- Entity %s ---\n", clientName)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - Edit client")
		fmt.Println("2 - Dependents")
		fmt.Println("3 - Contracts")
		fmt.Println("4 - Archive client")
		fmt.Println("5 - Delete client permanently")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			entity, err := entityStore.GetEntityByID(entityID)
			if err != nil || entity == nil {
				fmt.Println("Entity not found.")
				waitForEnter()
				continue
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("=== Edit Entity ===")
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", entity.Name)
			name, _ := reader.ReadString('\n')
			currentRegID := "-"
			if entity.RegistrationID != nil {
				currentRegID = *entity.RegistrationID
			}
			fmt.Printf("Current registration ID: %s | New registration ID (optional): ", currentRegID)
			registrationID, _ := reader.ReadString('\n')
			currentNickname := "-"
			if entity.Nickname != nil {
				currentNickname = *entity.Nickname
			}
			fmt.Printf("Current nickname: %s | New nickname: ", currentNickname)
			nickname, _ := reader.ReadString('\n')
			currentBirthDate := "-"
			if entity.BirthDate != nil {
				currentBirthDate = entity.BirthDate.Format("2006-01-02")
			}
			fmt.Printf("Current birth date: %s | New birth date (YYYY-MM-DD): ", currentBirthDate)
			birthDateStr, _ := reader.ReadString('\n')
			currentEmail := "-"
			if entity.Email != nil {
				currentEmail = *entity.Email
			}
			fmt.Printf("Current email: %s | New email: ", currentEmail)
			email, _ := reader.ReadString('\n')
			currentPhone := "-"
			if entity.Phone != nil {
				currentPhone = *entity.Phone
			}
			fmt.Printf("Current phone: %s | New phone: ", currentPhone)
			phone, _ := reader.ReadString('\n')
			currentAddress := "-"
			if entity.Address != nil {
				currentAddress = *entity.Address
			}
			fmt.Printf("Current address: %s | New address: ", currentAddress)
			address, _ := reader.ReadString('\n')
			currentNotes := "-"
			if entity.Notes != nil {
				currentNotes = *entity.Notes
			}
			fmt.Printf("Current notes: %s | New notes: ", currentNotes)
			notes, _ := reader.ReadString('\n')
			currentContactPref := "-"
			if entity.ContactPreference != nil {
				currentContactPref = *entity.ContactPreference
			}
			fmt.Printf("Current contact preference: %s | New contact preference: ", currentContactPref)
			contactPref, _ := reader.ReadString('\n')
			currentTags := "-"
			if entity.Tags != nil {
				currentTags = *entity.Tags
			}
			fmt.Printf("Current tags: %s | New tags: ", currentTags)
			tags, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			registrationID = strings.TrimSpace(registrationID)
			nickname = strings.TrimSpace(nickname)
			birthDateStr = strings.TrimSpace(birthDateStr)
			email = strings.TrimSpace(email)
			phone = strings.TrimSpace(phone)
			address = strings.TrimSpace(address)
			notes = strings.TrimSpace(notes)
			contactPref = strings.TrimSpace(contactPref)
			tags = strings.TrimSpace(tags)

			// Handle required fields: empty keeps current value
			if name == "" {
				name = entity.Name
			}
			entity.Name = name

			// Handle optional registration ID: "-" clears it, empty keeps it, other value updates it
			regIDVal, regIDUpdate, regIDClear := HandleOptionalField(registrationID)
			if regIDUpdate {
				if regIDClear {
					entity.RegistrationID = nil
				} else {
					entity.RegistrationID = &regIDVal
				}
			}

			// Handle optional nickname
			nicknameVal, nicknameUpdate, nicknameClear := HandleOptionalField(nickname)
			if nicknameUpdate {
				if nicknameClear {
					entity.Nickname = nil
				} else {
					entity.Nickname = &nicknameVal
				}
			}

			// Handle optional birth date
			birthDateVal, birthDateUpdate, birthDateClear := HandleOptionalField(birthDateStr)
			if birthDateUpdate {
				if birthDateClear {
					entity.BirthDate = nil
				} else {
					parsedDate, err := time.Parse("2006-01-02", birthDateVal)
					if err != nil {
						fmt.Printf("Warning: Invalid date format '%s'. Keeping previous value.\n", birthDateVal)
					} else {
						entity.BirthDate = &parsedDate
					}
				}
			}

			// Handle optional email: "-" clears it, empty keeps it, other value updates it
			emailVal, emailUpdate, emailClear := HandleOptionalField(email)
			if emailUpdate {
				if emailClear {
					entity.Email = nil
				} else {
					entity.Email = &emailVal
				}
			}

			// Handle optional phone: "-" clears it, empty keeps it, other value updates it
			phoneVal, phoneUpdate, phoneClear := HandleOptionalField(phone)
			if phoneUpdate {
				if phoneClear {
					entity.Phone = nil
				} else {
					entity.Phone = &phoneVal
				}
			}

			// Handle optional address
			addressVal, addressUpdate, addressClear := HandleOptionalField(address)
			if addressUpdate {
				if addressClear {
					entity.Address = nil
				} else {
					entity.Address = &addressVal
				}
			}

			// Handle optional notes
			notesVal, notesUpdate, notesClear := HandleOptionalField(notes)
			if notesUpdate {
				if notesClear {
					entity.Notes = nil
				} else {
					entity.Notes = &notesVal
				}
			}

			// Handle optional contact preference
			contactPrefVal, contactPrefUpdate, contactPrefClear := HandleOptionalField(contactPref)
			if contactPrefUpdate {
				if contactPrefClear {
					entity.ContactPreference = nil
				} else {
					entity.ContactPreference = &contactPrefVal
				}
			}

			// Handle optional tags
			tagsVal, tagsUpdate, tagsClear := HandleOptionalField(tags)
			if tagsUpdate {
				if tagsClear {
					entity.Tags = nil
				} else {
					entity.Tags = &tagsVal
				}
			}
			validationErrors := domain.ValidateEntity(entity)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				waitForEnter()
				continue
			}
			err = entityStore.UpdateEntity(*entity)
			if err != nil {
				fmt.Println("Error updating client:", err)
				waitForEnter()
			} else {
				fmt.Println("Entity updated.")
				waitForEnter()
			}
		case "2":
			DependentsSubmenu(entityID, subEntityStore)
		case "3":
			ContractsClientSubmenu(entityID, agreementStore, subEntityStore, subcategoryStore, categoryStore)
		case "4":
			err := entityStore.ArchiveEntity(entityID)
			if err != nil {
				fmt.Println("Error archiving client:", err)
				waitForEnter()
			} else {
				fmt.Println("Entity archived.")
				waitForEnter()
				return
			}
		case "5":
			err := entityStore.DeleteEntityPermanently(entityID)
			if err != nil {
				fmt.Println("Error deleting client:", err)
				waitForEnter()
			} else {
				fmt.Println("Entity permanently deleted.")
				waitForEnter()
				return
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// ContractsClientSubmenu handles agreements for a specific client
func ContractsClientSubmenu(entityID string, agreementStore *store.AgreementStore, subEntityStore *store.SubEntityStore, subcategoryStore *store.SubcategoryStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- Contracts ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List agreements")
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
			clearTerminal()
			agreements, err := agreementStore.GetAgreementsByEntityID(entityID)
			if err != nil {
				fmt.Println("Error listing agreements:", err)
				waitForEnter()
				continue
			}
			if len(agreements) == 0 {
				fmt.Println("No agreements found for this client.")
				waitForEnter()
				continue
			}
			fmt.Println("\n=== Contracts for Entity ===")
			for i, c := range agreements {
				dependent := ""
				if c.SubEntityID != nil {
					dependent = *c.SubEntityID
				}
				status := c.Status()
				fmt.Printf("%d - ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | SubEntity: %s\n",
					i+1, c.ID, c.Model, c.ItemKey, status, c.StartDate.Format("2006-01-02"), c.EndDate.Format("2006-01-02"), dependent)
			}
			waitForEnter()
		case "2":
			ContractsSubmenu(entityID, agreementStore, subEntityStore, subcategoryStore, categoryStore)
		case "3":
			clearTerminal()
			agreements, err := agreementStore.GetAgreementsByEntityID(entityID)
			if err != nil || len(agreements) == 0 {
				fmt.Println("No agreements found for this client.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a contract to edit by number:")
			for i, c := range agreements {
				fmt.Printf("%d - %s | %s\n", i+1, c.Model, c.ItemKey)
			}
			fmt.Print("Enter the number of the contract: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(agreements) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			agreement := &agreements[idx-1]
			fmt.Printf("Current model: %s | New model: ", agreement.Model)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current key: %s | New key: ", agreement.ItemKey)
			itemKey, _ := reader.ReadString('\n')
			fmt.Printf("Current start date: %s | New date (YYYY-MM-DD): ", agreement.StartDate.Format("2006-01-02"))
			startStr, _ := reader.ReadString('\n')
			fmt.Printf("Current end date: %s | New date (YYYY-MM-DD): ", agreement.EndDate.Format("2006-01-02"))
			endStr, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			itemKey = strings.TrimSpace(itemKey)

			if name == "" {
				fmt.Println("Error: Agreement model cannot be empty.")
				waitForEnter()
				continue
			}
			if itemKey == "" {
				fmt.Println("Error: Product key cannot be empty.")
				waitForEnter()
				continue
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
			err = agreementStore.UpdateAgreement(*agreement)
			if err != nil {
				fmt.Println("Error updating contract:", err)
				waitForEnter()
			} else {
				fmt.Println("Agreement updated.")
				waitForEnter()
			}
		case "4":
			clearTerminal()
			agreements, err := agreementStore.GetAgreementsByEntityID(entityID)
			if err != nil || len(agreements) == 0 {
				fmt.Println("No agreements found for this client.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a contract to delete by number:")
			for i, c := range agreements {
				fmt.Printf("%d - %s | %s\n", i+1, c.Model, c.ItemKey)
			}
			fmt.Print("Enter the number of the contract: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(agreements) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			contractID := agreements[idx-1].ID
			err = agreementStore.DeleteAgreement(contractID)
			if err != nil {
				fmt.Println("Error deleting contract:", err)
				waitForEnter()
			} else {
				fmt.Println("Agreement deleted.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// displayDependentsList shows a compact list of sub_entities with essential information
func displayDependentsList(sub_entities []domain.SubEntity) {
	fmt.Println("\n=== Dependents ===")
	if len(sub_entities) == 0 {
		fmt.Println("No sub_entities found.")
		return
	}

	fmt.Printf("\n%-4s | %-35s | %-40s | %-15s\n", "#", "Name", "Description", "Status")
	fmt.Println(strings.Repeat("-", 100))

	for i, d := range sub_entities {
		description := "-"
		if d.Description != nil && *d.Description != "" {
			description = *d.Description
			if len(description) > 40 {
				description = description[:37] + "..."
			}
		}

		name := d.Name
		if len(name) > 35 {
			name = name[:32] + "..."
		}

		fmt.Printf("%-4d | %-35s | %-40s | %-15s\n", i+1, name, description, d.Status)
	}
	fmt.Println()
}

// filterDependents filters sub_entities by name, email, or description
func filterDependents(sub_entities []domain.SubEntity, searchTerm string) []domain.SubEntity {
	var filtered []domain.SubEntity
	searchTerm = normalizeString(searchTerm)

	for _, d := range sub_entities {
		if strings.Contains(normalizeString(d.Name), searchTerm) {
			filtered = append(filtered, d)
			continue
		}

		if d.Description != nil && strings.Contains(normalizeString(*d.Description), searchTerm) {
			filtered = append(filtered, d)
			continue
		}

		if d.Email != nil && strings.Contains(normalizeString(*d.Email), searchTerm) {
			filtered = append(filtered, d)
			continue
		}
	}

	return filtered
}
