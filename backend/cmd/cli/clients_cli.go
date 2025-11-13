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

// ClientsFlow handles the clients menu, allowing listing, creation, and selection
func ClientsFlow(clientStore *store.ClientStore, dependentStore *store.DependentStore, contractStore *store.ContractStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- Clients Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all clients")
		fmt.Println("2 - Search/Filter clients")
		fmt.Println("3 - Create client")
		fmt.Println("4 - Select client")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			clients, err := clientStore.GetAllClients()
			if err != nil {
				fmt.Println("Error listing clients:", err)
				waitForEnter()
				continue
			}
			displayClientsList(clients)
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

			clients, err := clientStore.GetAllClients()
			if err != nil {
				fmt.Println("Error listing clients:", err)
				waitForEnter()
				continue
			}

			filtered := filterClients(clients, searchTerm)
			displayClientsList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("=== Create New Client ===")
			fmt.Print("Client name (required): ")
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
				fmt.Println("Error: Client name cannot be empty.")
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

			client := domain.Client{
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
			validationErrors := domain.ValidateClient(&client)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				waitForEnter()
				continue
			}
			id, err := clientStore.CreateClient(client)
			if err != nil {
				fmt.Println("Error creating client:", err)
				waitForEnter()
			} else {
				fmt.Println("Client created with ID:", id)
				waitForEnter()
			}
			continue
		case "4":
			clearTerminal()
			fmt.Println("\n=== Select Client ===")
			fmt.Print("Search term (or leave empty for all): ")
			searchTerm, _ := reader.ReadString('\n')
			searchTerm = strings.TrimSpace(strings.ToLower(searchTerm))

			clients, err := clientStore.GetAllClients()
			if err != nil || len(clients) == 0 {
				fmt.Println("No clients found.")
				waitForEnter()
				continue
			}

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
			ClientSubmenu(clientID, clientStore, dependentStore, contractStore, lineStore, categoryStore)
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// displayClientsList shows a compact list of clients with essential information
func displayClientsList(clients []domain.Client) {
	fmt.Println("\n=== Clients ===")
	if len(clients) == 0 {
		fmt.Println("No clients found.")
		return
	}

	fmt.Printf("\n%-4s | %-30s | %-25s | %-20s\n", "#", "Name", "Nickname", "Registration ID")
	fmt.Println(strings.Repeat("-", 85))

	for i, c := range clients {
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

// filterClients filters clients by name, nickname, or registration ID
func filterClients(clients []domain.Client, searchTerm string) []domain.Client {
	var filtered []domain.Client
	searchTerm = normalizeString(searchTerm)

	for _, c := range clients {
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

// DependentsSubmenu handles the dependents management for a specific client
func DependentsSubmenu(clientID string, dependentStore *store.DependentStore) {
	for {
		clearTerminal()
		fmt.Printf("\n--- Dependents of Client %s ---\n", clientID)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List all dependents")
		fmt.Println("2 - Search/Filter dependents")
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
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing dependents:", err)
				waitForEnter()
				continue
			}
			displayDependentsList(dependents)
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

			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing dependents:", err)
				waitForEnter()
				continue
			}

			filtered := filterDependents(dependents, searchTerm)
			displayDependentsList(filtered)
			waitForEnter()
		case "3":
			clearTerminal()
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("=== Create New Dependent ===")
			fmt.Print("Dependent name (required): ")
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
				fmt.Println("Error: Dependent name cannot be empty.")
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

			dependent := domain.Dependent{
				Name:              name,
				ClientID:          clientID,
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

			validationErrors := domain.ValidateDependent(&dependent)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				waitForEnter()
				continue
			}

			id, err := dependentStore.CreateDependent(dependent)
			if err != nil {
				fmt.Println("Error creating dependent:", err)
				waitForEnter()
			} else {
				fmt.Println("Dependent created with ID:", id)
				waitForEnter()
			}
		case "4":
			clearTerminal()
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil || len(dependents) == 0 {
				fmt.Println("No dependents found.")
				waitForEnter()
				continue
			}
			displayDependentsList(dependents)
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			dependent := &dependents[idx-1]
			fmt.Printf("Current name: %s | New name: ", dependent.Name)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Dependent name cannot be empty.")
				waitForEnter()
				continue
			}
			dependent.Name = name
			err = dependentStore.UpdateDependent(*dependent)
			if err != nil {
				fmt.Println("Error updating dependent:", err)
				waitForEnter()
			} else {
				fmt.Println("Dependent updated.")
				waitForEnter()
			}
		case "5":
			clearTerminal()
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil || len(dependents) == 0 {
				fmt.Println("No dependents found.")
				waitForEnter()
				continue
			}
			displayDependentsList(dependents)
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			dependentID := dependents[idx-1].ID
			err = dependentStore.DeleteDependent(dependentID)
			if err != nil {
				fmt.Println("Error deleting dependent:", err)
				waitForEnter()
			} else {
				fmt.Println("Dependent deleted.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// ClientSubmenu handles operations for a specific client
func ClientSubmenu(clientID string,
	clientStore *store.ClientStore,
	dependentStore *store.DependentStore,
	contractStore *store.ContractStore,
	lineStore *store.LineStore,
	categoryStore *store.CategoryStore) {
	if clientID == "" {
		fmt.Println("Error: Client ID cannot be empty.")
		waitForEnter()
		return
	}
	clientName, err := clientStore.GetClientNameByID(clientID)
	if err != nil {
		fmt.Println("Error: Client not found.")
		waitForEnter()
		return
	}
	for {
		clearTerminal()
		fmt.Printf("\n--- Client %s ---\n", clientName)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - Edit client")
		fmt.Println("2 - Archive client")
		fmt.Println("3 - Delete client")
		fmt.Println("4 - Dependents")
		fmt.Println("5 - Contracts")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clearTerminal()
			client, err := clientStore.GetClientByID(clientID)
			if err != nil || client == nil {
				fmt.Println("Client not found.")
				waitForEnter()
				continue
			}
			reader := bufio.NewReader(os.Stdin)
			fmt.Println("=== Edit Client ===")
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", client.Name)
			name, _ := reader.ReadString('\n')
			currentRegID := "-"
			if client.RegistrationID != nil {
				currentRegID = *client.RegistrationID
			}
			fmt.Printf("Current registration ID: %s | New registration ID (optional): ", currentRegID)
			registrationID, _ := reader.ReadString('\n')
			currentNickname := "-"
			if client.Nickname != nil {
				currentNickname = *client.Nickname
			}
			fmt.Printf("Current nickname: %s | New nickname: ", currentNickname)
			nickname, _ := reader.ReadString('\n')
			currentBirthDate := "-"
			if client.BirthDate != nil {
				currentBirthDate = client.BirthDate.Format("2006-01-02")
			}
			fmt.Printf("Current birth date: %s | New birth date (YYYY-MM-DD): ", currentBirthDate)
			birthDateStr, _ := reader.ReadString('\n')
			currentEmail := "-"
			if client.Email != nil {
				currentEmail = *client.Email
			}
			fmt.Printf("Current email: %s | New email: ", currentEmail)
			email, _ := reader.ReadString('\n')
			currentPhone := "-"
			if client.Phone != nil {
				currentPhone = *client.Phone
			}
			fmt.Printf("Current phone: %s | New phone: ", currentPhone)
			phone, _ := reader.ReadString('\n')
			currentAddress := "-"
			if client.Address != nil {
				currentAddress = *client.Address
			}
			fmt.Printf("Current address: %s | New address: ", currentAddress)
			address, _ := reader.ReadString('\n')
			currentNotes := "-"
			if client.Notes != nil {
				currentNotes = *client.Notes
			}
			fmt.Printf("Current notes: %s | New notes: ", currentNotes)
			notes, _ := reader.ReadString('\n')
			currentContactPref := "-"
			if client.ContactPreference != nil {
				currentContactPref = *client.ContactPreference
			}
			fmt.Printf("Current contact preference: %s | New contact preference: ", currentContactPref)
			contactPref, _ := reader.ReadString('\n')
			currentTags := "-"
			if client.Tags != nil {
				currentTags = *client.Tags
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
				name = client.Name
			}
			client.Name = name

			// Handle optional registration ID: "-" clears it, empty keeps it, other value updates it
			regIDVal, regIDUpdate, regIDClear := HandleOptionalField(registrationID)
			if regIDUpdate {
				if regIDClear {
					client.RegistrationID = nil
				} else {
					client.RegistrationID = &regIDVal
				}
			}

			// Handle optional nickname
			nicknameVal, nicknameUpdate, nicknameClear := HandleOptionalField(nickname)
			if nicknameUpdate {
				if nicknameClear {
					client.Nickname = nil
				} else {
					client.Nickname = &nicknameVal
				}
			}

			// Handle optional birth date
			birthDateVal, birthDateUpdate, birthDateClear := HandleOptionalField(birthDateStr)
			if birthDateUpdate {
				if birthDateClear {
					client.BirthDate = nil
				} else {
					parsedDate, err := time.Parse("2006-01-02", birthDateVal)
					if err != nil {
						fmt.Printf("Warning: Invalid date format '%s'. Keeping previous value.\n", birthDateVal)
					} else {
						client.BirthDate = &parsedDate
					}
				}
			}

			// Handle optional email: "-" clears it, empty keeps it, other value updates it
			emailVal, emailUpdate, emailClear := HandleOptionalField(email)
			if emailUpdate {
				if emailClear {
					client.Email = nil
				} else {
					client.Email = &emailVal
				}
			}

			// Handle optional phone: "-" clears it, empty keeps it, other value updates it
			phoneVal, phoneUpdate, phoneClear := HandleOptionalField(phone)
			if phoneUpdate {
				if phoneClear {
					client.Phone = nil
				} else {
					client.Phone = &phoneVal
				}
			}

			// Handle optional address
			addressVal, addressUpdate, addressClear := HandleOptionalField(address)
			if addressUpdate {
				if addressClear {
					client.Address = nil
				} else {
					client.Address = &addressVal
				}
			}

			// Handle optional notes
			notesVal, notesUpdate, notesClear := HandleOptionalField(notes)
			if notesUpdate {
				if notesClear {
					client.Notes = nil
				} else {
					client.Notes = &notesVal
				}
			}

			// Handle optional contact preference
			contactPrefVal, contactPrefUpdate, contactPrefClear := HandleOptionalField(contactPref)
			if contactPrefUpdate {
				if contactPrefClear {
					client.ContactPreference = nil
				} else {
					client.ContactPreference = &contactPrefVal
				}
			}

			// Handle optional tags
			tagsVal, tagsUpdate, tagsClear := HandleOptionalField(tags)
			if tagsUpdate {
				if tagsClear {
					client.Tags = nil
				} else {
					client.Tags = &tagsVal
				}
			}
			validationErrors := domain.ValidateClient(client)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				waitForEnter()
				continue
			}
			err = clientStore.UpdateClient(*client)
			if err != nil {
				fmt.Println("Error updating client:", err)
				waitForEnter()
			} else {
				fmt.Println("Client updated.")
				waitForEnter()
			}
		case "2":
			err := clientStore.ArchiveClient(clientID)
			if err != nil {
				fmt.Println("Error archiving client:", err)
				waitForEnter()
			} else {
				fmt.Println("Client archived.")
				waitForEnter()
			}
		case "3":
			err := clientStore.DeleteClientPermanently(clientID)
			if err != nil {
				fmt.Println("Error deleting client:", err)
				waitForEnter()
			} else {
				fmt.Println("Client permanently deleted.")
				waitForEnter()
			}
		case "4":
			DependentsSubmenu(clientID, dependentStore)
		case "5":
			ContractsClientSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// ContractsClientSubmenu handles contracts for a specific client
func ContractsClientSubmenu(clientID string, contractStore *store.ContractStore, dependentStore *store.DependentStore, lineStore *store.LineStore, categoryStore *store.CategoryStore) {
	for {
		clearTerminal()
		fmt.Println("\n--- Contracts ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List contracts")
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
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				waitForEnter()
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				waitForEnter()
				continue
			}
			fmt.Println("\n=== Contracts for Client ===")
			for i, c := range contracts {
				dependent := ""
				if c.DependentID != nil {
					dependent = *c.DependentID
				}
				status := c.Status()
				fmt.Printf("%d - ID: %s | Model: %s | Product: %s | Status: %s | Start: %s | End: %s | Dependent: %s\n",
					i+1, c.ID, c.Model, c.ProductKey, status, c.StartDate.Format("2006-01-02"), c.EndDate.Format("2006-01-02"), dependent)
			}
			waitForEnter()
		case "2":
			ContractsSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
		case "3":
			clearTerminal()
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil || len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a contract to edit by number:")
			for i, c := range contracts {
				fmt.Printf("%d - %s | %s\n", i+1, c.Model, c.ProductKey)
			}
			fmt.Print("Enter the number of the contract: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(contracts) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			contract := &contracts[idx-1]
			fmt.Printf("Current model: %s | New model: ", contract.Model)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current key: %s | New key: ", contract.ProductKey)
			productKey, _ := reader.ReadString('\n')
			fmt.Printf("Current start date: %s | New date (YYYY-MM-DD): ", contract.StartDate.Format("2006-01-02"))
			startStr, _ := reader.ReadString('\n')
			fmt.Printf("Current end date: %s | New date (YYYY-MM-DD): ", contract.EndDate.Format("2006-01-02"))
			endStr, _ := reader.ReadString('\n')

			name = strings.TrimSpace(name)
			productKey = strings.TrimSpace(productKey)

			if name == "" {
				fmt.Println("Error: Contract model cannot be empty.")
				waitForEnter()
				continue
			}
			if productKey == "" {
				fmt.Println("Error: Product key cannot be empty.")
				waitForEnter()
				continue
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
			err = contractStore.UpdateContract(*contract)
			if err != nil {
				fmt.Println("Error updating contract:", err)
				waitForEnter()
			} else {
				fmt.Println("Contract updated.")
				waitForEnter()
			}
		case "4":
			clearTerminal()
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil || len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
				waitForEnter()
				continue
			}
			fmt.Println("Select a contract to delete by number:")
			for i, c := range contracts {
				fmt.Printf("%d - %s | %s\n", i+1, c.Model, c.ProductKey)
			}
			fmt.Print("Enter the number of the contract: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(contracts) {
				fmt.Println("Invalid selection.")
				waitForEnter()
				continue
			}
			contractID := contracts[idx-1].ID
			err = contractStore.DeleteContract(contractID)
			if err != nil {
				fmt.Println("Error deleting contract:", err)
				waitForEnter()
			} else {
				fmt.Println("Contract deleted.")
				waitForEnter()
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// displayDependentsList shows a compact list of dependents with essential information
func displayDependentsList(dependents []domain.Dependent) {
	fmt.Println("\n=== Dependents ===")
	if len(dependents) == 0 {
		fmt.Println("No dependents found.")
		return
	}

	fmt.Printf("\n%-4s | %-35s | %-40s | %-15s\n", "#", "Name", "Description", "Status")
	fmt.Println(strings.Repeat("-", 100))

	for i, d := range dependents {
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

// filterDependents filters dependents by name, email, or description
func filterDependents(dependents []domain.Dependent, searchTerm string) []domain.Dependent {
	var filtered []domain.Dependent
	searchTerm = normalizeString(searchTerm)

	for _, d := range dependents {
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
