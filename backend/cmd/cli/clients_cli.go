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
		fmt.Println("\n--- Clients Menu ---")
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List clients")
		fmt.Println("2 - Create client")
		fmt.Println("3 - Select client")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			clients, err := clientStore.GetAllClients()
			if err != nil {
				fmt.Println("Error listing clients:", err)
				continue
			}
			fmt.Println("Active clients:")
			for _, c := range clients {
				email := "-"
				if c.Email != nil {
					email = *c.Email
				}
				phone := "-"
				if c.Phone != nil {
					phone = *c.Phone
				}
				fmt.Printf("ID: %s | Name: %s | Registration ID: %s | Email: %s | Phone: %s\n", c.ID, c.Name, c.RegistrationID, email, phone)
			}
		case "2":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Client name: ")
			name, _ := reader.ReadString('\n')
			fmt.Print("Registration ID: ")
			registrationID, _ := reader.ReadString('\n')
			fmt.Print("Email (optional): ")
			email, _ := reader.ReadString('\n')
			fmt.Print("Phone (optional): ")
			phone, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			registrationID = strings.TrimSpace(registrationID)
			email = strings.TrimSpace(email)
			phone = strings.TrimSpace(phone)
			if name == "" {
				fmt.Println("Error: Client name cannot be empty.")
				continue
			}
			if registrationID == "" {
				fmt.Println("Error: Registration ID cannot be empty.")
				continue
			}
			var emailPtr, phonePtr *string
			if email != "" {
				emailPtr = &email
			}
			if phone != "" {
				phonePtr = &phone
			}
			client := domain.Client{
				Name:           name,
				RegistrationID: registrationID,
				Email:          emailPtr,
				Phone:          phonePtr,
			}
			validationErrors := domain.ValidateClient(&client)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				continue
			}
			id, err := clientStore.CreateClient(client)
			if err != nil {
				fmt.Println("Error creating client:", err)
			} else {
				fmt.Println("Client created with ID:", id)
			}
			continue
		case "3":
			clients, err := clientStore.GetAllClients()
			if err != nil || len(clients) == 0 {
				fmt.Println("No clients found.")
				continue
			}
			fmt.Println("Select a client by number:")
			for i, c := range clients {
				fmt.Printf("%d - %s | %s\n", i+1, c.Name, c.RegistrationID)
			}
			fmt.Print("Enter the number of the client: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(clients) {
				fmt.Println("Invalid selection.")
				continue
			}
			clientID := clients[idx-1].ID
			ClientSubmenu(clientID, clientStore, dependentStore, contractStore, lineStore, categoryStore)
		default:
			fmt.Println("Invalid option.")
		}
	}
}

// DependentsSubmenu handles the dependents management for a specific client
func DependentsSubmenu(clientID string, dependentStore *store.DependentStore) {
	for {
		fmt.Printf("\n--- Dependents of Client %s ---\n", clientID)
		fmt.Println("0 - Back/Cancel")
		fmt.Println("1 - List dependents")
		fmt.Println("2 - Create dependent")
		fmt.Println("3 - Edit dependent")
		fmt.Println("4 - Delete dependent")
		fmt.Print("Option: ")
		reader := bufio.NewReader(os.Stdin)
		opt, _ := reader.ReadString('\n')
		opt = strings.TrimSpace(opt)

		switch opt {
		case "0":
			return
		case "1":
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing dependents:", err)
				continue
			}
			for _, e := range dependents {
				fmt.Printf("ID: %s | Name: %s\n", e.ID, e.Name)
			}
		case "2":
			reader := bufio.NewReader(os.Stdin)
			fmt.Print("Dependent name: ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Dependent name cannot be empty.")
				continue
			}
			dependent := domain.Dependent{
				Name:     name,
				ClientID: clientID,
			}
			id, err := dependentStore.CreateDependent(dependent)
			if err != nil {
				fmt.Println("Error creating dependent:", err)
			} else {
				fmt.Println("Dependent created with ID:", id)
			}
		case "3":
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil || len(dependents) == 0 {
				fmt.Println("No dependents found.")
				continue
			}
			fmt.Println("Select a dependent to edit by number:")
			for i, d := range dependents {
				fmt.Printf("%d - %s\n", i+1, d.Name)
			}
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Invalid selection.")
				continue
			}
			dependent := &dependents[idx-1]
			fmt.Printf("Current name: %s | New name: ", dependent.Name)
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)
			if name == "" {
				fmt.Println("Error: Dependent name cannot be empty.")
				continue
			}
			dependent.Name = name
			err = dependentStore.UpdateDependent(*dependent)
			if err != nil {
				fmt.Println("Error updating dependent:", err)
			} else {
				fmt.Println("Dependent updated.")
			}
		case "4":
			dependents, err := dependentStore.GetDependentsByClientID(clientID)
			if err != nil || len(dependents) == 0 {
				fmt.Println("No dependents found.")
				continue
			}
			fmt.Println("Select a dependent to delete by number:")
			for i, d := range dependents {
				fmt.Printf("%d - %s\n", i+1, d.Name)
			}
			fmt.Print("Enter the number of the dependent: ")
			idxStr, _ := reader.ReadString('\n')
			idxStr = strings.TrimSpace(idxStr)
			if idxStr == "0" {
				continue
			}
			idx, err := strconv.Atoi(idxStr)
			if err != nil || idx < 1 || idx > len(dependents) {
				fmt.Println("Invalid selection.")
				continue
			}
			dependentID := dependents[idx-1].ID
			err = dependentStore.DeleteDependent(dependentID)
			if err != nil {
				fmt.Println("Error deleting dependent:", err)
			} else {
				fmt.Println("Dependent deleted.")
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
		return
	}
	clientName, err := clientStore.GetClientNameByID(clientID)
	if err != nil {
		fmt.Println("Error: Client not found.")
		return
	}
	for {
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
			client, err := clientStore.GetClientByID(clientID)
			if err != nil || client == nil {
				fmt.Println("Client not found.")
				continue
			}
			reader := bufio.NewReader(os.Stdin)
			PrintOptionalFieldHint()
			fmt.Printf("Current name: %s | New name: ", client.Name)
			name, _ := reader.ReadString('\n')
			fmt.Printf("Current Registration ID: %s | New Registration ID: ", client.RegistrationID)
			registrationID, _ := reader.ReadString('\n')
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
			name = strings.TrimSpace(name)
			registrationID = strings.TrimSpace(registrationID)
			email = strings.TrimSpace(email)
			phone = strings.TrimSpace(phone)

			// Handle required fields: empty keeps current value
			if name == "" {
				name = client.Name
			}
			if registrationID == "" {
				registrationID = client.RegistrationID
			}
			client.Name = name
			client.RegistrationID = registrationID
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
			validationErrors := domain.ValidateClient(client)
			if !validationErrors.IsValid() {
				fmt.Println("Validation errors:")
				for _, err := range validationErrors {
					fmt.Printf("  - %s: %s\n", err.Field, err.Message)
				}
				continue
			}
			err = clientStore.UpdateClient(*client)
			if err != nil {
				fmt.Println("Error updating client:", err)
			} else {
				fmt.Println("Client updated.")
			}
		case "2":
			err := clientStore.ArchiveClient(clientID)
			if err != nil {
				fmt.Println("Error archiving client:", err)
			} else {
				fmt.Println("Client archived.")
			}
		case "3":
			err := clientStore.DeleteClientPermanently(clientID)
			if err != nil {
				fmt.Println("Error deleting client:", err)
			} else {
				fmt.Println("Client permanently deleted.")
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
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil {
				fmt.Println("Error listing contracts:", err)
				continue
			}
			if len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
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
		case "2":
			ContractsSubmenu(clientID, contractStore, dependentStore, lineStore, categoryStore)
		case "3":
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil || len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
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
				continue
			}
			if productKey == "" {
				fmt.Println("Error: Product key cannot be empty.")
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

			contract.Model = name
			contract.ProductKey = productKey
			contract.StartDate = startDate
			contract.EndDate = endDate
			err = contractStore.UpdateContract(*contract)
			if err != nil {
				fmt.Println("Error updating contract:", err)
			} else {
				fmt.Println("Contract updated.")
			}
		case "4":
			contracts, err := contractStore.GetContractsByClientID(clientID)
			if err != nil || len(contracts) == 0 {
				fmt.Println("No contracts found for this client.")
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
				continue
			}
			contractID := contracts[idx-1].ID
			err = contractStore.DeleteContract(contractID)
			if err != nil {
				fmt.Println("Error deleting contract:", err)
			} else {
				fmt.Println("Contract deleted.")
			}
		default:
			fmt.Println("Invalid option.")
		}
	}
}
