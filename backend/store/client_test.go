package store

import (
	"Contracts-Manager/backend/domain"
	"database/sql"
	"strings"
	"testing"
	"time"
)

// ============================================================================
// SETUP HELPERS
// ============================================================================

func setupClientTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

func setupClientTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

// ============================================================================
// BASIC CRUD TESTS
// ============================================================================

func TestCreateClient(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	tests := []struct {
		name        string
		client      domain.Client
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			client: domain.Client{
				Name:           "Test Client",
				RegistrationID: "45.723.174/0001-10",
				Email:          stringPtr("test@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: false,
		},
		{
			name: "erro - CNPJ duplicado",
			client: domain.Client{
				Name:           "Another Client",
				RegistrationID: "45.723.174/0001-10",
				Email:          stringPtr("another@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: true,
		},
		{
			name: "erro - CNPJ vazio",
			client: domain.Client{
				Name:           "Test Client",
				RegistrationID: "",
				Email:          stringPtr("test@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			client: domain.Client{
				Name:           "",
				RegistrationID: "45.723.174/0001-10",
				Email:          stringPtr("test@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientStore := NewClientStore(db)

			id, err := clientStore.CreateClient(tt.client)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && id == "" {
				t.Error("Expected ID but got empty string")
			}
		})
	}
}

func TestCreateClientWithFormatStandardization(t *testing.T) {
	tests := []struct {
		name               string
		inputRegistration  string
		expectedFormatting string
		expectError        bool
	}{
		{
			name:               "CNPJ sem formatação é padronizado",
			inputRegistration:  "45723174000110",
			expectedFormatting: "45.723.174/0001-10",
			expectError:        false,
		},
		{
			name:               "CNPJ já formatado mantém formatação correta",
			inputRegistration:  "11.222.333/0001-81",
			expectedFormatting: "11.222.333/0001-81",
			expectError:        false,
		},
		{
			name:               "CPF sem formatação é padronizado",
			inputRegistration:  "11144477735",
			expectedFormatting: "111.444.777-35",
			expectError:        false,
		},
		{
			name:               "CPF já formatado mantém formatação correta",
			inputRegistration:  "111.444.777-35",
			expectedFormatting: "111.444.777-35",
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupClientTest(t)
			defer CloseDB(db)

			clientStore := NewClientStore(db)

			client := domain.Client{
				Name:           "Test Client " + tt.name,
				RegistrationID: tt.inputRegistration,
			}

			id, err := clientStore.CreateClient(client)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				retrievedClient, err := clientStore.GetClientByID(id)
				if err != nil {
					t.Errorf("Failed to retrieve client: %v", err)
				}
				if retrievedClient == nil {
					t.Error("Expected client but got nil")
				}
				if retrievedClient.RegistrationID != tt.expectedFormatting {
					t.Errorf("Expected registration ID to be '%s', but got '%s'",
						tt.expectedFormatting, retrievedClient.RegistrationID)
				}
			}
		})
	}
}

func TestGetClientByID(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - empresa encontrada",
			id:          clientID,
			expectError: false,
			expectFound: true,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
			expectFound: false,
		},
		{
			name:        "não encontrado - id inexistente",
			id:          "non-existent-id",
			expectError: false,
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientStore := NewClientStore(db)
			client, err := clientStore.GetClientByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && client == nil {
				t.Error("Expected client but got nil")
			}
			if !tt.expectFound && client != nil {
				t.Error("Expected no client but got one")
			}
		})
	}
}

func TestArchiveClient(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - arquivamento normal",
			id:          clientID,
			expectError: false,
		},
		{
			name:        "erro - empresa não encontrada",
			id:          "non-existent-id",
			expectError: true,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientStore := NewClientStore(db)
			err := clientStore.ArchiveClient(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var archivedAt *time.Time
				err = db.QueryRow("SELECT archived_at FROM clients WHERE id = $1", tt.id).Scan(&archivedAt)
				if err != nil {
					t.Errorf("Failed to query archived client: %v", err)
				}
				if archivedAt == nil {
					t.Error("Expected archived_at to be set, but it was nil")
				}
			}
		})
	}
}

func TestUnarchiveClient(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	_, err = db.Exec("UPDATE clients SET archived_at = $1 WHERE id = $2", time.Now(), clientID)
	if err != nil {
		t.Fatalf("Failed to archive test client: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - desarquivamento normal",
			id:          clientID,
			expectError: false,
		},
		{
			name:        "erro - empresa não encontrada",
			id:          "non-existent-id",
			expectError: true,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientStore := NewClientStore(db)
			err := clientStore.UnarchiveClient(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var archivedAt *time.Time
				err = db.QueryRow("SELECT archived_at FROM clients WHERE id = $1", tt.id).Scan(&archivedAt)
				if err != nil {
					t.Errorf("Failed to query unarchived client: %v", err)
				}
				if archivedAt != nil {
					t.Error("Expected archived_at to be nil after unarchiving")
				}
			}
		})
	}
}

func TestDeleteClientPermanently(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          clientID,
			expectError: false,
		},
		{
			name:        "erro - empresa não encontrada",
			id:          "non-existent-id",
			expectError: true,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientStore := NewClientStore(db)
			err := clientStore.DeleteClientPermanently(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted client: %v", err)
				}
				if count != 0 {
					t.Error("Expected client to be deleted, but it still exists")
				}
			}
		})
	}
}

// ============================================================================
// COMPLEX SCENARIOS
// ============================================================================

func TestArchiveAndDeleteClientWithPermanentContract(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	categoryID, err := InsertTestCategory(db, "Categoria Permanente")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Linha Permanente", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	clientID, err := InsertTestClient(db, "Empresa Permanente", "99.999.999/0001-99")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	startDate := time.Now()
	endDate := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	contractID, err := InsertTestContract(db, "Licença Permanente", "KEY-PERM", startDate, endDate, lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert permanent contract: %v", err)
	}

	clientStore := NewClientStore(db)

	err = clientStore.DeleteClientPermanently(clientID)
	if err == nil {
		t.Error("Expected error when deleting client with permanent contract, got none")
	}

	err = clientStore.ArchiveClient(clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Fatalf("Failed to delete client with archived permanent contract: %v", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM contracts WHERE id = $1", contractID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query contract after client deletion: %v", err)
	}
	if count != 0 {
		t.Error("Expected contract to be deleted after client deletion")
	}
}

func TestDeleteClientWithActiveContracts(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Empresa Ativa", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Categoria Teste")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	lineID, err := InsertTestLine(db, "Linha Teste", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	contractStore := NewContractStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contract := domain.Contract{
		Model:      "Licença Ativa",
		ProductKey: "ACTIVE-KEY-001",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
	}
	_, err = contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create active contract: %v", err)
	}

	clientStore := NewClientStore(db)
	err = clientStore.DeleteClientPermanently(clientID)
	if err == nil {
		t.Error("Expected error when deleting client with active contracts, got none")
	}
}

// ============================================================================
// CRITICAL TESTS: GetClientNameByID, UpdateClient, GetAllClients, GetArchivedClients
// ============================================================================

func TestGetClientNameByID(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	clientStore := NewClientStore(db)

	tests := []struct {
		name         string
		id           string
		expectError  bool
		expectedName string
	}{
		{
			name:         "success - get client name",
			id:           clientID,
			expectError:  false,
			expectedName: "Test Client",
		},
		{
			name:        "error - non-existent client",
			id:          "non-existent-id",
			expectError: true,
		},
		{
			name:        "error - empty client id",
			id:          "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := clientStore.GetClientNameByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && name != tt.expectedName {
				t.Errorf("Expected name '%s', got '%s'", tt.expectedName, name)
			}
		})
	}
}

func TestUpdateClientCritical(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientID, err := InsertTestClient(db, "Original Name", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	clientStore := NewClientStore(db)

	tests := []struct {
		name        string
		client      domain.Client
		expectError bool
		errorMsg    string
	}{
		{
			name: "success - update client",
			client: domain.Client{
				ID:             clientID,
				Name:           "Updated Name",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: false,
		},
		{
			name: "error - empty id",
			client: domain.Client{
				ID:             "",
				Name:           "Test",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
			errorMsg:    "ID",
		},
		{
			name: "error - empty name",
			client: domain.Client{
				ID:             clientID,
				Name:           "",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
			errorMsg:    "name",
		},
		{
			name: "error - name too long",
			client: domain.Client{
				ID:             clientID,
				Name:           string(make([]byte, 256)),
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
			errorMsg:    "255",
		},
		{
			name: "error - empty registration ID",
			client: domain.Client{
				ID:             clientID,
				Name:           "Test",
				RegistrationID: "",
			},
			expectError: true,
			errorMsg:    "registration",
		},
		{
			name: "error - invalid registration ID",
			client: domain.Client{
				ID:             clientID,
				Name:           "Test",
				RegistrationID: "invalid",
			},
			expectError: true,
			errorMsg:    "valid",
		},
		{
			name: "error - non-existent client",
			client: domain.Client{
				ID:             "non-existent-id",
				Name:           "Test",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
			errorMsg:    "not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := clientStore.UpdateClient(tt.client)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestGetAllClientsCritical(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	client1ID, err := InsertTestClient(db, "Client 1", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Client 2", "11.222.333/0001-81")
	if err != nil {
		t.Fatalf("Failed to insert client 2: %v", err)
	}

	now := time.Now()
	_, err = db.Exec("UPDATE clients SET archived_at = $1 WHERE id = $2", now, client2ID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	clients, err := clientStore.GetAllClients()
	if err != nil {
		t.Fatalf("Failed to get all clients: %v", err)
	}

	if len(clients) != 1 {
		t.Errorf("Expected 1 non-archived client, got %d", len(clients))
	}

	if len(clients) > 0 && clients[0].ID != client1ID {
		t.Errorf("Expected client ID '%s', got '%s'", client1ID, clients[0].ID)
	}

	if len(clients) > 0 && clients[0].ArchivedAt != nil {
		t.Error("Expected archived_at to be nil for non-archived client")
	}
}

func TestGetArchivedClientsCritical(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	client1ID, err := InsertTestClient(db, "Client 1", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Client 2", "11.222.333/0001-81")
	if err != nil {
		t.Fatalf("Failed to insert client 2: %v", err)
	}

	now := time.Now()
	_, err = db.Exec("UPDATE clients SET archived_at = $1 WHERE id IN ($2, $3)", now, client1ID, client2ID)
	if err != nil {
		t.Fatalf("Failed to archive clients: %v", err)
	}

	clients, err := clientStore.GetArchivedClients()
	if err != nil {
		t.Fatalf("Failed to get archived clients: %v", err)
	}

	if len(clients) != 2 {
		t.Errorf("Expected 2 archived clients, got %d", len(clients))
	}

	for _, client := range clients {
		if client.ArchivedAt == nil {
			t.Error("Expected archived_at to be set for archived client")
		}
	}
}

func TestDeleteClientPermanentlyWithActiveContracts(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()
	_, err = InsertTestContract(db, "Test Contract", "TEST-KEY-123", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test contract: %v", err)
	}

	err = clientStore.DeleteClientPermanently(clientID)
	if err == nil {
		t.Error("Expected error deleting client with active contracts")
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", clientID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query client: %v", err)
	}
	if count != 1 {
		t.Error("Expected client to still exist after failed deletion")
	}
}

func TestDeleteClientPermanentlyWithExpiredContracts(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()
	_, err = InsertTestContract(db, "Test Contract", "TEST-KEY-456", now.AddDate(0, 0, -30), now.AddDate(0, 0, -5), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test contract: %v", err)
	}

	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Errorf("Expected no error deleting client with expired contracts, got: %v", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = $1", clientID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query client: %v", err)
	}
	if count != 0 {
		t.Error("Expected client to be deleted")
	}
}

// ============================================================================
// EDGE CASES: VALIDATION
// ============================================================================

func TestCreateClientWithInvalidCPFCNPJ(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	tests := []struct {
		name           string
		registrationID string
		expectError    bool
		description    string
	}{
		{
			name:           "invalid - CPF with letters",
			registrationID: "111.ABC.777-35",
			expectError:    true,
			description:    "CPF cannot contain letters",
		},
		{
			name:           "invalid - CNPJ with letters",
			registrationID: "45.ABC.174/0001-10",
			expectError:    true,
			description:    "CNPJ cannot contain letters",
		},
		{
			name:           "invalid - CPF with special chars",
			registrationID: "111@444#777-35",
			expectError:    true,
			description:    "CPF cannot contain special characters beyond dots and dashes",
		},
		{
			name:           "invalid - CNPJ with special chars",
			registrationID: "45.723.174/0001@10",
			expectError:    true,
			description:    "CNPJ cannot contain special characters beyond dots, dashes and slash",
		},
		{
			name:           "invalid - random string",
			registrationID: "invalid-registration",
			expectError:    true,
			description:    "Random string is not a valid CPF or CNPJ",
		},
		{
			name:           "invalid - only numbers but wrong length",
			registrationID: "123456",
			expectError:    true,
			description:    "Too short to be CPF or CNPJ",
		},
		{
			name:           "invalid - CPF with spaces",
			registrationID: "111 444 777 35",
			expectError:    true,
			description:    "CPF with spaces instead of proper formatting",
		},
		{
			name:           "invalid - CNPJ with spaces",
			registrationID: "45 723 174 0001 10",
			expectError:    true,
			description:    "CNPJ with spaces instead of proper formatting",
		},
		{
			name:           "invalid - SQL injection attempt",
			registrationID: "'; DROP TABLE clients; --",
			expectError:    true,
			description:    "SQL injection should be rejected",
		},
		{
			name:           "invalid - HTML/XSS attempt",
			registrationID: "<script>alert('xss')</script>",
			expectError:    true,
			description:    "XSS attempt should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := domain.Client{
				Name:           "Test Client - " + tt.name,
				RegistrationID: tt.registrationID,
			}

			_, err := clientStore.CreateClient(client)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestCreateClientWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	validCNPJs := []string{
		"45.723.174/0001-10",
		"11.222.333/0001-81",
	}

	veryLongName := strings.Repeat("a", 1000)

	tests := []struct {
		name        string
		clientName  string
		cnpjIndex   int
		expectError bool
		description string
	}{
		{
			name:        "invalid - name too long (256 chars)",
			clientName:  strings.Repeat("a", 256),
			cnpjIndex:   0,
			expectError: true,
			description: "Name with 256 characters should be rejected",
		},
		{
			name:        "invalid - name way too long (1000 chars)",
			clientName:  veryLongName,
			cnpjIndex:   0,
			expectError: true,
			description: "Name with 1000 characters should be rejected",
		},
		{
			name:        "invalid - name with only spaces",
			clientName:  "     ",
			cnpjIndex:   0,
			expectError: true,
			description: "Name with only whitespace should be rejected",
		},
		{
			name:        "valid - name with SQL-like content (but valid)",
			clientName:  "Company DROP TABLE; Inc",
			cnpjIndex:   0,
			expectError: false,
			description: "Name containing SQL keywords should be allowed if properly escaped",
		},
		{
			name:        "valid - name with special characters",
			clientName:  "Company & Associates - S/A",
			cnpjIndex:   1,
			expectError: false,
			description: "Name with common business special characters should be allowed",
		},
		{
			name:        "valid - name with accents",
			clientName:  "Solução Tecnológica Ltda",
			cnpjIndex:   0,
			expectError: false,
			description: "Name with Portuguese accents should be allowed",
		},
		{
			name:        "invalid - name with HTML tags",
			clientName:  "<script>alert('xss')</script>",
			cnpjIndex:   1,
			expectError: false,
			description: "Name with HTML tags - depends on validation strategy",
		},
		{
			name:        "valid - name at max length (255 chars)",
			clientName:  strings.Repeat("a", 255),
			cnpjIndex:   0,
			expectError: false,
			description: "Name with exactly 255 characters should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			cnpj := validCNPJs[tt.cnpjIndex]

			client := domain.Client{
				Name:           tt.clientName,
				RegistrationID: cnpj,
			}

			_, err := clientStore.CreateClient(client)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestUpdateClientWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	clientID, err := InsertTestClient(db, "Original Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	tests := []struct {
		name        string
		updateData  domain.Client
		expectError bool
		description string
	}{
		{
			name: "invalid - update with invalid CPF",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "Updated Name",
				RegistrationID: "111.ABC.777-35",
			},
			expectError: true,
			description: "Update with invalid CPF should fail",
		},
		{
			name: "invalid - update with invalid CNPJ",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "Updated Name",
				RegistrationID: "invalid-cnpj",
			},
			expectError: true,
			description: "Update with invalid CNPJ should fail",
		},
		{
			name: "invalid - update with name too long",
			updateData: domain.Client{
				ID:             clientID,
				Name:           strings.Repeat("a", 256),
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace name",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "    ",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "valid - update with valid data",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "Valid Updated Name",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: false,
			description: "Update with valid data should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := clientStore.UpdateClient(tt.updateData)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestCreateClientWithDuplicateCPFCNPJVariations(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	_, err = clientStore.CreateClient(domain.Client{
		Name:           "First Client",
		RegistrationID: "45.723.174/0001-10",
	})
	if err != nil {
		t.Fatalf("Failed to create first client: %v", err)
	}

	tests := []struct {
		name           string
		registrationID string
		expectError    bool
		description    string
	}{
		{
			name:           "duplicate - same CNPJ without formatting",
			registrationID: "45723174000110",
			expectError:    true,
			description:    "CNPJ without formatting should be detected as duplicate",
		},
		{
			name:           "duplicate - same CNPJ with different formatting",
			registrationID: "45.723.174/0001-10",
			expectError:    true,
			description:    "Same CNPJ with same formatting should be duplicate",
		},
		{
			name:           "valid - different CNPJ",
			registrationID: "11.222.333/0001-81",
			expectError:    false,
			description:    "Different CNPJ should be allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := domain.Client{
				Name:           "Test Client - " + tt.name,
				RegistrationID: tt.registrationID,
			}

			_, err := clientStore.CreateClient(client)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

func TestClientNameTrimming(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	tests := []struct {
		name         string
		inputName    string
		expectedName string
		expectError  bool
	}{
		{
			name:         "name with leading spaces",
			inputName:    "   Leading Spaces",
			expectedName: "Leading Spaces",
			expectError:  false,
		},
		{
			name:         "name with trailing spaces",
			inputName:    "Trailing Spaces   ",
			expectedName: "Trailing Spaces",
			expectError:  false,
		},
		{
			name:         "name with both leading and trailing spaces",
			inputName:    "   Both Spaces   ",
			expectedName: "Both Spaces",
			expectError:  false,
		},
		{
			name:        "only spaces",
			inputName:   "     ",
			expectError: true,
		},
		{
			name:        "only tabs",
			inputName:   "\t\t\t",
			expectError: true,
		},
		{
			name:        "only newlines",
			inputName:   "\n\n\n",
			expectError: true,
		},
	}

	validCNPJs := []string{
		"11.222.333/0001-81",
		"45.723.174/0001-10",
		"11.222.333/0001-81",
		"45.723.174/0001-10",
		"11.222.333/0001-81",
		"45.723.174/0001-10",
	}

	counter := 0
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			cnpj := validCNPJs[counter%len(validCNPJs)]
			counter++

			client := domain.Client{
				Name:           tt.inputName,
				RegistrationID: cnpj,
			}

			id, err := clientStore.CreateClient(client)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError && err == nil {
				retrievedClient, err := clientStore.GetClientByID(id)
				if err != nil {
					t.Errorf("Failed to retrieve client: %v", err)
				}
				if retrievedClient != nil && retrievedClient.Name != tt.expectedName {
					t.Errorf("Expected name '%s', got '%s'", tt.expectedName, retrievedClient.Name)
				}
			}
		})
	}
}
