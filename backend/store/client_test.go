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

package store

import (
	"Open-Generic-Hub/backend/domain"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func stringPtr(s string) *string {
	return &s
}

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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

// ============================================================================
// BASIC CRUD TESTS
// ============================================================================

func TestCreateClient(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	tests := []struct {
		name        string
		client      domain.Client
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			client: domain.Client{
				Name:           "Test Client",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
				Email:          stringPtr("test@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: false,
		},
		{
			name: "erro - CNPJ duplicado",
			client: domain.Client{
				Name:           "Another Client",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
				Email:          stringPtr("another@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: true,
		},
		{
			name: "sucesso - CNPJ vazio (opcional)",
			client: domain.Client{
				Name:           "Test Client Without CNPJ",
				RegistrationID: nil,
				Status:         "ativo",
				Email:          stringPtr("test@example.com"),
				Phone:          stringPtr("+5511987654321"),
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			client: domain.Client{
				Name:           "",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
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
				t.Error("Expected non-empty ID but got empty string")
			}
		})
	}
}

func TestClientNameUniquenessWithRegistrationID(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	// Test 1: Create client with name "Test Company" and registration_id
	regID1 := "45.723.174/0001-10"
	client1 := domain.Client{
		Name:           "Test Company",
		RegistrationID: &regID1,
		Status:         "ativo",
	}
	id1, err := clientStore.CreateClient(client1)
	if err != nil {
		t.Fatalf("Failed to create first client with registration_id: %v", err)
	}
	if id1 == "" {
		t.Error("Expected non-empty ID for first client")
	}

	// Test 2: Create another client with SAME name but DIFFERENT registration_id - should succeed
	regID2 := "11.222.333/0001-81"
	client2 := domain.Client{
		Name:           "Test Company",
		RegistrationID: &regID2,
		Status:         "ativo",
	}
	id2, err := clientStore.CreateClient(client2)
	if err != nil {
		t.Errorf("Should allow duplicate name when both have different registration_id, but got error: %v", err)
	}
	if id2 == "" {
		t.Error("Expected non-empty ID for second client")
	}

	// Test 3: Create client with name "Another Company" WITHOUT registration_id
	client3 := domain.Client{
		Name:           "Another Company",
		RegistrationID: nil,
		Status:         "ativo",
	}
	id3, err := clientStore.CreateClient(client3)
	if err != nil {
		t.Fatalf("Failed to create client without registration_id: %v", err)
	}
	if id3 == "" {
		t.Error("Expected non-empty ID for third client")
	}

	// Test 4: Try to create another client with SAME name WITHOUT registration_id - should fail
	client4 := domain.Client{
		Name:           "Another Company",
		RegistrationID: nil,
		Status:         "ativo",
	}
	_, err = clientStore.CreateClient(client4)
	if err == nil {
		t.Error("Should NOT allow duplicate name when both have NULL registration_id")
	}
	if err != nil && !strings.Contains(err.Error(), "name already exists") {
		t.Errorf("Expected 'name already exists' error, got: %v", err)
	}

	// Test 5: Create client with name "Another Company" WITH registration_id - should succeed
	// (same name as client3, but this one has registration_id)
	regID5 := "33.444.555/0001-81"
	client5 := domain.Client{
		Name:           "Another Company",
		RegistrationID: &regID5,
		Status:         "ativo",
	}
	id5, err := clientStore.CreateClient(client5)
	if err != nil {
		t.Errorf("Should allow same name when one has NULL registration_id and other has registration_id, but got error: %v", err)
	}
	if id5 == "" {
		t.Error("Expected non-empty ID for fifth client")
	}
}

func TestCreateClientWithFormatStandardization(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

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
			// Clear tables before each subtest to avoid data conflicts
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			clientStore := NewClientStore(db)

			client := domain.Client{
				Name:           "Test Client " + tt.name,
				RegistrationID: &tt.inputRegistration,
				Status:         "ativo",
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
				if retrievedClient.RegistrationID == nil || *retrievedClient.RegistrationID != tt.expectedFormatting {
					var actual string
					if retrievedClient.RegistrationID != nil {
						actual = *retrievedClient.RegistrationID
					}
					t.Errorf("Expected registration ID to be '%s', but got '%s'",
						tt.expectedFormatting, actual)
				}
			}
		})
	}
}

func TestGetClientByID(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	// Clean up before test
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

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
			id:          uuid.New().String(),
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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientID, err := InsertTestClient(db, "Test Client", "11.111.111/0001-11")
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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientID, err := InsertTestClient(db, "Test Client", "22.222.222/0002-22")
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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientID, err := InsertTestClient(db, "Test Client", "33.333.333/0003-33")
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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

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

	startDate := timePtr(time.Now())
	endDate := timePtr(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))
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
	startDate := timePtr(time.Now())
	endDate := timePtr(time.Now().AddDate(1, 0, 0))
	contract := domain.Contract{
		Model:      "Test Contract",
		ProductKey: "TEST-KEY-001",
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
	db := setupClientTest(t)
	defer CloseDB(db)
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

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
	db := setupClientTest(t)
	defer CloseDB(db)
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientID, err := InsertTestClient(db, "Original Client", "55.555.555/0005-55")
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
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
			},
			expectError: false,
		},
		{
			name: "error - empty id",
			client: domain.Client{
				ID:             "",
				Name:           "Test",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
			},
			expectError: true,
			errorMsg:    "ID",
		},
		{
			name: "error - empty name",
			client: domain.Client{
				ID:             clientID,
				Name:           "",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
			},
			expectError: true,
			errorMsg:    "name",
		},
		{
			name: "error - name too long",
			client: domain.Client{
				ID:             clientID,
				Name:           string(make([]byte, 256)),
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
			},
			expectError: true,
			errorMsg:    "255",
		},
		{
			name: "success - empty registration ID (opcional)",
			client: domain.Client{
				ID:             clientID,
				Name:           "Test Without Reg",
				RegistrationID: nil,
				Status:         "ativo",
			},
			expectError: false,
		},
		{
			name: "error - invalid registration ID",
			client: domain.Client{
				ID:             clientID,
				Name:           "Test",
				RegistrationID: stringPtr("invalid"),
				Status:         "ativo",
			},
			expectError: true,
			errorMsg:    "valid",
		},
		{
			name: "error - non-existent client",
			client: domain.Client{
				ID:             "non-existent-id",
				Name:           "Test",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
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
	db := setupClientTest(t)
	defer CloseDB(db)
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientStore := NewClientStore(db)

	client1ID, err := InsertTestClient(db, "Client 1", "66.666.666/0006-66")
	if err != nil {
		t.Fatalf("Failed to insert client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Client 2", "99.999.999/0009-99")
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
	db := setupClientTest(t)
	defer CloseDB(db)
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientStore := NewClientStore(db)

	client1ID, err := InsertTestClient(db, "Client 1", "88.888.888/0008-88")
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
	_, err = InsertTestContract(db, "Expiring Contract", "KEY-EXP-001", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), lineID, clientID, nil)
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
	_, err = InsertTestContract(db, "Expired Contract", "KEY-EXPIRED-001", timePtr(now.AddDate(0, 0, -30)), timePtr(now.AddDate(0, 0, -5)), lineID, clientID, nil)
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
				RegistrationID: &tt.registrationID,
				Status:         "ativo",
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
				RegistrationID: &cnpj,
				Status:         "ativo",
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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

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
				RegistrationID: stringPtr("111.ABC.777-35"),
				Status:         "ativo",
			},
			expectError: true,
			description: "Update with invalid CPF should fail",
		},
		{
			name: "invalid - update with invalid CNPJ",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "Updated Name",
				RegistrationID: stringPtr("invalid-cnpj"),
				Status:         "ativo",
			},
			expectError: true,
			description: "Update with invalid CNPJ should fail",
		},
		{
			name: "invalid - update with name too long",
			updateData: domain.Client{
				ID:             clientID,
				Name:           strings.Repeat("a", 256),
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with only whitespace name",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "    ",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
			},
			expectError: true,
			description: "Update with whitespace-only name should fail",
		},
		{
			name: "valid - update with valid data",
			updateData: domain.Client{
				ID:             clientID,
				Name:           "Valid Updated Name",
				RegistrationID: stringPtr("45.723.174/0001-10"),
				Status:         "ativo",
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
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientStore := NewClientStore(db)

	_, err = clientStore.CreateClient(domain.Client{
		Name:           "First Client",
		RegistrationID: stringPtr("45.723.174/0001-10"),
		Status:         "ativo",
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
				RegistrationID: &tt.registrationID,
				Status:         "ativo",
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
				RegistrationID: &cnpj,
				Status:         "ativo",
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

// TestGetClientsByName tests the GetClientsByName function
func TestGetClientsByName(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := NewClientStore(db)

	// Create test clients
	regID1 := "45.723.174/0001-10"
	_, err := clientStore.CreateClient(domain.Client{
		Name:           "Acme Corporation",
		RegistrationID: &regID1,
		Status:         "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create client 1: %v", err)
	}

	regID2 := "11.222.333/0001-81"
	_, err = clientStore.CreateClient(domain.Client{
		Name:           "Acme Industries",
		RegistrationID: &regID2,
		Status:         "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create client 2: %v", err)
	}

	regID3 := "33.444.555/0001-81"
	_, err = clientStore.CreateClient(domain.Client{
		Name:           "Global Tech",
		RegistrationID: &regID3,
		Status:         "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create client 3: %v", err)
	}

	// Archive one client
	archivedRegID := "55.666.777/0001-81"
	archivedID, err := clientStore.CreateClient(domain.Client{
		Name:           "Acme Archived",
		RegistrationID: &archivedRegID,
		Status:         "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create archived client: %v", err)
	}
	err = clientStore.ArchiveClient(archivedID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	tests := []struct {
		name          string
		searchName    string
		expectedCount int
		expectError   bool
	}{
		{
			name:          "search 'Acme' - should find 2 active clients",
			searchName:    "Acme",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'acme' (case-insensitive) - should find 2",
			searchName:    "acme",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'Corporation' - should find 1",
			searchName:    "Corporation",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "search 'Global' - should find 1",
			searchName:    "Global",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "search 'NonExistent' - should find 0",
			searchName:    "NonExistent",
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:        "empty search name - should error",
			searchName:  "",
			expectError: true,
		},
		{
			name:        "only spaces - should error",
			searchName:  "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clients, err := clientStore.GetClientsByName(tt.searchName)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(clients) != tt.expectedCount {
				t.Errorf("Expected %d clients, got %d", tt.expectedCount, len(clients))
			}
		})
	}
}
