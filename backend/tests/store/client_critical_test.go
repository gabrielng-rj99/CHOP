package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

func setupClientTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

// TestGetClientNameByID tests retrieving only the client name
func TestGetClientNameByID(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	// Insert test client
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	clientStore := store.NewClientStore(db)

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

// TestUpdateClientCritical tests client update with validation
func TestUpdateClientCritical(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	// Insert test client
	clientID, err := InsertTestClient(db, "Original Name", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	clientStore := store.NewClientStore(db)

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

// TestGetAllClientsCritical tests retrieving all non-archived clients
func TestGetAllClientsCritical(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := store.NewClientStore(db)

	// Insert multiple clients
	client1ID, err := InsertTestClient(db, "Client 1", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Client 2", "11.222.333/0001-81")
	if err != nil {
		t.Fatalf("Failed to insert client 2: %v", err)
	}

	// Archive one client
	now := time.Now()
	_, err = db.Exec("UPDATE clients SET archived_at = ? WHERE id = ?", now, client2ID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Get all clients
	clients, err := clientStore.GetAllClients()
	if err != nil {
		t.Fatalf("Failed to get all clients: %v", err)
	}

	// Should only return non-archived clients
	if len(clients) != 1 {
		t.Errorf("Expected 1 non-archived client, got %d", len(clients))
	}

	if len(clients) > 0 && clients[0].ID != client1ID {
		t.Errorf("Expected client ID '%s', got '%s'", client1ID, clients[0].ID)
	}

	// Verify archived_at is nil for non-archived
	if len(clients) > 0 && clients[0].ArchivedAt != nil {
		t.Error("Expected archived_at to be nil for non-archived client")
	}
}

// TestGetArchivedClientsCritical tests retrieving all archived clients
func TestGetArchivedClientsCritical(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := store.NewClientStore(db)

	// Insert multiple clients
	client1ID, err := InsertTestClient(db, "Client 1", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Client 2", "11.222.333/0001-81")
	if err != nil {
		t.Fatalf("Failed to insert client 2: %v", err)
	}

	// Archive both clients
	now := time.Now()
	_, err = db.Exec("UPDATE clients SET archived_at = ? WHERE id IN (?, ?)", now, client1ID, client2ID)
	if err != nil {
		t.Fatalf("Failed to archive clients: %v", err)
	}

	// Get archived clients
	clients, err := clientStore.GetArchivedClients()
	if err != nil {
		t.Fatalf("Failed to get archived clients: %v", err)
	}

	if len(clients) != 2 {
		t.Errorf("Expected 2 archived clients, got %d", len(clients))
	}

	// Verify all have archived_at set
	for _, client := range clients {
		if client.ArchivedAt == nil {
			t.Error("Expected archived_at to be set for archived client")
		}
	}
}

// TestDeleteClientPermanentlyWithActiveLicenses tests that deletion fails with active licenses
func TestDeleteClientPermanentlyWithActiveLicenses(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := store.NewClientStore(db)

	// Insert test client
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert test category and line
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Insert active license
	now := time.Now()
	_, err = InsertTestLicense(db, "Test License", "TEST-KEY-123", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	// Try to delete - should fail
	err = clientStore.DeleteClientPermanently(clientID)
	if err == nil {
		t.Error("Expected error deleting client with active licenses")
	}

	// Verify client still exists
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", clientID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query client: %v", err)
	}
	if count != 1 {
		t.Error("Expected client to still exist after failed deletion")
	}
}

// TestDeleteClientPermanentlyWithExpiredLicenses tests deletion succeeds with expired licenses
func TestDeleteClientPermanentlyWithExpiredLicenses(t *testing.T) {
	db := setupClientTestDB(t)
	defer CloseDB(db)

	clientStore := store.NewClientStore(db)

	// Insert test client
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert test category and line
	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Insert expired license
	now := time.Now()
	_, err = InsertTestLicense(db, "Test License", "TEST-KEY-456", now.AddDate(0, 0, -30), now.AddDate(0, 0, -5), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	// Delete should succeed
	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Errorf("Expected no error deleting client with expired licenses, got: %v", err)
	}

	// Verify client is deleted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", clientID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query client: %v", err)
	}
	if count != 0 {
		t.Error("Expected client to be deleted")
	}
}
