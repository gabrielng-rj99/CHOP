package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

func setupClientTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

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
			},
			expectError: false,
		},
		{
			name: "erro - CNPJ duplicado",
			client: domain.Client{
				Name:           "Another Client",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
		},
		{
			name: "erro - CNPJ vazio",
			client: domain.Client{
				Name:           "Test Client",
				RegistrationID: "",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			client: domain.Client{
				Name:           "",
				RegistrationID: "45.723.174/0001-10",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			clientStore := store.NewClientStore(db)

			// Insert the first client for the duplicate test
			if tt.name == "erro - CNPJ duplicado" {
				_, err := clientStore.CreateClient(domain.Client{
					Name:           "Test Client",
					RegistrationID: "45.723.174/0001-10",
				})
				if err != nil {
					t.Fatalf("Failed to insert client for duplicate test: %v", err)
				}
			}

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

func TestGetClientByID(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	// Insert test client
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
			clientStore := store.NewClientStore(db)
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

	// Insert test client
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
			clientStore := store.NewClientStore(db)
			err := clientStore.ArchiveClient(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify client was archived
				var archivedAt *time.Time
				err = db.QueryRow("SELECT archived_at FROM clients WHERE id = ?", tt.id).Scan(&archivedAt)
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

	// Insert and archive test client
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	_, err = db.Exec("UPDATE clients SET archived_at = ? WHERE id = ?", time.Now(), clientID)
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
			clientStore := store.NewClientStore(db)
			err := clientStore.UnarchiveClient(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify client was unarchived
				var archivedAt *time.Time
				err = db.QueryRow("SELECT archived_at FROM clients WHERE id = ?", tt.id).Scan(&archivedAt)
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

	// Insert test client
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
			clientStore := store.NewClientStore(db)
			err := clientStore.DeleteClientPermanently(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify client was deleted
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", tt.id).Scan(&count)
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
