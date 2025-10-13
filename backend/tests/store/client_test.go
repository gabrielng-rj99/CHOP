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
			clientStore := store.NewClientStore(db)

			// Para o teste de duplicidade, não insira o cliente antes.
			// O próprio teste tentará criar o cliente duplicado e deve esperar erro.

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

func TestArchiveAndDeleteClientWithPermanentLicense(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	// 1. Inserir categoria
	categoryID, err := InsertTestCategory(db, "Categoria Permanente")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	// 2. Inserir linha vinculada à categoria
	lineID, err := InsertTestLine(db, "Linha Permanente", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// 3. Inserir cliente de teste
	clientID, err := InsertTestClient(db, "Empresa Permanente", "99.999.999/0001-99")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// 4. Inserir licença permanente (end_date muito distante)
	startDate := time.Now()
	endDate := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	licenseID, err := InsertTestLicense(db, "Licença Permanente", "KEY-PERM", startDate, endDate, lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert permanent license: %v", err)
	}

	clientStore := store.NewClientStore(db)

	// 5. Tentar excluir cliente (deve falhar pois tem licença ativa/permanente)
	err = clientStore.DeleteClientPermanently(clientID)
	if err == nil {
		t.Error("Expected error when deleting client with permanent license, got none")
	}

	// 6. Arquivar cliente (licença permanente deve ser arquivada)
	err = clientStore.ArchiveClient(clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// 7. Agora deve conseguir excluir cliente (licença permanente foi arquivada)
	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Fatalf("Failed to delete client with archived permanent license: %v", err)
	}

	// 8. Verificar se licença foi excluída
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM licenses WHERE id = ?", licenseID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query license after client deletion: %v", err)
	}
	if count != 0 {
		t.Error("Expected license to be deleted after client deletion")
	}
}

func TestDeleteClientWithActiveLicenses(t *testing.T) {
	db := setupClientTest(t)
	defer CloseDB(db)

	// Insert test client
	clientID, err := InsertTestClient(db, "Empresa Ativa", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert category and line
	categoryID, err := InsertTestCategory(db, "Categoria Teste")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	lineID, err := InsertTestLine(db, "Linha Teste", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Insert active license
	licenseStore := store.NewLicenseStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	license := domain.License{
		Model:      "Licença Ativa",
		ProductKey: "ACTIVE-KEY-001",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
	}
	_, err = licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create active license: %v", err)
	}

	clientStore := store.NewClientStore(db)
	err = clientStore.DeleteClientPermanently(clientID)
	if err == nil {
		t.Error("Expected error when deleting client with active licenses, got none")
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
