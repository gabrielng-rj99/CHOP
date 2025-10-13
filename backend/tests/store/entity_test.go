package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

func setupEntityTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

func TestCreateEntity(t *testing.T) {
	db := setupEntityTest(t)
	defer CloseDB(db)

	// Create test client first
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	tests := []struct {
		name        string
		entity      domain.Entity
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			entity: domain.Entity{
				Name:     "Test Entity",
				ClientID: clientID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			entity: domain.Entity{
				Name:     "",
				ClientID: clientID,
			},
			expectError: true,
		},
		{
			name: "erro - nome duplicado para mesma empresa",
			entity: domain.Entity{
				Name:     "Test Entity",
				ClientID: clientID,
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			entity: domain.Entity{
				Name:     "Test Entity",
				ClientID: "non-existent-client",
			},
			expectError: true,
		},
		{
			name: "erro - sem client_id",
			entity: domain.Entity{
				Name: "Test Entity",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name != "erro - empresa não existe" {
				err := ClearTables(db)
				if err != nil {
					t.Fatalf("Failed to clear tables: %v", err)
				}
				// Recreate client after clearing
				clientID, err = InsertTestClient(db, "Test Client", "45.723.174/0001-10")
				if err != nil {
					t.Fatalf("Failed to insert test client: %v", err)
				}
				if tt.entity.ClientID == clientID {
					tt.entity.ClientID = clientID
				}
			}

			entityStore := store.NewEntityStore(db)

			// Para o teste de nome duplicado, insere a primeira entidade antes
			if tt.name == "erro - nome duplicado para mesma empresa" {
				_, err := entityStore.CreateEntity(domain.Entity{
					Name:     "Test Entity",
					ClientID: clientID,
				})
				if err != nil {
					t.Fatalf("Failed to insert entity for duplicate test: %v", err)
				}
			}

			id, err := entityStore.CreateEntity(tt.entity)

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

func TestDeleteEntityDisassociatesLicenses(t *testing.T) {
	db := setupEntityTest(t)
	defer CloseDB(db)

	// Create test client and entity
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}
	entityID, err := InsertTestEntity(db, "Entity Delete", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test entity: %v", err)
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

	// Insert license associated to entity
	licenseStore := store.NewLicenseStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	license := domain.License{
		Model:      "Licença Teste",
		ProductKey: "ENTITY-DEL-KEY-001",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
		EntityID:   &entityID,
	}
	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// Delete entity
	entityStore := store.NewEntityStore(db)
	err = entityStore.DeleteEntity(entityID)
	if err != nil {
		t.Fatalf("Failed to delete entity: %v", err)
	}

	// Check license entity_id is NULL
	updatedLicense, err := licenseStore.GetLicenseByID(licenseID)
	if err != nil {
		t.Fatalf("Failed to get license after entity deletion: %v", err)
	}
	if updatedLicense == nil || updatedLicense.EntityID != nil {
		t.Error("Expected license entity_id to be NULL after entity deletion")
	}
}

func TestGetEntityByID(t *testing.T) {
	db := setupEntityTest(t)
	defer CloseDB(db)

	// Create test client and entity
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	entityID, err := InsertTestEntity(db, "Test Entity", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test entity: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - unidade encontrada",
			id:          entityID,
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
			entityStore := store.NewEntityStore(db)
			entity, err := entityStore.GetEntityByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && entity == nil {
				t.Error("Expected entity but got nil")
			}
			if !tt.expectFound && entity != nil {
				t.Error("Expected no entity but got one")
			}
		})
	}
}

func TestGetEntitiesByClient(t *testing.T) {
	db := setupEntityTest(t)
	defer CloseDB(db)

	// Create test client
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert test entities
	testEntities := []string{"Entity 1", "Entity 2", "Entity 3"}
	for _, name := range testEntities {
		_, err := InsertTestEntity(db, name, clientID)
		if err != nil {
			t.Fatalf("Failed to insert test entity: %v", err)
		}
	}

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - unidades encontradas",
			clientID:    clientID,
			expectError: false,
			expectCount: len(testEntities),
		},
		{
			name:        "erro - empresa vazia",
			clientID:    "",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "sucesso - empresa sem unidades",
			clientID:    "non-existent-client",
			expectError: false,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entityStore := store.NewEntityStore(db)
			entities, err := entityStore.GetEntitiesByClientID(tt.clientID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(entities) != tt.expectCount {
				t.Errorf("Expected %d entities but got %d", tt.expectCount, len(entities))
			}
		})
	}
}

func TestUpdateEntity(t *testing.T) {
	db := setupEntityTest(t)
	defer CloseDB(db)

	// Create test client and entity
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	_, err = InsertTestEntity(db, "Test Entity", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test entity: %v", err)
	}

	tests := []struct {
		name        string
		entity      domain.Entity
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			entity: domain.Entity{
				ID:       "",
				Name:     "Updated Entity",
				ClientID: "",
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			entity: domain.Entity{
				ID:       "",
				Name:     "Updated Entity",
				ClientID: "client-id-1",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			entity: domain.Entity{
				ID:       "entity-id-1",
				Name:     "",
				ClientID: "client-id-1",
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			entity: domain.Entity{
				ID:       "entity-id-1",
				Name:     "Updated Entity",
				ClientID: "non-existent-client",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entityStore := store.NewEntityStore(db)
			// For the success case, ensure the entity exists before update
			if tt.name == "sucesso - atualização normal" {
				// Create test client first
				clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
				if err != nil {
					t.Fatalf("Failed to insert test client: %v", err)
				}
				createdID, err := entityStore.CreateEntity(domain.Entity{
					Name:     "Original Entity",
					ClientID: clientID,
				})
				if err != nil {
					t.Fatalf("Failed to create entity before update: %v", err)
				}
				tt.entity.ID = createdID
				tt.entity.ClientID = clientID
			}
			err := entityStore.UpdateEntity(tt.entity)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, clientID string
				err = db.QueryRow("SELECT name, client_id FROM entities WHERE id = ?", tt.entity.ID).
					Scan(&name, &clientID)
				if err != nil {
					t.Errorf("Failed to query updated entity: %v", err)
				}
				if name != tt.entity.Name {
					t.Errorf("Expected name %q but got %q", tt.entity.Name, name)
				}
				if clientID != tt.entity.ClientID {
					t.Errorf("Expected client_id %q but got %q", tt.entity.ClientID, clientID)
				}
			}
		})
	}
}

func TestDeleteEntity(t *testing.T) {
	db := setupEntityTest(t)
	defer CloseDB(db)

	// Create test client and entity
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	entityID, err := InsertTestEntity(db, "Test Entity", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test entity: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          entityID,
			expectError: false,
		},
		{
			name:        "erro - id vazio",
			id:          "",
			expectError: true,
		},
		{
			name:        "erro - id inexistente",
			id:          "non-existent-id",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entityStore := store.NewEntityStore(db)
			err := entityStore.DeleteEntity(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted entity: %v", err)
				}
				if count != 0 {
					t.Error("Expected entity to be deleted, but it still exists")
				}
			}
		})
	}
}
