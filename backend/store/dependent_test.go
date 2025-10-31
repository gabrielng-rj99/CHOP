package store

import (
	"Contracts-Manager/backend/domain"
	"database/sql"
	"testing"
	"time"
)

func setupDependentTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

func TestCreateDependent(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client first
	clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	tests := []struct {
		name        string
		dependent   domain.Dependent
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			dependent: domain.Dependent{
				Name:     "Test Dependent",
				ClientID: clientID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			dependent: domain.Dependent{
				Name:     "",
				ClientID: clientID,
			},
			expectError: true,
		},
		{
			name: "erro - nome duplicado para mesma empresa",
			dependent: domain.Dependent{
				Name:     "Test Dependent",
				ClientID: clientID,
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			dependent: domain.Dependent{
				Name:     "Test Dependent",
				ClientID: "non-existent-client",
			},
			expectError: true,
		},
		{
			name: "erro - sem client_id",
			dependent: domain.Dependent{
				Name: "Test Dependent",
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
				if tt.dependent.ClientID == clientID {
					tt.dependent.ClientID = clientID
				}
			}

			dependentStore := NewDependentStore(db)

			// Para o teste de nome duplicado, insere a primeira entidade antes
			if tt.name == "erro - nome duplicado para mesma empresa" {
				_, err := dependentStore.CreateDependent(domain.Dependent{
					Name:     "Test Dependent",
					ClientID: clientID,
				})
				if err != nil {
					t.Fatalf("Failed to insert dependent for duplicate test: %v", err)
				}
			}

			id, err := dependentStore.CreateDependent(tt.dependent)

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

func TestDeleteDependentDisassociatesContracts(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}
	dependentID, err := InsertTestDependent(db, "Dependent Delete", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
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

	// Insert license associated to dependent
	contractStore := NewContractStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contract := domain.Contract{
		Model:       "Licença Teste",
		ProductKey:  "ENTITY-DEL-KEY-001",
		StartDate:   startDate,
		EndDate:     endDate,
		LineID:      lineID,
		ClientID:    clientID,
		DependentID: &dependentID,
	}
	contractID, err := contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Delete dependent
	dependentStore := NewDependentStore(db)
	err = dependentStore.DeleteDependent(dependentID)
	if err != nil {
		t.Fatalf("Failed to delete dependent: %v", err)
	}

	// Check contract dependent_id is NULL
	updatedContract, err := contractStore.GetContractByID(contractID)
	if err != nil {
		t.Fatalf("Failed to get contract after dependent deletion: %v", err)
	}
	if updatedContract == nil || updatedContract.DependentID != nil {
		t.Error("Expected contract dependent_id to be NULL after dependent deletion")
	}
}

func TestGetDependentByID(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	dependentID, err := InsertTestDependent(db, "Test Dependent", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - unidade encontrada",
			id:          dependentID,
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
			dependentStore := NewDependentStore(db)
			dependent, err := dependentStore.GetDependentByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && dependent == nil {
				t.Error("Expected dependent but got nil")
			}
			if !tt.expectFound && dependent != nil {
				t.Error("Expected no dependent but got one")
			}
		})
	}
}

func TestGetDependentsByClient(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert test dependents
	testDependents := []string{"Dependent 1", "Dependent 2", "Dependent 3"}
	for _, name := range testDependents {
		_, err := InsertTestDependent(db, name, clientID)
		if err != nil {
			t.Fatalf("Failed to insert test dependent: %v", err)
		}
	}

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - dependentes encontrados",
			clientID:    clientID,
			expectError: false,
			expectCount: len(testDependents),
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
			dependentStore := NewDependentStore(db)
			dependents, err := dependentStore.GetDependentsByClientID(tt.clientID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(dependents) != tt.expectCount {
				t.Errorf("Expected %d dependents but got %d", tt.expectCount, len(dependents))
			}
		})
	}
}

func TestUpdateDependent(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	_, err = InsertTestDependent(db, "Test Dependent", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
	}

	tests := []struct {
		name        string
		dependent   domain.Dependent
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			dependent: domain.Dependent{
				ID:       "",
				Name:     "Updated Dependent",
				ClientID: "",
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			dependent: domain.Dependent{
				ID:       "",
				Name:     "Updated Dependent",
				ClientID: "client-id-1",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			dependent: domain.Dependent{
				ID:       "dependent-id-1",
				Name:     "",
				ClientID: "client-id-1",
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			dependent: domain.Dependent{
				ID:       "dependent-id-1",
				Name:     "Updated Dependent",
				ClientID: "non-existent-client",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dependentStore := NewDependentStore(db)
			// For the success case, ensure the dependent exists before update
			if tt.name == "sucesso - atualização normal" {
				// Create test client first
				clientID, err := InsertTestClient(db, "Test Client", "45.723.174/0001-10")
				if err != nil {
					t.Fatalf("Failed to insert test client: %v", err)
				}
				createdID, err := dependentStore.CreateDependent(domain.Dependent{
					Name:     "Original Dependent",
					ClientID: clientID,
				})
				if err != nil {
					t.Fatalf("Failed to create dependent before update: %v", err)
				}
				tt.dependent.ID = createdID
				tt.dependent.ClientID = clientID
			}
			err := dependentStore.UpdateDependent(tt.dependent)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, clientID string
				err = db.QueryRow("SELECT name, client_id FROM dependents WHERE id = ?", tt.dependent.ID).
					Scan(&name, &clientID)
				if err != nil {
					t.Errorf("Failed to query updated dependent: %v", err)
				}
				if name != tt.dependent.Name {
					t.Errorf("Expected name %q but got %q", tt.dependent.Name, name)
				}
				if clientID != tt.dependent.ClientID {
					t.Errorf("Expected client_id %q but got %q", tt.dependent.ClientID, clientID)
				}
			}
		})
	}
}

func TestDeleteDependent(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	dependentID, err := InsertTestDependent(db, "Test Dependent", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          dependentID,
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
			dependentStore := NewDependentStore(db)
			err := dependentStore.DeleteDependent(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM dependents WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted dependent: %v", err)
				}
				if count != 0 {
					t.Error("Expected dependent to be deleted, but it still exists")
				}
			}
		})
	}
}
