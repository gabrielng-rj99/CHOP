package store

import (
	"Contracts-Manager/backend/domain"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

func setupDependentTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

func TestCreateDependent(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	dependentStore := NewDependentStore(db)

	tests := []struct {
		name        string
		dependName  string
		clientID    string
		setup       func() (string, error)
		expectError bool
	}{
		{
			name:       "sucesso - criação normal",
			dependName: "Test Dependent",
			setup: func() (string, error) {
				return InsertTestClient(db, "TestClient1-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: false,
		},
		{
			name:       "erro - nome vazio",
			dependName: "",
			setup: func() (string, error) {
				return InsertTestClient(db, "TestClient2-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: true,
		},
		{
			name:       "erro - nome duplicado para mesma empresa",
			dependName: "Duplicate Dependent",
			setup: func() (string, error) {
				return InsertTestClient(db, "TestClient3-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: true,
		},
		{
			name:        "erro - empresa não existe",
			dependName:  "Test Dependent",
			clientID:    uuid.New().String(),
			expectError: true,
		},
		{
			name:        "erro - sem client_id",
			dependName:  "Test Dependent",
			clientID:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			clientID := tt.clientID
			if tt.setup != nil {
				id, err := tt.setup()
				if err != nil {
					t.Fatalf("Failed to setup test: %v", err)
				}
				clientID = id
			}

			dependent := domain.Dependent{
				Name:     tt.dependName,
				ClientID: clientID,
				Status:   "ativo",
			}

			// Para o teste de nome duplicado, insere a primeira entidade antes
			if tt.name == "erro - nome duplicado para mesma empresa" {
				_, err := dependentStore.CreateDependent(domain.Dependent{
					Name:     "Duplicate Dependent",
					ClientID: clientID,
					Status:   "ativo",
				})
				if err != nil {
					t.Fatalf("Failed to insert dependent for duplicate test: %v", err)
				}
			}

			id, err := dependentStore.CreateDependent(dependent)

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
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
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
		StartDate:   timePtr(startDate),
		EndDate:     timePtr(endDate),
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
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
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
			id:          uuid.New().String(),
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
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
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
			clientID:    uuid.New().String(),
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
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
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
				Status:   "ativo",
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			dependent: domain.Dependent{
				ID:       "",
				Name:     "Updated Dependent",
				ClientID: "client-id-1",
				Status:   "ativo",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			dependent: domain.Dependent{
				ID:       "dependent-id-1",
				Name:     "",
				ClientID: "client-id-1",
				Status:   "ativo",
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			dependent: domain.Dependent{
				ID:       "dependent-id-1",
				Name:     "Updated Dependent",
				ClientID: uuid.New().String(),
				Status:   "ativo",
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
				clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
				if err != nil {
					t.Fatalf("Failed to insert test client: %v", err)
				}
				createdID, err := dependentStore.CreateDependent(domain.Dependent{
					Name:     "Original Dependent",
					ClientID: clientID,
					Status:   "ativo",
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
				err = db.QueryRow("SELECT name, client_id FROM dependents WHERE id = $1", tt.dependent.ID).
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

// TestGetDependentsByName tests the GetDependentsByName function
func TestGetDependentsByName(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	dependentStore := NewDependentStore(db)

	// Create test client
	clientID, err := InsertTestClient(db, "Test Company", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create test dependents
	_, err = dependentStore.CreateDependent(domain.Dependent{
		Name:     "Branch Office Alpha",
		ClientID: clientID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create dependent 1: %v", err)
	}

	_, err = dependentStore.CreateDependent(domain.Dependent{
		Name:     "Branch Office Beta",
		ClientID: clientID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create dependent 2: %v", err)
	}

	_, err = dependentStore.CreateDependent(domain.Dependent{
		Name:     "Warehouse Unit",
		ClientID: clientID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create dependent 3: %v", err)
	}

	tests := []struct {
		name          string
		clientID      string
		searchName    string
		expectedCount int
		expectError   bool
	}{
		{
			name:          "search 'Branch' - should find 2",
			clientID:      clientID,
			searchName:    "Branch",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'branch' (case-insensitive) - should find 2",
			clientID:      clientID,
			searchName:    "branch",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'Office' - should find 2",
			clientID:      clientID,
			searchName:    "Office",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'Alpha' - should find 1",
			clientID:      clientID,
			searchName:    "Alpha",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "search 'Warehouse' - should find 1",
			clientID:      clientID,
			searchName:    "Warehouse",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "search 'NonExistent' - should find 0",
			clientID:      clientID,
			searchName:    "NonExistent",
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:        "empty client ID - should error",
			clientID:    "",
			searchName:  "Branch",
			expectError: true,
		},
		{
			name:        "empty search name - should error",
			clientID:    clientID,
			searchName:  "",
			expectError: true,
		},
		{
			name:        "only spaces - should error",
			clientID:    clientID,
			searchName:  "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dependents, err := dependentStore.GetDependentsByName(tt.clientID, tt.searchName)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(dependents) != tt.expectedCount {
				t.Errorf("Expected %d dependents, got %d", tt.expectedCount, len(dependents))
			}
		})
	}
}

func TestDeleteDependent(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
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
			id:          uuid.New().String(),
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
				err = db.QueryRow("SELECT COUNT(*) FROM dependents WHERE id = $1", tt.id).Scan(&count)
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
