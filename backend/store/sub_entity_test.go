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

func TestCreateSubEntity(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	subEntityStore := NewSubEntityStore(db)

	tests := []struct {
		name        string
		dependName  string
		entityID    string
		setup       func() (string, error)
		expectError bool
	}{
		{
			name:       "sucesso - criação normal",
			dependName: "Test SubEntity",
			setup: func() (string, error) {
				return InsertTestEntity(db, "TestClient1-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: false,
		},
		{
			name:       "erro - nome vazio",
			dependName: "",
			setup: func() (string, error) {
				return InsertTestEntity(db, "TestClient2-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: true,
		},
		{
			name:       "erro - nome duplicado para mesma empresa",
			dependName: "Duplicate SubEntity",
			setup: func() (string, error) {
				return InsertTestEntity(db, "TestClient3-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: true,
		},
		{
			name:        "erro - empresa não existe",
			dependName:  "Test SubEntity",
			entityID:    uuid.New().String(),
			expectError: true,
		},
		{
			name:        "erro - sem entity_id",
			dependName:  "Test SubEntity",
			entityID:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			entityID := tt.entityID
			if tt.setup != nil {
				id, err := tt.setup()
				if err != nil {
					t.Fatalf("Failed to setup test: %v", err)
				}
				entityID = id
			}

			dependent := domain.SubEntity{
				Name:     tt.dependName,
				EntityID: entityID,
				Status:   "ativo",
			}

			// Para o teste de nome duplicado, insere a primeira entidade antes
			if tt.name == "erro - nome duplicado para mesma empresa" {
				_, err := subEntityStore.CreateSubEntity(domain.SubEntity{
					Name:     "Duplicate SubEntity",
					EntityID: entityID,
					Status:   "ativo",
				})
				if err != nil {
					t.Fatalf("Failed to insert dependent for duplicate test: %v", err)
				}
			}

			id, err := subEntityStore.CreateSubEntity(dependent)

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

func TestDeleteSubEntityDisassociatesContracts(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}
	subEntityID, err := InsertTestSubEntity(db, "SubEntity Delete", entityID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
	}

	// Insert category and line
	categoryID, err := InsertTestCategory(db, "Categoria Teste")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	subcategoryID, err := InsertTestSubcategory(db, "Linha Teste", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Insert license associated to dependent
	agreementStore := NewAgreementStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contract := domain.Agreement{
		Model:       "Licença Teste",
		ItemKey:  "ENTITY-DEL-KEY-001",
		StartDate:   timePtr(startDate),
		EndDate:     timePtr(endDate),
		SubcategoryID:      subcategoryID,
		EntityID:    entityID,
		SubEntityID: &subEntityID,
	}
	contractID, err := agreementStore.CreateAgreement(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Delete dependent
	subEntityStore := NewSubEntityStore(db)
	err = subEntityStore.DeleteSubEntity(subEntityID)
	if err != nil {
		t.Fatalf("Failed to delete dependent: %v", err)
	}

	// Check contract sub_entity_id is NULL
	updatedContract, err := agreementStore.GetAgreementByID(contractID)
	if err != nil {
		t.Fatalf("Failed to get contract after dependent deletion: %v", err)
	}
	if updatedContract == nil || updatedContract.SubEntityID != nil {
		t.Error("Expected contract sub_entity_id to be NULL after dependent deletion")
	}
}

func TestGetSubEntityByID(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subEntityID, err := InsertTestSubEntity(db, "Test SubEntity", entityID)
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
			id:          subEntityID,
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
			subEntityStore := NewSubEntityStore(db)
			dependent, err := subEntityStore.GetSubEntityByID(tt.id)

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
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert test sub_entities
	testDependents := []string{"SubEntity 1", "SubEntity 2", "SubEntity 3"}
	for _, name := range testDependents {
		_, err := InsertTestSubEntity(db, name, entityID)
		if err != nil {
			t.Fatalf("Failed to insert test dependent: %v", err)
		}
	}

	tests := []struct {
		name        string
		entityID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - dependentes encontrados",
			entityID:    entityID,
			expectError: false,
			expectCount: len(testDependents),
		},
		{
			name:        "erro - empresa vazia",
			entityID:    "",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "sucesso - empresa sem unidades",
			entityID:    uuid.New().String(),
			expectError: false,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subEntityStore := NewSubEntityStore(db)
			sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(tt.entityID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(sub_entities) != tt.expectCount {
				t.Errorf("Expected %d sub_entities but got %d", tt.expectCount, len(sub_entities))
			}
		})
	}
}

func TestUpdateSubEntity(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	_, err = InsertTestSubEntity(db, "Test SubEntity", entityID)
	if err != nil {
		t.Fatalf("Failed to insert test dependent: %v", err)
	}

	tests := []struct {
		name        string
		subEntity   domain.SubEntity
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			subEntity: domain.SubEntity{
				ID:       "",
				Name:     "Updated SubEntity",
				EntityID: "",
				Status:   "ativo",
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			subEntity: domain.SubEntity{
				ID:       "",
				Name:     "Updated SubEntity",
				EntityID: "client-id-1",
				Status:   "ativo",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			subEntity: domain.SubEntity{
				ID:       "dependent-id-1",
				Name:     "",
				EntityID: "client-id-1",
				Status:   "ativo",
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			subEntity: domain.SubEntity{
				ID:       "dependent-id-1",
				Name:     "Updated SubEntity",
				EntityID: uuid.New().String(),
				Status:   "ativo",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subEntityStore := NewSubEntityStore(db)
			// For the success case, ensure the dependent exists before update
			if tt.name == "sucesso - atualização normal" {
				// Create test client first
				entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
				if err != nil {
					t.Fatalf("Failed to insert test client: %v", err)
				}
				createdID, err := subEntityStore.CreateSubEntity(domain.SubEntity{
					Name:     "Original SubEntity",
					EntityID: entityID,
					Status:   "ativo",
				})
				if err != nil {
					t.Fatalf("Failed to create dependent before update: %v", err)
				}
				tt.subEntity.ID = createdID
				tt.subEntity.EntityID = entityID
			}
			err := subEntityStore.UpdateSubEntity(tt.subEntity)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, entityID string
				err = db.QueryRow("SELECT name, entity_id FROM sub_entities WHERE id = $1", tt.subEntity.ID).
					Scan(&name, &entityID)
				if err != nil {
					t.Errorf("Failed to query updated dependent: %v", err)
				}
				if name != tt.subEntity.Name {
					t.Errorf("Expected name %q but got %q", tt.subEntity.Name, name)
				}
				if entityID != tt.subEntity.EntityID {
					t.Errorf("Expected entity_id %q but got %q", tt.subEntity.EntityID, entityID)
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

	subEntityStore := NewSubEntityStore(db)

	// Create test client
	entityID, err := InsertTestEntity(db, "Test Company", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create test sub_entities
	_, err = subEntityStore.CreateSubEntity(domain.SubEntity{
		Name:     "Branch Office Alpha",
		EntityID: entityID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create dependent 1: %v", err)
	}

	_, err = subEntityStore.CreateSubEntity(domain.SubEntity{
		Name:     "Branch Office Beta",
		EntityID: entityID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create dependent 2: %v", err)
	}

	_, err = subEntityStore.CreateSubEntity(domain.SubEntity{
		Name:     "Warehouse Unit",
		EntityID: entityID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create dependent 3: %v", err)
	}

	tests := []struct {
		name          string
		entityID      string
		searchName    string
		expectedCount int
		expectError   bool
	}{
		{
			name:          "search 'Branch' - should find 2",
			entityID:      entityID,
			searchName:    "Branch",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'branch' (case-insensitive) - should find 2",
			entityID:      entityID,
			searchName:    "branch",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'Office' - should find 2",
			entityID:      entityID,
			searchName:    "Office",
			expectedCount: 2,
			expectError:   false,
		},
		{
			name:          "search 'Alpha' - should find 1",
			entityID:      entityID,
			searchName:    "Alpha",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "search 'Warehouse' - should find 1",
			entityID:      entityID,
			searchName:    "Warehouse",
			expectedCount: 1,
			expectError:   false,
		},
		{
			name:          "search 'NonExistent' - should find 0",
			entityID:      entityID,
			searchName:    "NonExistent",
			expectedCount: 0,
			expectError:   false,
		},
		{
			name:        "empty entity ID - should error",
			entityID:    "",
			searchName:  "Branch",
			expectError: true,
		},
		{
			name:        "empty search name - should error",
			entityID:    entityID,
			searchName:  "",
			expectError: true,
		},
		{
			name:        "only spaces - should error",
			entityID:    entityID,
			searchName:  "   ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sub_entities, err := subEntityStore.GetDependentsByName(tt.entityID, tt.searchName)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(sub_entities) != tt.expectedCount {
				t.Errorf("Expected %d sub_entities, got %d", tt.expectedCount, len(sub_entities))
			}
		})
	}
}

func TestDeleteSubEntity(t *testing.T) {
	db := setupDependentTest(t)
	defer CloseDB(db)

	// Create test client and dependent
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subEntityID, err := InsertTestSubEntity(db, "Test SubEntity", entityID)
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
			id:          subEntityID,
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
			subEntityStore := NewSubEntityStore(db)
			err := subEntityStore.DeleteSubEntity(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM sub_entities WHERE id = $1", tt.id).Scan(&count)
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
