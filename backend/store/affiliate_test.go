/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
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

func setupAffiliateTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

func TestCreateAffiliate(t *testing.T) {
	db := setupAffiliateTest(t)
	defer CloseDB(db)

	subClientStore := NewAffiliateStore(db)

	tests := []struct {
		name        string
		dependName  string
		clientID    string
		setup       func() (string, error)
		expectError bool
	}{
		{
			name:       "sucesso - criação normal",
			dependName: "Test Affiliate",
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
			dependName: "Duplicate Affiliate",
			setup: func() (string, error) {
				return InsertTestClient(db, "TestClient3-"+uuid.New().String()[:8], generateUniqueCNPJ())
			},
			expectError: true,
		},
		{
			name:        "erro - empresa não existe",
			dependName:  "Test Affiliate",
			clientID:    uuid.New().String(),
			expectError: true,
		},
		{
			name:        "erro - sem client_id",
			dependName:  "Test Affiliate",
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

			affiliate := domain.Affiliate{
				Name:     tt.dependName,
				ClientID: clientID,
				Status:   "ativo",
			}

			// Para o teste de nome duplicado, insere a primeira entidade antes
			if tt.name == "erro - nome duplicado para mesma empresa" {
				_, err := subClientStore.CreateAffiliate(domain.Affiliate{
					Name:     "Duplicate Affiliate",
					ClientID: clientID,
					Status:   "ativo",
				})
				if err != nil {
					t.Fatalf("Failed to insert affiliate for duplicate test: %v", err)
				}
			}

			id, err := subClientStore.CreateAffiliate(affiliate)

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

func TestDeleteAffiliateDisassociatesContracts(t *testing.T) {
	db := setupAffiliateTest(t)
	defer CloseDB(db)

	// Create test client and affiliate
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}
	subClientID, err := InsertTestAffiliate(db, "Affiliate Delete", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test affiliate: %v", err)
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

	// Insert license associated to affiliate
	contractStore := NewContractStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contract := domain.Contract{
		Model:         "Licença Teste",
		ItemKey:       "TEST-DEL-KEY-001",
		StartDate:     timePtr(startDate),
		EndDate:       timePtr(endDate),
		SubcategoryID: subcategoryID,
		ClientID:      clientID,
		AffiliateID:   &subClientID,
	}
	contractID, err := contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Delete affiliate
	subClientStore := NewAffiliateStore(db)
	err = subClientStore.DeleteAffiliate(subClientID)
	if err != nil {
		t.Fatalf("Failed to delete affiliate: %v", err)
	}

	// Check contract affiliate_id is NULL
	updatedContract, err := contractStore.GetContractByID(contractID)
	if err != nil {
		t.Fatalf("Failed to get contract after affiliate deletion: %v", err)
	}
	if updatedContract == nil || updatedContract.AffiliateID != nil {
		t.Error("Expected contract affiliate_id to be NULL after affiliate deletion")
	}
}

func TestGetAffiliateByID(t *testing.T) {
	db := setupAffiliateTest(t)
	defer CloseDB(db)

	// Create test client and affiliate
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subClientID, err := InsertTestAffiliate(db, "Test Affiliate", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test affiliate: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - unidade encontrada",
			id:          subClientID,
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
			subClientStore := NewAffiliateStore(db)
			affiliate, err := subClientStore.GetAffiliateByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && affiliate == nil {
				t.Error("Expected affiliate but got nil")
			}
			if !tt.expectFound && affiliate != nil {
				t.Error("Expected no affiliate but got one")
			}
		})
	}
}

func TestGetAffiliatesByClient(t *testing.T) {
	db := setupAffiliateTest(t)
	defer CloseDB(db)

	// Create test client
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	// Insert test affiliates
	testAffiliates := []string{"Affiliate 1", "Affiliate 2", "Affiliate 3"}
	for _, name := range testAffiliates {
		_, err := InsertTestAffiliate(db, name, clientID)
		if err != nil {
			t.Fatalf("Failed to insert test affiliate: %v", err)
		}
	}

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - afiliados encontrados",
			clientID:    clientID,
			expectError: false,
			expectCount: len(testAffiliates),
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
			subClientStore := NewAffiliateStore(db)
			affiliates, err := subClientStore.GetAffiliatesByClientID(tt.clientID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(affiliates) != tt.expectCount {
				t.Errorf("Expected %d affiliates but got %d", tt.expectCount, len(affiliates))
			}
		})
	}
}

func TestUpdateAffiliate(t *testing.T) {
	db := setupAffiliateTest(t)
	defer CloseDB(db)

	// Create test client and affiliate
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	_, err = InsertTestAffiliate(db, "Test Affiliate", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test affiliate: %v", err)
	}

	tests := []struct {
		name        string
		subClient   domain.Affiliate
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			subClient: domain.Affiliate{
				ID:       "",
				Name:     "Updated Affiliate",
				ClientID: "",
				Status:   "ativo",
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			subClient: domain.Affiliate{
				ID:       "",
				Name:     "Updated Affiliate",
				ClientID: "client-id-1",
				Status:   "ativo",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			subClient: domain.Affiliate{
				ID:       "affiliate-id-1",
				Name:     "",
				ClientID: "client-id-1",
				Status:   "ativo",
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			subClient: domain.Affiliate{
				ID:       "affiliate-id-1",
				Name:     "Updated Affiliate",
				ClientID: uuid.New().String(),
				Status:   "ativo",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subClientStore := NewAffiliateStore(db)
			// For the success case, ensure the affiliate exists before update
			if tt.name == "sucesso - atualização normal" {
				// Create test client first
				clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
				if err != nil {
					t.Fatalf("Failed to insert test client: %v", err)
				}
				createdID, err := subClientStore.CreateAffiliate(domain.Affiliate{
					Name:     "Original Affiliate",
					ClientID: clientID,
					Status:   "ativo",
				})
				if err != nil {
					t.Fatalf("Failed to create affiliate before update: %v", err)
				}
				tt.subClient.ID = createdID
				tt.subClient.ClientID = clientID
			}
			err := subClientStore.UpdateAffiliate(tt.subClient)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, clientID string
				err = db.QueryRow("SELECT name, client_id FROM affiliates WHERE id = $1", tt.subClient.ID).
					Scan(&name, &clientID)
				if err != nil {
					t.Errorf("Failed to query updated affiliate: %v", err)
				}
				if name != tt.subClient.Name {
					t.Errorf("Expected name %q but got %q", tt.subClient.Name, name)
				}
				if clientID != tt.subClient.ClientID {
					t.Errorf("Expected client_id %q but got %q", tt.subClient.ClientID, clientID)
				}
			}
		})
	}
}

// TestGetAffiliatesByName tests the GetAffiliatesByName function
func TestGetAffiliatesByName(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	subClientStore := NewAffiliateStore(db)

	// Create test client
	clientID, err := InsertTestClient(db, "Test Company", "45.723.174/0001-10")
	if err != nil {
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create test affiliates
	_, err = subClientStore.CreateAffiliate(domain.Affiliate{
		Name:     "Branch Office Alpha",
		ClientID: clientID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create affiliate 1: %v", err)
	}

	_, err = subClientStore.CreateAffiliate(domain.Affiliate{
		Name:     "Branch Office Beta",
		ClientID: clientID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create affiliate 2: %v", err)
	}

	_, err = subClientStore.CreateAffiliate(domain.Affiliate{
		Name:     "Warehouse Unit",
		ClientID: clientID,
		Status:   "ativo",
	})
	if err != nil {
		t.Fatalf("Failed to create affiliate 3: %v", err)
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
			affiliates, err := subClientStore.GetAffiliatesByName(tt.clientID, tt.searchName)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(affiliates) != tt.expectedCount {
				t.Errorf("Expected %d affiliates, got %d", tt.expectedCount, len(affiliates))
			}
		})
	}
}

func TestDeleteAffiliate(t *testing.T) {
	db := setupAffiliateTest(t)
	defer CloseDB(db)

	// Create test client and affiliate
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	subClientID, err := InsertTestAffiliate(db, "Test Affiliate", clientID)
	if err != nil {
		t.Fatalf("Failed to insert test affiliate: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          subClientID,
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
			subClientStore := NewAffiliateStore(db)
			err := subClientStore.DeleteAffiliate(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM affiliates WHERE id = $1", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted affiliate: %v", err)
				}
				if count != 0 {
					t.Error("Expected affiliate to be deleted, but it still exists")
				}
			}
		})
	}
}
