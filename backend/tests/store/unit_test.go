package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
)

func setupUnitTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

func TestCreateUnit(t *testing.T) {
	db := setupUnitTest(t)
	defer CloseDB(db)

	// Create test company first
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	tests := []struct {
		name        string
		unit        domain.Unit
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			unit: domain.Unit{
				Name:      "Test Unit",
				CompanyID: companyID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			unit: domain.Unit{
				Name:      "",
				CompanyID: companyID,
			},
			expectError: true,
		},
		{
			name: "erro - empresa não existe",
			unit: domain.Unit{
				Name:      "Test Unit",
				CompanyID: "non-existent-company",
			},
			expectError: true,
		},
		{
			name: "erro - sem company_id",
			unit: domain.Unit{
				Name: "Test Unit",
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
				// Recreate company after clearing
				companyID, err = InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
				if err != nil {
					t.Fatalf("Failed to insert test company: %v", err)
				}
				if tt.unit.CompanyID == companyID {
					tt.unit.CompanyID = companyID
				}
			}

			unitStore := store.NewUnitStore(db)
			id, err := unitStore.CreateUnit(tt.unit)

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

func TestGetUnitByID(t *testing.T) {
	db := setupUnitTest(t)
	defer CloseDB(db)

	// Create test company and unit
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	unitID, err := InsertTestUnit(db, "Test Unit", companyID)
	if err != nil {
		t.Fatalf("Failed to insert test unit: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - unidade encontrada",
			id:          unitID,
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
			unitStore := store.NewUnitStore(db)
			unit, err := unitStore.GetUnitByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && unit == nil {
				t.Error("Expected unit but got nil")
			}
			if !tt.expectFound && unit != nil {
				t.Error("Expected no unit but got one")
			}
		})
	}
}

func TestGetUnitsByCompany(t *testing.T) {
	db := setupUnitTest(t)
	defer CloseDB(db)

	// Create test company
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	// Insert test units
	testUnits := []string{"Unit 1", "Unit 2", "Unit 3"}
	for _, name := range testUnits {
		_, err := InsertTestUnit(db, name, companyID)
		if err != nil {
			t.Fatalf("Failed to insert test unit: %v", err)
		}
	}

	tests := []struct {
		name        string
		companyID   string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - unidades encontradas",
			companyID:   companyID,
			expectError: false,
			expectCount: len(testUnits),
		},
		{
			name:        "erro - empresa vazia",
			companyID:   "",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "sucesso - empresa sem unidades",
			companyID:   "non-existent-company",
			expectError: false,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unitStore := store.NewUnitStore(db)
			units, err := unitStore.GetUnitsByCompanyID(tt.companyID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(units) != tt.expectCount {
				t.Errorf("Expected %d units but got %d", tt.expectCount, len(units))
			}
		})
	}
}

func TestUpdateUnit(t *testing.T) {
	db := setupUnitTest(t)
	defer CloseDB(db)

	// Create test company and unit
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	unitID, err := InsertTestUnit(db, "Test Unit", companyID)
	if err != nil {
		t.Fatalf("Failed to insert test unit: %v", err)
	}

	tests := []struct {
		name        string
		unit        domain.Unit
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			unit: domain.Unit{
				ID:        unitID,
				Name:      "Updated Unit",
				CompanyID: companyID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			unit: domain.Unit{
				Name:      "Updated Unit",
				CompanyID: companyID,
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			unit: domain.Unit{
				ID:        unitID,
				Name:      "",
				CompanyID: companyID,
			},
			expectError: true,
		},
		{
			name: "erro - empresa inválida",
			unit: domain.Unit{
				ID:        unitID,
				Name:      "Updated Unit",
				CompanyID: "non-existent-company",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unitStore := store.NewUnitStore(db)
			err := unitStore.UpdateUnit(tt.unit)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify update
				var name, companyID string
				err = db.QueryRow("SELECT name, company_id FROM units WHERE id = ?", tt.unit.ID).
					Scan(&name, &companyID)
				if err != nil {
					t.Errorf("Failed to query updated unit: %v", err)
				}
				if name != tt.unit.Name {
					t.Errorf("Expected name %q but got %q", tt.unit.Name, name)
				}
				if companyID != tt.unit.CompanyID {
					t.Errorf("Expected company_id %q but got %q", tt.unit.CompanyID, companyID)
				}
			}
		})
	}
}

func TestDeleteUnit(t *testing.T) {
	db := setupUnitTest(t)
	defer CloseDB(db)

	// Create test company and unit
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	unitID, err := InsertTestUnit(db, "Test Unit", companyID)
	if err != nil {
		t.Fatalf("Failed to insert test unit: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          unitID,
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
			unitStore := store.NewUnitStore(db)
			err := unitStore.DeleteUnit(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify deletion
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM units WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted unit: %v", err)
				}
				if count != 0 {
					t.Error("Expected unit to be deleted, but it still exists")
				}
			}
		})
	}
}
