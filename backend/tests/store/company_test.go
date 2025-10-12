package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

func setupCompanyTest(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

func TestCreateCompany(t *testing.T) {
	db := setupCompanyTest(t)
	defer CloseDB(db)

	tests := []struct {
		name        string
		company     domain.Company
		expectError bool
	}{
		{
			name: "sucesso - criação normal",
			company: domain.Company{
				Name: "Test Company",
				CNPJ: "12.345.678/0001-90",
			},
			expectError: false,
		},
		{
			name: "erro - CNPJ duplicado",
			company: domain.Company{
				Name: "Another Company",
				CNPJ: "12.345.678/0001-90",
			},
			expectError: true,
		},
		{
			name: "erro - CNPJ vazio",
			company: domain.Company{
				Name: "Test Company",
				CNPJ: "",
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			company: domain.Company{
				Name: "",
				CNPJ: "12.345.678/0001-91",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			companyStore := store.NewCompanyStore(db)

			// Insert the first company for the duplicate test
			if tt.name == "erro - CNPJ duplicado" {
				_, err := companyStore.CreateCompany(domain.Company{
					Name: "Test Company",
					CNPJ: "12.345.678/0001-90",
				})
				if err != nil {
					t.Fatalf("Failed to insert company for duplicate test: %v", err)
				}
			}

			id, err := companyStore.CreateCompany(tt.company)

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

func TestGetCompanyByID(t *testing.T) {
	db := setupCompanyTest(t)
	defer CloseDB(db)

	// Insert test company
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - empresa encontrada",
			id:          companyID,
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
			companyStore := store.NewCompanyStore(db)
			company, err := companyStore.GetCompanyByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && company == nil {
				t.Error("Expected company but got nil")
			}
			if !tt.expectFound && company != nil {
				t.Error("Expected no company but got one")
			}
		})
	}
}

func TestArchiveCompany(t *testing.T) {
	db := setupCompanyTest(t)
	defer CloseDB(db)

	// Insert test company
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - arquivamento normal",
			id:          companyID,
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
			companyStore := store.NewCompanyStore(db)
			err := companyStore.ArchiveCompany(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify company was archived
				var archivedAt *time.Time
				err = db.QueryRow("SELECT archived_at FROM companies WHERE id = ?", tt.id).Scan(&archivedAt)
				if err != nil {
					t.Errorf("Failed to query archived company: %v", err)
				}
				if archivedAt == nil {
					t.Error("Expected archived_at to be set, but it was nil")
				}
			}
		})
	}
}

func TestUnarchiveCompany(t *testing.T) {
	db := setupCompanyTest(t)
	defer CloseDB(db)

	// Insert and archive test company
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	_, err = db.Exec("UPDATE companies SET archived_at = ? WHERE id = ?", time.Now(), companyID)
	if err != nil {
		t.Fatalf("Failed to archive test company: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - desarquivamento normal",
			id:          companyID,
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
			companyStore := store.NewCompanyStore(db)
			err := companyStore.UnarchiveCompany(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify company was unarchived
				var archivedAt *time.Time
				err = db.QueryRow("SELECT archived_at FROM companies WHERE id = ?", tt.id).Scan(&archivedAt)
				if err != nil {
					t.Errorf("Failed to query unarchived company: %v", err)
				}
				if archivedAt != nil {
					t.Error("Expected archived_at to be nil after unarchiving")
				}
			}
		})
	}
}

func TestDeleteCompanyPermanently(t *testing.T) {
	db := setupCompanyTest(t)
	defer CloseDB(db)

	// Insert test company
	companyID, err := InsertTestCompany(db, "Test Company", "12.345.678/0001-90")
	if err != nil {
		t.Fatalf("Failed to insert test company: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          companyID,
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
			companyStore := store.NewCompanyStore(db)
			err := companyStore.DeleteCompanyPermanently(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				// Verify company was deleted
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted company: %v", err)
				}
				if count != 0 {
					t.Error("Expected company to be deleted, but it still exists")
				}
			}
		})
	}
}
