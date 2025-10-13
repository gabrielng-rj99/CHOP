package tests

import (
	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
	"testing"
	"time"
)

func insertTestDependencies(db *sql.DB) (string, string, string, string, error) {
	clientID, err := InsertTestClient(db, "Test Client", "12.345.678/0001-90")
	if err != nil {
		return "", "", "", "", err
	}
	// Helper para inserir entidade no banco
	entityID := "test-entity-123"
	_, err = db.Exec(
		"INSERT INTO entities (id, name, client_id) VALUES (?, ?, ?)",
		entityID,
		"Test Entity",
		clientID,
	)
	if err != nil {
		return "", "", "", "", err
	}
	categoryID, err := InsertTestCategory(db, "Test Category")
	if err != nil {
		return "", "", "", "", err
	}
	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		return "", "", "", "", err
	}
	return clientID, entityID, categoryID, lineID, nil
}

func TestCreateLicense(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	t.Logf("DEBUG: clientID=%s, entityID=%s, lineID=%s", clientID, entityID, lineID)

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	tests := []struct {
		name        string
		license     domain.License
		expectError bool
	}{
		{
			name: "sucesso - criação normal com unidade",
			license: domain.License{
				Model:      "Test License",
				ProductKey: "TEST-KEY-125",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
				EntityID:   &entityID,
			},
			expectError: false,
		},
		{
			name: "sucesso - criação sem unidade",
			license: domain.License{
				Model:      "Test License",
				ProductKey: "TEST-KEY-124",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
				EntityID:   &entityID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			license: domain.License{
				ProductKey: "TEST-KEY-125",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - chave do produto vazia",
			license: domain.License{
				Model:     "Test License",
				StartDate: startDate,
				EndDate:   endDate,
				LineID:    lineID,
				ClientID:  clientID,
			},
			expectError: true,
		},
		{
			name: "erro - data final antes da inicial",
			license: domain.License{
				Model:      "Test License",
				ProductKey: "TEST-KEY-126",
				StartDate:  endDate,
				EndDate:    startDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - atualização com StartDate após EndDate",
			license: domain.License{
				Model:      "Test License Update",
				ProductKey: "TEST-KEY-UPDATE",
				StartDate:  endDate.AddDate(2, 0, 0),
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - atualização com StartDate após EndDate",
			license: domain.License{
				Model:      "Test License Update",
				ProductKey: "TEST-KEY-UPDATE",
				StartDate:  endDate.AddDate(2, 0, 0),
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - tipo inválido",
			license: domain.License{
				Model:      "Test License",
				ProductKey: "TEST-KEY-127",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     "invalid-line",
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - empresa inválida",
			license: domain.License{
				Model:      "Test License",
				ProductKey: "TEST-KEY-128",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   "invalid-client",
			},
			expectError: true,
		},
		{
			name: "erro - unidade inválida",
			license: domain.License{
				Model:      "Test License",
				ProductKey: "TEST-KEY-129",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
				EntityID:   stringPtr("invalid-entity"),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !tt.expectError {
				if err := ClearTables(db); err != nil {
					t.Fatalf("Failed to clear tables: %v", err)
				}
				clientID, entityID, _, lineID, err = insertTestDependencies(db)
				if err != nil {
					t.Fatalf("Failed to insert test dependencies: %v", err)
				}
				tt.license.ClientID = clientID
				tt.license.LineID = lineID
				if tt.license.EntityID != nil {
					tt.license.EntityID = &entityID
				}
			}

			t.Logf("DEBUG: Creating license with ClientID=%s, LineID=%s, EntityID=%v, Model=%s, ProductKey=%s", tt.license.ClientID, tt.license.LineID, tt.license.EntityID, tt.license.Model, tt.license.ProductKey)
			licenseStore := store.NewLicenseStore(db)
			id, err := licenseStore.CreateLicense(tt.license)

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

func TestUpdateLicenseEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	licenseStore := store.NewLicenseStore(db)
	license := domain.License{
		Model:      "Edge License",
		ProductKey: "EDGE-KEY-1",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
		EntityID:   &entityID,
	}
	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license for update edge case: %v", err)
	}

	// Atualizar com datas invertidas
	license.ID = licenseID
	license.StartDate = endDate.AddDate(2, 0, 0)
	license.EndDate = endDate
	err = licenseStore.UpdateLicense(license)
	if err == nil {
		t.Error("Expected error when updating license with StartDate after EndDate, got none")
	}

	// Atualizar licença inexistente
	license.ID = "non-existent-id"
	license.StartDate = startDate
	license.EndDate = endDate
	licenseStore = store.NewLicenseStore(db)
	err = licenseStore.UpdateLicense(license)
	if err == nil {
		t.Error("Expected error when updating non-existent license, got none")
	}
}

func TestDeleteLicenseEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	licenseStore := store.NewLicenseStore(db)
	// Tentar deletar licença inexistente
	err = licenseStore.DeleteLicense("non-existent-id")
	if err == nil {
		t.Error("Expected error when deleting non-existent license, got none")
	}
}

func TestDeleteClientEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientStore := store.NewClientStore(db)
	// Tentar deletar empresa inexistente
	err = clientStore.DeleteClientPermanently("non-existent-id")
	if err == nil {
		t.Error("Expected error when deleting non-existent client, got none")
	}
}

func TestGetLicenseByID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	_, err = db.Exec(
		"INSERT INTO licenses (id, name, product_key, start_date, end_date, line_id, client_id, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"test-license-123",
		"Test License",
		"TEST-KEY-123",
		startDate,
		endDate,
		lineID,
		clientID,
		entityID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - licença encontrada",
			id:          "test-license-123",
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
			licenseStore := store.NewLicenseStore(db)
			license, err := licenseStore.GetLicenseByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && license == nil {
				t.Error("Expected license but got nil")
			}
			if !tt.expectFound && license != nil {
				t.Error("Expected no license but got one")
			}
		})
	}
}

func TestGetLicensesByClientID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	for i := 0; i < 3; i++ {
		_, err := db.Exec(
			"INSERT INTO licenses (id, name, product_key, start_date, end_date, line_id, client_id, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			"test-license-"+string(rune('a'+i)),
			"Test License "+string(rune('A'+i)),
			"TEST-KEY-"+string(rune('a'+i)),
			startDate,
			endDate,
			lineID,
			clientID,
			entityID,
		)
		if err != nil {
			t.Fatalf("Failed to insert test license: %v", err)
		}
	}

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - licenças encontradas",
			clientID:    clientID,
			expectError: false,
			expectCount: 3,
		},
		{
			name:        "erro - empresa vazia",
			clientID:    "",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "erro - empresa não existe",
			clientID:    "non-existent-client",
			expectError: true,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(db)
			licenses, err := licenseStore.GetLicensesByClientID(tt.clientID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(licenses) != tt.expectCount {
				t.Errorf("Expected %d licenses but got %d", tt.expectCount, len(licenses))
			}
		})
	}
}

func TestUpdateLicense(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	licenseID := "test-license-123"
	_, err = db.Exec(
		"INSERT INTO licenses (id, name, product_key, start_date, end_date, line_id, client_id, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		licenseID,
		"Test License",
		"TEST-KEY-123",
		startDate,
		endDate,
		lineID,
		clientID,
		entityID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	tests := []struct {
		name        string
		license     domain.License
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			license: domain.License{
				ID:         licenseID,
				Model:      "Updated License",
				ProductKey: "TEST-KEY-123",
				StartDate:  startDate,
				EndDate:    endDate.AddDate(1, 0, 0),
				LineID:     lineID,
				ClientID:   clientID,
				EntityID:   &entityID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			license: domain.License{
				Model:      "Updated License",
				ProductKey: "TEST-KEY-123",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			license: domain.License{
				ID:         licenseID,
				ProductKey: "TEST-KEY-123",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - data final antes da inicial",
			license: domain.License{
				ID:         licenseID,
				Model:      "Updated License",
				ProductKey: "TEST-KEY-123",
				StartDate:  endDate,
				EndDate:    startDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenseStore := store.NewLicenseStore(db)
			err := licenseStore.UpdateLicense(tt.license)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var name string
				err = db.QueryRow("SELECT name FROM licenses WHERE id = ?", tt.license.ID).Scan(&name)
				if err != nil {
					t.Errorf("Failed to query updated license: %v", err)
				}
				if name != tt.license.Model {
					t.Errorf("Expected name %q but got %q", tt.license.Model, name)
				}
			}
		})
	}
}

func TestDeleteLicense(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, entityID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	licenseID := "test-license-123"
	_, err = db.Exec(
		"INSERT INTO licenses (id, name, product_key, start_date, end_date, line_id, client_id, entity_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		licenseID,
		"Test License",
		"TEST-KEY-123",
		startDate,
		endDate,
		lineID,
		clientID,
		entityID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test license: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          licenseID,
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
			licenseStore := store.NewLicenseStore(db)
			err := licenseStore.DeleteLicense(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM licenses WHERE id = ?", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted license: %v", err)
				}
				if count != 0 {
					t.Error("Expected license to be deleted, but it still exists")
				}
			}
		})
	}
}

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}
