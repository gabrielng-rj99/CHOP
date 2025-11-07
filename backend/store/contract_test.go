package store

import (
	"Contracts-Manager/backend/domain"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func generateUniqueCNPJ() string {
	uniqueID := uuid.New().String()[:8]
	return uniqueID[0:2] + "." + uniqueID[2:5] + ".111/0001-11"
}

func insertTestDependencies(db *sql.DB) (string, string, string, string, error) {
	uniqueID := uuid.New().String()[:8]
	clientID, err := InsertTestClient(db, "Test Client "+uniqueID, generateUniqueCNPJ())
	if err != nil {
		return "", "", "", "", err
	}
	// Helper para inserir entidade no banco
	dependentID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO dependents (id, name, client_id) VALUES ($1, $2, $3)",
		dependentID,
		"Test Dependent "+uniqueID,
		clientID,
	)
	if err != nil {
		return "", "", "", "", err
	}
	categoryID, err := InsertTestCategory(db, "Test Category "+uniqueID)
	if err != nil {
		return "", "", "", "", err
	}
	lineID, err := InsertTestLine(db, "Test Line "+uniqueID, categoryID)
	if err != nil {
		return "", "", "", "", err
	}
	return clientID, dependentID, categoryID, lineID, nil
}

// Teste: Não pode mover linha entre categorias
func TestCannotMoveLineBetweenCategories(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	categoryID1, err := InsertTestCategory(db, "Categoria 1")
	if err != nil {
		t.Fatalf("Failed to insert test category 1: %v", err)
	}
	categoryID2, err := InsertTestCategory(db, "Categoria 2")
	if err != nil {
		t.Fatalf("Failed to insert test category 2: %v", err)
	}

	lineStore := NewLineStore(db)
	line := domain.Line{
		Line:       "Linha Teste",
		CategoryID: categoryID1,
	}
	lineID, err := lineStore.CreateLine(line)
	if err != nil {
		t.Fatalf("Failed to create line: %v", err)
	}

	// Tentar mover linha para outra categoria
	lineUpdate := domain.Line{
		ID:         lineID,
		Line:       "Linha Teste",
		CategoryID: categoryID2,
	}
	err = lineStore.UpdateLine(lineUpdate)
	if err == nil {
		t.Error("Expected error when moving line between categories, got none")
	}
}

// Teste: Não pode deletar linha com contratos associadas
func TestDeleteLineWithContractsAssociated(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}
	categoryID, err := InsertTestCategory(db, "Categoria Teste")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	lineStore := NewLineStore(db)
	line := domain.Line{
		Line:       "Linha Teste",
		CategoryID: categoryID,
	}
	lineID, err := lineStore.CreateLine(line)
	if err != nil {
		t.Fatalf("Failed to create line: %v", err)
	}

	contractStore := NewContractStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contract := domain.Contract{
		Model:      "Licença Teste",
		ProductKey: "LINE-DEL-KEY-001",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
	}
	_, err = contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	err = lineStore.DeleteLine(lineID)
	if err == nil {
		t.Error("Expected error when deleting line with contracts associated, got none")
	}
}

func TestCreateContract(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	tests := []struct {
		name        string
		contract    domain.Contract
		expectError bool
	}{
		{
			name: "sucesso - criação normal com unidade",
			contract: domain.Contract{
				Model:       "Test Contract",
				ProductKey:  "TEST-KEY-125",
				StartDate:   startDate,
				EndDate:     endDate,
				LineID:      lineID,
				ClientID:    clientID,
				DependentID: &dependentID,
			},
			expectError: false,
		},
		{
			name: "sucesso - criação sem unidade",
			contract: domain.Contract{
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-124",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			contract: domain.Contract{
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
			contract: domain.Contract{
				Model:     "Test Contract",
				StartDate: startDate,
				EndDate:   endDate,
				LineID:    lineID,
				ClientID:  clientID,
			},
			expectError: true,
		},
		{
			name: "erro - data final antes da inicial",
			contract: domain.Contract{
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-126",
				StartDate:  endDate,
				EndDate:    startDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
		},
		{
			name: "erro - sobreposição de datas para mesma empresa/unidade/tipo",
			contract: domain.Contract{
				Model:       "Test Contract",
				ProductKey:  "TEST-KEY-OVERLAP",
				StartDate:   startDate,
				EndDate:     endDate,
				LineID:      lineID,
				ClientID:    clientID,
				DependentID: &dependentID,
			},
			expectError: true,
		},
		{
			name: "erro - atualização com StartDate após EndDate",
			contract: domain.Contract{
				Model:      "Test Contract Update",
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
			contract: domain.Contract{
				Model:      "Test Contract",
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
			contract: domain.Contract{
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-128",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   "invalid-client",
			},
			expectError: true,
		},
		{
			name: "erro - empresa arquivada",
			contract: domain.Contract{
				Model:      "Test Contract",
				ProductKey: "TEST-KEY-ARCHIVED",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID, // Usar clientID válido
			},
			expectError: true,
		},
		{
			name: "erro - unidade inválida",
			contract: domain.Contract{
				Model:       "Test Contract",
				ProductKey:  "TEST-KEY-129",
				StartDate:   startDate,
				EndDate:     endDate,
				LineID:      lineID,
				ClientID:    clientID,
				DependentID: func() *string { s := "invalid-dependent"; return &s }(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contractStore := NewContractStore(db)
			id, err := contractStore.CreateContract(tt.contract)
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

// Função de utilitário para status de licença deve estar fora do TestCreateContract!
func TestContractStatusUtil(t *testing.T) {
	now := time.Now()
	contractActive := domain.Contract{
		EndDate: now.AddDate(0, 1, 0), // expira em 1 mês
	}
	contractExpiring := domain.Contract{
		EndDate: now.AddDate(0, 0, 10), // expira em 10 dias
	}
	contractExpired := domain.Contract{
		EndDate: now.AddDate(0, 0, -1), // já expirou
	}

	statusActive := GetContractStatus(contractActive)
	statusExpiring := GetContractStatus(contractExpiring)
	statusExpired := GetContractStatus(contractExpired)

	if statusActive != "ativo" {
		t.Errorf("Expected status 'ativo', got '%s'", statusActive)
	}
	if statusExpiring != "expirando" {
		t.Errorf("Expected status 'expirando', got '%s'", statusExpiring)
	}
	if statusExpired != "expirado" {
		t.Errorf("Expected status 'expirado', got '%s'", statusExpired)
	}
}

func TestUpdateContractEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contractStore := NewContractStore(db)
	contract := domain.Contract{
		Model:       "Edge Contract",
		ProductKey:  "EDGE-KEY-1",
		StartDate:   startDate,
		EndDate:     endDate,
		LineID:      lineID,
		ClientID:    clientID,
		DependentID: &dependentID,
	}
	contractID, err := contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract for update edge case: %v", err)
	}

	// Atualizar com datas invertidas
	contract.ID = contractID
	contract.StartDate = endDate.AddDate(2, 0, 0)
	contract.EndDate = endDate
	err = contractStore.UpdateContract(contract)
	if err == nil {
		t.Error("Expected error when updating contract with StartDate after EndDate, got none")
	}

	// Atualizar licença inexistente
	contract.ID = uuid.New().String()
	contract.StartDate = startDate
	contract.EndDate = endDate
	contractStore = NewContractStore(db)
	err = contractStore.UpdateContract(contract)
	if err == nil {
		t.Error("Expected error when updating non-existent contract, got none")
	}
}

func TestDeleteContractEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	contractStore := NewContractStore(db)
	// Tentar deletar licença inexistente
	err = contractStore.DeleteContract(uuid.New().String())
	if err == nil {
		t.Error("Expected error when deleting non-existent contract, got none")
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

	clientStore := NewClientStore(db)
	// Tentar deletar empresa inexistente
	err = clientStore.DeleteClientPermanently(uuid.New().String())
	if err == nil {
		t.Error("Expected error when deleting non-existent client, got none")
	}
}

func TestGetContractByID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	_, err = db.Exec(
		"INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		uuid.New().String(),
		"Test Contract",
		"TEST-KEY-123",
		startDate,
		endDate,
		lineID,
		clientID,
		dependentID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test contract: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
		expectFound bool
	}{
		{
			name:        "sucesso - licença encontrada",
			id:          uuid.New().String(),
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
			contractStore := NewContractStore(db)
			contract, err := contractStore.GetContractByID(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if tt.expectFound && contract == nil {
				t.Error("Expected contract but got nil")
			}
			if !tt.expectFound && contract != nil {
				t.Error("Expected no contract but got one")
			}
		})
	}
}

func TestGetContractsByClientID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	for i := 0; i < 3; i++ {
		_, err := db.Exec(
			"INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
			"test-contract-"+string(rune('a'+i)),
			"Test Contract "+string(rune('A'+i)),
			"TEST-KEY-"+string(rune('a'+i)),
			startDate,
			endDate,
			lineID,
			clientID,
			dependentID,
		)
		if err != nil {
			t.Fatalf("Failed to insert test contract: %v", err)
		}
	}

	tests := []struct {
		name        string
		clientID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - contratos encontradas",
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
			contractStore := NewContractStore(db)
			contracts, err := contractStore.GetContractsByClientID(tt.clientID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(contracts) != tt.expectCount {
				t.Errorf("Expected %d contracts but got %d", tt.expectCount, len(contracts))
			}
		})
	}
}

func TestUpdateContract(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contractID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		contractID,
		"Test Contract",
		"TEST-KEY-UPDATE",
		startDate,
		endDate,
		lineID,
		clientID,
		dependentID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test contract: %v", err)
	}

	tests := []struct {
		name        string
		contract    domain.Contract
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			contract: domain.Contract{
				ID:          contractID,
				Model:       "Updated Contract",
				ProductKey:  "TEST-KEY-123",
				StartDate:   startDate,
				EndDate:     endDate.AddDate(1, 0, 0),
				LineID:      lineID,
				ClientID:    clientID,
				DependentID: &dependentID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			contract: domain.Contract{
				Model:      "Updated Contract",
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
			contract: domain.Contract{
				ID:         contractID,
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
			contract: domain.Contract{
				ID:         contractID,
				Model:      "Updated Contract",
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
			contractStore := NewContractStore(db)
			err := contractStore.UpdateContract(tt.contract)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var model string
				err = db.QueryRow("SELECT model FROM contracts WHERE id = $1", tt.contract.ID).Scan(&model)
				if err != nil {
					t.Errorf("Failed to query updated contract: %v", err)
				}
				if model != tt.contract.Model {
					t.Errorf("Expected model %q but got %q", tt.contract.Model, model)
				}
			}
		})
	}
}

func TestDeleteContract(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contractID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO contracts (id, model, product_key, start_date, end_date, line_id, client_id, dependent_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		contractID,
		"Test Contract",
		"TEST-KEY-DELETE",
		startDate,
		endDate,
		lineID,
		clientID,
		dependentID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test contract: %v", err)
	}

	tests := []struct {
		name        string
		id          string
		expectError bool
	}{
		{
			name:        "sucesso - deleção normal",
			id:          contractID,
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
			contractStore := NewContractStore(db)
			err := contractStore.DeleteContract(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM contracts WHERE id = $1", tt.id).Scan(&count)
				if err != nil {
					t.Errorf("Failed to query deleted contract: %v", err)
				}
				if count != 0 {
					t.Error("Expected contract to be deleted, but it still exists")
				}
			}
		})
	}
}

// Helper function to create a string pointer
func stringPtr(s string) *string {
	return &s
}

// ============================================================================
// CRITICAL TESTS
// ============================================================================

func setupContractTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

// TestGetContractsExpiringSoon tests retrieving contracts expiring within a specified number of days
func TestGetContractsExpiringSoon(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	contractStore := NewContractStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Insert contracts with different expiration dates
	// Contract 1: expires in 10 days (should be included in 30-day search)
	_, err = InsertTestContract(db, "Contract 1", "KEY-1", now.AddDate(0, 0, -10), now.AddDate(0, 0, 10), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 1: %v", err)
	}

	// Contract 2: expires in 60 days (should NOT be included in 30-day search)
	_, err = InsertTestContract(db, "Contract 2", "KEY-2", now.AddDate(0, 0, -10), now.AddDate(0, 0, 60), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 2: %v", err)
	}

	// Contract 3: already expired (should NOT be included)
	_, err = InsertTestContract(db, "Contract 3", "KEY-3", now.AddDate(0, 0, -30), now.AddDate(0, 0, -5), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 3: %v", err)
	}

	// Contract 4: expires in 25 days (should be included in 30-day search)
	_, err = InsertTestContract(db, "Contract 4", "KEY-4", now.AddDate(0, 0, -10), now.AddDate(0, 0, 25), lineID, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 4: %v", err)
	}

	// Get contracts expiring in 30 days
	contracts, err := contractStore.GetContractsExpiringSoon(30)
	if err != nil {
		t.Fatalf("Failed to get expiring contracts: %v", err)
	}

	if len(contracts) != 2 {
		t.Errorf("Expected 2 expiring contracts, got %d", len(contracts))
	}

	// Verify correct contracts are returned
	expiredKeys := make(map[string]bool)
	for _, l := range contracts {
		expiredKeys[l.ProductKey] = true
	}

	if !expiredKeys["KEY-1"] || !expiredKeys["KEY-4"] {
		t.Error("Expected contracts KEY-1 and KEY-4 in results")
	}
}

// TestGetContractsByLineIDCritical tests retrieving contracts by line ID
func TestGetContractsByLineIDCritical(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	contractStore := NewContractStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID1, err := InsertTestLine(db, "Line 1", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line 1: %v", err)
	}

	lineID2, err := InsertTestLine(db, "Line 2", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line 2: %v", err)
	}

	now := time.Now()

	// Insert contracts for different lines
	_, err = InsertTestContract(db, "Contract 1", "KEY-1", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 1: %v", err)
	}

	_, err = InsertTestContract(db, "Contract 2", "KEY-2", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 2: %v", err)
	}

	_, err = InsertTestContract(db, "Contract 3", "KEY-3", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID2, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 3: %v", err)
	}

	// Get contracts for lineID1
	contracts, err := contractStore.GetContractsByLineID(lineID1)
	if err != nil {
		t.Fatalf("Failed to get contracts by line: %v", err)
	}

	if len(contracts) != 2 {
		t.Errorf("Expected 2 contracts for line 1, got %d", len(contracts))
	}

	// Verify all returned contracts belong to lineID1
	for _, l := range contracts {
		if l.LineID != lineID1 {
			t.Errorf("Expected line ID '%s', got '%s'", lineID1, l.LineID)
		}
	}
}

// TestGetContractsByCategoryIDCritical tests retrieving contracts by category ID
func TestGetContractsByCategoryIDCritical(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	contractStore := NewContractStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID1, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert test category 2: %v", err)
	}

	lineID1, err := InsertTestLine(db, "Line 1", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert test line 1: %v", err)
	}

	lineID2, err := InsertTestLine(db, "Line 2", categoryID2)
	if err != nil {
		t.Fatalf("Failed to insert test line 2: %v", err)
	}

	now := time.Now()

	// Insert contracts for different categories
	_, err = InsertTestContract(db, "Contract 1", "KEY-1", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 1: %v", err)
	}

	_, err = InsertTestContract(db, "Contract 2", "KEY-2", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID1, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 2: %v", err)
	}

	_, err = InsertTestContract(db, "Contract 3", "KEY-3", now.AddDate(0, 0, -10), now.AddDate(0, 0, 30), lineID2, clientID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 3: %v", err)
	}

	// Get contracts for categoryID1
	contracts, err := contractStore.GetContractsByCategoryID(categoryID1)
	if err != nil {
		t.Fatalf("Failed to get contracts by category: %v", err)
	}

	if len(contracts) != 2 {
		t.Errorf("Expected 2 contracts for category 1, got %d", len(contracts))
	}

	// Verify all returned contracts belong to categoryID1
	for _, l := range contracts {
		if l.LineID != lineID1 {
			t.Errorf("Expected line ID '%s', got '%s'", lineID1, l.LineID)
		}
	}
}

// TestCreateContractWithOverlap tests contract creation fails when there's a time overlap
func TestCreateContractWithOverlap(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	contractStore := NewContractStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Create first contract
	firstContract := domain.Contract{
		Model:      "First Contract",
		ProductKey: "KEY-1",
		StartDate:  now.AddDate(0, 0, -10),
		EndDate:    now.AddDate(0, 0, 30),
		LineID:     lineID,
		ClientID:   clientID,
	}

	id, err := contractStore.CreateContract(firstContract)
	if err != nil {
		t.Fatalf("Failed to create first contract: %v", err)
	}
	if id == "" {
		t.Error("Expected contract ID")
	}

	// Try to create overlapping contract
	overlappingContract := domain.Contract{
		Model:      "Overlapping Contract",
		ProductKey: "KEY-2",
		StartDate:  now.AddDate(0, 0, 5),  // Within first contract period
		EndDate:    now.AddDate(0, 0, 20), // Within first contract period
		LineID:     lineID,
		ClientID:   clientID,
	}

	_, err = contractStore.CreateContract(overlappingContract)
	if err == nil {
		t.Error("Expected error creating overlapping contract")
	}
}

// TestCreateContractNonOverlappingValid tests that non-overlapping contracts can be created
func TestCreateContractNonOverlappingValid(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	contractStore := NewContractStore(db)

	// Insert test data
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Create first contract
	firstContract := domain.Contract{
		Model:      "First Contract",
		ProductKey: "KEY-1",
		StartDate:  now.AddDate(0, 0, -30),
		EndDate:    now.AddDate(0, 0, -5),
		LineID:     lineID,
		ClientID:   clientID,
	}

	id, err := contractStore.CreateContract(firstContract)
	if err != nil {
		t.Fatalf("Failed to create first contract: %v", err)
	}
	if id == "" {
		t.Error("Expected contract ID")
	}

	// Create non-overlapping contract (starts after first ends)
	secondContract := domain.Contract{
		Model:      "Second Contract",
		ProductKey: "KEY-2",
		StartDate:  now.AddDate(0, 0, -4),
		EndDate:    now.AddDate(0, 0, 30),
		LineID:     lineID,
		ClientID:   clientID,
	}

	id2, err := contractStore.CreateContract(secondContract)
	if err != nil {
		t.Fatalf("Failed to create second contract: %v", err)
	}
	if id2 == "" {
		t.Error("Expected contract ID for second contract")
	}
}

// ============================================================================
// VALIDATION & EDGE CASES
// ============================================================================

// TestCreateContractWithInvalidNames tests various invalid contract model names
func TestCreateContractWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	contractStore := NewContractStore(db)
	startDate := time.Now()
	var clientID, categoryID, lineID string

	// Generate long names
	longName := strings.Repeat("a", 256)
	veryLongName := strings.Repeat("a", 1000)

	tests := []struct {
		name        string
		model       string
		expectError bool
		description string
	}{
		{
			name:        "invalid - model name too long (256 chars)",
			model:       longName,
			expectError: true,
			description: "Contract model with 256 characters should be rejected",
		},
		{
			name:        "invalid - model name way too long (1000 chars)",
			model:       veryLongName,
			expectError: true,
			description: "Contract model with 1000 characters should be rejected",
		},
		{
			name:        "invalid - model name with only spaces",
			model:       "     ",
			expectError: true,
			description: "Contract model with only whitespace should be rejected",
		},
		{
			name:        "valid - model name at max length (255 chars)",
			model:       strings.Repeat("a", 255),
			expectError: false,
			description: "Contract model with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - model name with special characters",
			model:       "License Pro - Enterprise Edition (2025)",
			expectError: false,
			description: "Contract model with special characters should be allowed",
		},
		{
			name:        "valid - model name with accents",
			model:       "Licença Profissional",
			expectError: false,
			description: "Contract model with Portuguese accents should be allowed",
		},
	}

	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear tables before each test to avoid conflicts
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			// Re-insert dependencies after clearing tables
			var errInsert error
			clientID, errInsert = InsertTestClient(db, "Test Client", generateUniqueCNPJ())
			if errInsert != nil {
				t.Fatalf("Failed to insert test client: %v", errInsert)
			}

			categoryID, errInsert = InsertTestCategory(db, "Software")
			if errInsert != nil {
				t.Fatalf("Failed to insert test category: %v", errInsert)
			}

			lineID, errInsert = InsertTestLine(db, "Test Line", categoryID)
			if errInsert != nil {
				t.Fatalf("Failed to insert test line: %v", errInsert)
			}

			// Use different time periods for each contract to avoid overlap detection
			contractStart := startDate.AddDate(0, 0, idx*30)
			contractEnd := contractStart.AddDate(1, 0, 0)

			contract := domain.Contract{
				Model:      tt.model,
				ProductKey: "TEST-KEY-" + string(rune('A'+idx)),
				StartDate:  contractStart,
				EndDate:    contractEnd,
				LineID:     lineID,
				ClientID:   clientID,
			}

			_, errCreate := contractStore.CreateContract(contract)

			if tt.expectError && errCreate == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && errCreate != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, errCreate)
			}
		})
	}
}

// TestCreateContractWithInvalidProductKeys tests various invalid product key formats
func TestCreateContractWithInvalidProductKeys(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	contractStore := NewContractStore(db)
	startDate := time.Now()
	var clientID, categoryID, lineID string

	longKey := strings.Repeat("A", 256)
	veryLongKey := strings.Repeat("A", 1000)

	tests := []struct {
		name        string
		productKey  string
		expectError bool
		description string
	}{
		{
			name:        "invalid - product key too long (256 chars)",
			productKey:  longKey,
			expectError: true,
			description: "Product key with 256 characters should be rejected",
		},
		{
			name:        "invalid - product key way too long (1000 chars)",
			productKey:  veryLongKey,
			expectError: true,
			description: "Product key with 1000 characters should be rejected",
		},
		{
			name:        "invalid - product key with only spaces",
			productKey:  "     ",
			expectError: true,
			description: "Product key with only whitespace should be rejected",
		},
		{
			name:        "valid - product key at max length (255 chars)",
			productKey:  strings.Repeat("K", 255),
			expectError: false,
			description: "Product key with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - product key with special characters",
			productKey:  "ABCD-1234-EFGH-5678",
			expectError: false,
			description: "Product key with dashes should be allowed",
		},
		{
			name:        "valid - product key with mixed case",
			productKey:  "AbCd-1234-EfGh-5678",
			expectError: false,
			description: "Product key with mixed case should be allowed",
		},
	}

	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear tables before each test to avoid conflicts
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			// Re-insert dependencies after clearing tables
			var errInsert error
			clientID, errInsert = InsertTestClient(db, "Test Client", generateUniqueCNPJ())
			if errInsert != nil {
				t.Fatalf("Failed to insert test client: %v", errInsert)
			}

			categoryID, errInsert = InsertTestCategory(db, "Software")
			if errInsert != nil {
				t.Fatalf("Failed to insert test category: %v", errInsert)
			}

			lineID, errInsert = InsertTestLine(db, "Test Line", categoryID)
			if errInsert != nil {
				t.Fatalf("Failed to insert test line: %v", errInsert)
			}

			// Use different time periods for each contract to avoid overlap detection
			contractStart := startDate.AddDate(0, 0, idx*30)
			contractEnd := contractStart.AddDate(1, 0, 0)

			contract := domain.Contract{
				Model:      "Test Model " + string(rune('A'+idx)),
				ProductKey: tt.productKey,
				StartDate:  contractStart,
				EndDate:    contractEnd,
				LineID:     lineID,
				ClientID:   clientID,
			}

			_, errCreate := contractStore.CreateContract(contract)

			if tt.expectError && errCreate == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && errCreate != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, errCreate)
			}
		})
	}
}

// TestCreateContractWithDuplicateProductKey tests duplicate product key detection
func TestCreateContractWithDuplicateProductKey(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	contractStore := NewContractStore(db)
	startDate := time.Now()

	tests := []struct {
		name        string
		contract    domain.Contract
		expectError bool
		description string
	}{
		{
			name: "duplicate - same product key for same client/dependent",
			contract: domain.Contract{
				Model:      "Duplicate Contract",
				ProductKey: "DUPLICATE-KEY-TEST",
				StartDate:  startDate,
				EndDate:    startDate.AddDate(1, 0, 0),
			},
			expectError: true,
			description: "Same product key for same client/dependent should be rejected",
		},
		{
			name: "valid - same product key for different client",
			contract: domain.Contract{
				Model:      "Different Client Contract",
				ProductKey: "DUPLICATE-KEY-TEST",
				StartDate:  startDate.AddDate(0, 0, 60),
				EndDate:    startDate.AddDate(1, 0, 60),
			},
			expectError: false,
			description: "Same product key for different client should be allowed",
		},
		{
			name: "valid - same product key for same client but different dependent",
			contract: domain.Contract{
				Model:      "Different Dependent Contract",
				ProductKey: "DUPLICATE-KEY-TEST",
				StartDate:  startDate.AddDate(0, 0, 120),
				EndDate:    startDate.AddDate(1, 0, 120),
			},
			expectError: true,
			description: "Same product key with mismatched client/dependent should be rejected",
		},
	}

	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear tables before each test
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			// Setup dependencies for each test
			client1ID, errSetup := InsertTestClient(db, "Client 1", generateUniqueCNPJ())
			if errSetup != nil {
				t.Fatalf("Failed to insert client 1: %v", errSetup)
			}

			client2ID, errSetup := InsertTestClient(db, "Client 2", "11.222.333/0001-81")
			if errSetup != nil {
				t.Fatalf("Failed to insert client 2: %v", errSetup)
			}

			categoryID, errSetup := InsertTestCategory(db, "Software")
			if errSetup != nil {
				t.Fatalf("Failed to insert test category: %v", errSetup)
			}

			lineID, errSetup := InsertTestLine(db, "Test Line", categoryID)
			if errSetup != nil {
				t.Fatalf("Failed to insert test line: %v", errSetup)
			}

			// Create dependent for client 1
			dependent1ID := "dependent-1"
			_, errSetup = db.Exec("INSERT INTO dependents (id, name, client_id) VALUES ($1, $2, $3)",
				dependent1ID, "Dependent 1", client1ID)
			if errSetup != nil {
				t.Fatalf("Failed to insert dependent 1: %v", errSetup)
			}

			// Create dependent for client 2
			dependent2ID := "dependent-2"
			_, errSetup = db.Exec("INSERT INTO dependents (id, name, client_id) VALUES ($1, $2, $3)",
				dependent2ID, "Dependent 2", client2ID)
			if errSetup != nil {
				t.Fatalf("Failed to insert dependent 2: %v", errSetup)
			}

			// For test 0 (duplicate), create first contract and set up the contract to test
			if idx == 0 {
				_, errSetup = contractStore.CreateContract(domain.Contract{
					Model:       "First Contract",
					ProductKey:  "DUPLICATE-KEY-TEST",
					StartDate:   tt.contract.StartDate,
					EndDate:     tt.contract.EndDate,
					LineID:      lineID,
					ClientID:    client1ID,
					DependentID: &dependent1ID,
				})
				if errSetup != nil {
					t.Fatalf("Failed to create first contract: %v", errSetup)
				}
			}

			// For test 1 (different client), use client2
			contract := tt.contract
			if idx == 1 {
				contract.LineID = lineID
				contract.ClientID = client2ID
			} else {
				// For tests 0 and 2, use client1
				contract.LineID = lineID
				contract.ClientID = client1ID
				if idx == 2 {
					// Test 2 uses a dependent from client2 with client1 (should fail)
					contract.DependentID = &dependent2ID
				} else {
					// Test 0 uses dependent1
					contract.DependentID = &dependent1ID
				}
			}

			_, err := contractStore.CreateContract(contract)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateContractWithInvalidDates tests various date validation scenarios
func TestCreateContractWithInvalidDates(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	contractStore := NewContractStore(db)
	now := time.Now()
	var clientID, categoryID, lineID string

	tests := []struct {
		name        string
		startDate   time.Time
		endDate     time.Time
		expectError bool
		description string
	}{
		{
			name:        "invalid - end date before start date",
			startDate:   now,
			endDate:     now.AddDate(0, 0, -1),
			expectError: true,
			description: "End date before start date should be rejected",
		},
		{
			name:        "invalid - end date equals start date",
			startDate:   now,
			endDate:     now,
			expectError: true,
			description: "End date equal to start date should be rejected",
		},
		{
			name:        "valid - start date in the past",
			startDate:   now.AddDate(0, 0, -30),
			endDate:     now.AddDate(0, 0, 30),
			expectError: false,
			description: "Contract with start date in the past is allowed",
		},
		{
			name:        "valid - very short contract (1 day)",
			startDate:   now,
			endDate:     now.AddDate(0, 0, 1),
			expectError: false,
			description: "Contract with 1 day duration should be allowed",
		},
		{
			name:        "valid - very long contract (10 years)",
			startDate:   now,
			endDate:     now.AddDate(10, 0, 0),
			expectError: false,
			description: "Contract with 10 years duration should be allowed",
		},
		{
			name:        "valid - permanent contract (year 9999)",
			startDate:   now,
			endDate:     time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
			expectError: false,
			description: "Permanent contract with far future date should be allowed",
		},
		{
			name:        "invalid - negative duration (1 year backwards)",
			startDate:   now,
			endDate:     now.AddDate(-1, 0, 0),
			expectError: true,
			description: "Negative duration should be rejected",
		},
		{
			name:        "valid - start and end on same day but different times",
			startDate:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			endDate:     time.Date(2026, 1, 1, 23, 59, 59, 0, time.UTC),
			expectError: false,
			description: "Valid contract spanning more than a year",
		},
	}

	for idx, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear tables before each test to avoid conflicts
			if err := ClearTables(db); err != nil {
				t.Fatalf("Failed to clear tables: %v", err)
			}

			// Re-insert dependencies after clearing tables
			var errInsert error
			clientID, errInsert = InsertTestClient(db, "Test Client", generateUniqueCNPJ())
			if errInsert != nil {
				t.Fatalf("Failed to insert test client: %v", errInsert)
			}

			categoryID, errInsert = InsertTestCategory(db, "Software")
			if errInsert != nil {
				t.Fatalf("Failed to insert test category: %v", errInsert)
			}

			lineID, errInsert = InsertTestLine(db, "Test Line", categoryID)
			if errInsert != nil {
				t.Fatalf("Failed to insert test line: %v", errInsert)
			}

			// Use different time periods for each contract to avoid overlap detection
			contractStart := tt.startDate.AddDate(0, 0, idx*60)
			contractEnd := tt.endDate.AddDate(0, 0, idx*60)

			contract := domain.Contract{
				Model:      "Test Contract " + string(rune('A'+idx)),
				ProductKey: "KEY-" + string(rune('A'+idx)) + "-TEST",
				StartDate:  contractStart,
				EndDate:    contractEnd,
				LineID:     lineID,
				ClientID:   clientID,
			}

			_, err := contractStore.CreateContract(contract)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateContractWithArchivedClient tests that contracts cannot be created for archived clients
func TestCreateContractWithArchivedClient(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Setup dependencies
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Archive the client
	_, err = db.Exec("UPDATE clients SET archived_at = $1 WHERE id = $2", time.Now(), clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	contractStore := NewContractStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	contract := domain.Contract{
		Model:      "Test Contract",
		ProductKey: "ARCHIVED-CLIENT-KEY",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
	}

	_, err = contractStore.CreateContract(contract)
	if err == nil {
		t.Error("Expected error when creating contract for archived client, but got none")
	}
}

// TestUpdateContractWithInvalidData tests update operations with invalid data
func TestUpdateContractWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Setup dependencies
	clientID, err := InsertTestClient(db, "Test Client", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	lineID, err := InsertTestLine(db, "Test Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	contractStore := NewContractStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	// Create initial contract
	contractID, err := contractStore.CreateContract(domain.Contract{
		Model:      "Original Contract",
		ProductKey: "ORIGINAL-KEY",
		StartDate:  startDate,
		EndDate:    endDate,
		LineID:     lineID,
		ClientID:   clientID,
	})
	if err != nil {
		t.Fatalf("Failed to create initial contract: %v", err)
	}

	tests := []struct {
		name        string
		contract    domain.Contract
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			contract: domain.Contract{
				ID:         contractID,
				Model:      strings.Repeat("a", 256),
				ProductKey: "ORIGINAL-KEY",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with empty product key",
			contract: domain.Contract{
				ID:         contractID,
				Model:      "Updated Contract",
				ProductKey: "",
				StartDate:  startDate,
				EndDate:    endDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
			description: "Update with empty product key should fail",
		},
		{
			name: "invalid - update with end date before start date",
			contract: domain.Contract{
				ID:         contractID,
				Model:      "Updated Contract",
				ProductKey: "ORIGINAL-KEY",
				StartDate:  endDate,
				EndDate:    startDate,
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: true,
			description: "Update with invalid dates should fail",
		},
		{
			name: "valid - update with valid data",
			contract: domain.Contract{
				ID:         contractID,
				Model:      "Updated Contract Name",
				ProductKey: "ORIGINAL-KEY",
				StartDate:  startDate,
				EndDate:    endDate.AddDate(0, 1, 0),
				LineID:     lineID,
				ClientID:   clientID,
			},
			expectError: false,
			description: "Update with valid data should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := contractStore.UpdateContract(tt.contract)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// ============================================================================
// NEW METHODS & ADDITIONAL OPERATIONS
// ============================================================================

// TestGetAllContracts tests the GetAllContracts method
func TestGetAllContracts(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	contractStore := NewContractStore(db)

	// Setup dependencies
	clientID, dependentID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	tests := []struct {
		name           string
		contractsToAdd int
		expectedCount  int
	}{
		{
			name:           "empty database",
			contractsToAdd: 0,
			expectedCount:  0,
		},
		{
			name:           "single contract",
			contractsToAdd: 1,
			expectedCount:  1,
		},
		{
			name:           "multiple contracts",
			contractsToAdd: 5,
			expectedCount:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear contracts for each test
			if _, err := db.Exec("DELETE FROM contracts"); err != nil {
				t.Fatalf("Failed to clear contracts: %v", err)
			}

			// Add contracts
			for i := 0; i < tt.contractsToAdd; i++ {
				contract := domain.Contract{
					Model:       "Test Contract",
					ProductKey:  "KEY-" + string(rune(48+i)),
					StartDate:   time.Now().AddDate(0, 0, i*30),
					EndDate:     time.Now().AddDate(0, 0, (i+1)*30),
					LineID:      lineID,
					ClientID:    clientID,
					DependentID: &dependentID,
				}
				_, err := contractStore.CreateContract(contract)
				if err != nil {
					t.Fatalf("Failed to create contract: %v", err)
				}
			}

			// Test GetAllContracts
			contracts, err := contractStore.GetAllContracts()
			if err != nil {
				t.Errorf("GetAllContracts failed: %v", err)
			}

			if len(contracts) != tt.expectedCount {
				t.Errorf("Expected %d contracts, got %d", tt.expectedCount, len(contracts))
			}

			// Verify all contracts have required fields
			for _, contract := range contracts {
				if contract.ID == "" {
					t.Error("Contract ID is empty")
				}
				if contract.Model == "" {
					t.Error("Contract Model is empty")
				}
				if contract.ProductKey == "" {
					t.Error("Contract ProductKey is empty")
				}
			}
		})
	}
}

// TestGetContractsByLineID tests filtering contracts by line ID
func TestGetContractsByLineID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	contractStore := NewContractStore(db)

	// Setup dependencies
	clientID, dependentID, categoryID, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	// Create a second line in the same category
	lineID2, err := InsertTestLine(db, "Test Line 2", categoryID)
	if err != nil {
		t.Fatalf("Failed to create second line: %v", err)
	}

	// Create contracts for both lines
	contract1 := domain.Contract{
		Model:       "Contract Line 1",
		ProductKey:  "KEY-LINE1-001",
		StartDate:   time.Now(),
		EndDate:     time.Now().AddDate(1, 0, 0),
		LineID:      lineID,
		ClientID:    clientID,
		DependentID: &dependentID,
	}
	_, err = contractStore.CreateContract(contract1)
	if err != nil {
		t.Fatalf("Failed to create contract 1: %v", err)
	}

	contract2 := domain.Contract{
		Model:       "Contract Line 2",
		ProductKey:  "KEY-LINE2-001",
		StartDate:   time.Now(),
		EndDate:     time.Now().AddDate(1, 0, 0),
		LineID:      lineID2,
		ClientID:    clientID,
		DependentID: &dependentID,
	}
	_, err = contractStore.CreateContract(contract2)
	if err != nil {
		t.Fatalf("Failed to create contract 2: %v", err)
	}

	tests := []struct {
		name          string
		queryLineID   string
		expectedCount int
		shouldError   bool
	}{
		{
			name:          "valid line with contracts",
			queryLineID:   lineID,
			expectedCount: 1,
			shouldError:   false,
		},
		{
			name:          "valid line with different contracts",
			queryLineID:   lineID2,
			expectedCount: 1,
			shouldError:   false,
		},
		{
			name:          "empty line ID",
			queryLineID:   "",
			expectedCount: 0,
			shouldError:   true,
		},
		{
			name:          "non-existent line ID",
			queryLineID:   uuid.New().String(),
			expectedCount: 0,
			shouldError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contracts, err := contractStore.GetContractsByLineID(tt.queryLineID)

			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error: %v, got: %v", tt.shouldError, err)
			}

			if len(contracts) != tt.expectedCount {
				t.Errorf("Expected %d contracts, got %d", tt.expectedCount, len(contracts))
			}

			// Verify contracts belong to the queried line
			for _, contract := range contracts {
				if contract.LineID != tt.queryLineID {
					t.Errorf("Contract LineID %s doesn't match query LineID %s", contract.LineID, tt.queryLineID)
				}
			}
		})
	}
}

// TestGetContractsByCategoryID tests filtering contracts by category ID
func TestGetContractsByCategoryID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	contractStore := NewContractStore(db)

	// Setup dependencies
	clientID, dependentID, categoryID, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	// Create a second category with its own line
	categoryID2, err := InsertTestCategory(db, "Test Category 2")
	if err != nil {
		t.Fatalf("Failed to create second category: %v", err)
	}

	lineID2, err := InsertTestLine(db, "Test Line in Category 2", categoryID2)
	if err != nil {
		t.Fatalf("Failed to create line in second category: %v", err)
	}

	// Create contracts in both categories
	contract1 := domain.Contract{
		Model:       "Contract Category 1",
		ProductKey:  "KEY-CAT1-001",
		StartDate:   time.Now(),
		EndDate:     time.Now().AddDate(1, 0, 0),
		LineID:      lineID,
		ClientID:    clientID,
		DependentID: &dependentID,
	}
	_, err = contractStore.CreateContract(contract1)
	if err != nil {
		t.Fatalf("Failed to create contract in category 1: %v", err)
	}

	contract2 := domain.Contract{
		Model:       "Contract Category 2",
		ProductKey:  "KEY-CAT2-001",
		StartDate:   time.Now(),
		EndDate:     time.Now().AddDate(1, 0, 0),
		LineID:      lineID2,
		ClientID:    clientID,
		DependentID: &dependentID,
	}
	_, err = contractStore.CreateContract(contract2)
	if err != nil {
		t.Fatalf("Failed to create contract in category 2: %v", err)
	}

	tests := []struct {
		name            string
		queryCategoryID string
		expectedCount   int
		shouldError     bool
	}{
		{
			name:            "valid category with contracts",
			queryCategoryID: categoryID,
			expectedCount:   1,
			shouldError:     false,
		},
		{
			name:            "valid category with different contracts",
			queryCategoryID: categoryID2,
			expectedCount:   1,
			shouldError:     false,
		},
		{
			name:            "empty category ID",
			queryCategoryID: "",
			expectedCount:   0,
			shouldError:     true,
		},
		{
			name:            "non-existent category ID",
			queryCategoryID: uuid.New().String(),
			expectedCount:   0,
			shouldError:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contracts, err := contractStore.GetContractsByCategoryID(tt.queryCategoryID)

			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error: %v, got: %v", tt.shouldError, err)
			}

			if len(contracts) != tt.expectedCount {
				t.Errorf("Expected %d contracts, got %d", tt.expectedCount, len(contracts))
			}

			// Verify contracts belong to lines in the queried category
			for _, contract := range contracts {
				var lineCategory string
				err := db.QueryRow("SELECT category_id FROM lines WHERE id = $1", contract.LineID).Scan(&lineCategory)
				if err != nil {
					t.Errorf("Failed to verify contract's line category: %v", err)
				}
				if lineCategory != tt.queryCategoryID {
					t.Errorf("Contract's line category %s doesn't match query category %s", lineCategory, tt.queryCategoryID)
				}
			}
		})
	}
}

// TestGetAllContractsWithMultipleClients tests GetAllContracts with contracts from different clients
func TestGetAllContractsWithMultipleClients(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	contractStore := NewContractStore(db)

	// Create two clients with their dependencies
	client1ID, entity1ID, _, line1ID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies for client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Test Client 2", "12.345.678/0001-99")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	entity2ID, err := InsertTestDependent(db, "Dependent 2", client2ID)
	if err != nil {
		t.Fatalf("Failed to create dependent 2: %v", err)
	}
	category2ID, err := InsertTestCategory(db, "Category 2")
	if err != nil {
		t.Fatalf("Failed to create category 2: %v", err)
	}
	line2ID, err := InsertTestLine(db, "Line 2", category2ID)
	if err != nil {
		t.Fatalf("Failed to create line 2: %v", err)
	}

	// Create contracts for both clients
	for i := 0; i < 3; i++ {
		contract := domain.Contract{
			Model:       "Contract Client 1",
			ProductKey:  "KEY-C1-" + string(rune(48+i)),
			StartDate:   time.Now().AddDate(0, 0, i*30),
			EndDate:     time.Now().AddDate(0, 0, (i+1)*30),
			LineID:      line1ID,
			ClientID:    client1ID,
			DependentID: &entity1ID,
		}
		_, err := contractStore.CreateContract(contract)
		if err != nil {
			t.Fatalf("Failed to create contract for client 1: %v", err)
		}
	}

	for i := 0; i < 2; i++ {
		contract := domain.Contract{
			Model:       "Contract Client 2",
			ProductKey:  "KEY-C2-" + string(rune(48+i)),
			StartDate:   time.Now().AddDate(0, 1, i*30),
			EndDate:     time.Now().AddDate(0, 1, (i+1)*30),
			LineID:      line2ID,
			ClientID:    client2ID,
			DependentID: &entity2ID,
		}
		_, err := contractStore.CreateContract(contract)
		if err != nil {
			t.Fatalf("Failed to create contract for client 2: %v", err)
		}
	}

	// Test GetAllContracts returns all contracts
	contracts, err := contractStore.GetAllContracts()
	if err != nil {
		t.Errorf("GetAllContracts failed: %v", err)
	}

	expectedTotal := 5
	if len(contracts) != expectedTotal {
		t.Errorf("Expected %d total contracts, got %d", expectedTotal, len(contracts))
	}

	// Verify we have contracts from both clients
	client1Count := 0
	client2Count := 0
	for _, contract := range contracts {
		if contract.ClientID == client1ID {
			client1Count++
		} else if contract.ClientID == client2ID {
			client2Count++
		}
	}

	if client1Count != 3 {
		t.Errorf("Expected 3 contracts for client 1, got %d", client1Count)
	}
	if client2Count != 2 {
		t.Errorf("Expected 2 contracts for client 2, got %d", client2Count)
	}
}

// TestGetContractsByLineIDWithMultipleClients tests that GetContractsByLineID returns contracts from all clients
func TestGetContractsByLineIDWithMultipleClients(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	contractStore := NewContractStore(db)

	// Create two clients
	client1ID, entity1ID, _, lineID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies for client 1: %v", err)
	}

	client2ID, err := InsertTestClient(db, "Test Client 2", "98.765.432/0001-11")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	entity2ID, err := InsertTestDependent(db, "Dependent 2", client2ID)
	if err != nil {
		t.Fatalf("Failed to create dependent 2: %v", err)
	}

	// Create contracts for the same line but different clients
	contract1 := domain.Contract{
		Model:       "Contract Client 1",
		ProductKey:  "KEY-SAME-001",
		StartDate:   time.Now(),
		EndDate:     time.Now().AddDate(1, 0, 0),
		LineID:      lineID,
		ClientID:    client1ID,
		DependentID: &entity1ID,
	}
	_, err = contractStore.CreateContract(contract1)
	if err != nil {
		t.Fatalf("Failed to create contract for client 1: %v", err)
	}

	contract2 := domain.Contract{
		Model:       "Contract Client 2",
		ProductKey:  "KEY-SAME-002",
		StartDate:   time.Now(),
		EndDate:     time.Now().AddDate(1, 0, 0),
		LineID:      lineID,
		ClientID:    client2ID,
		DependentID: &entity2ID,
	}
	_, err = contractStore.CreateContract(contract2)
	if err != nil {
		t.Fatalf("Failed to create contract for client 2: %v", err)
	}

	// Test GetContractsByLineID returns contracts from both clients
	contracts, err := contractStore.GetContractsByLineID(lineID)
	if err != nil {
		t.Errorf("GetContractsByLineID failed: %v", err)
	}

	if len(contracts) != 2 {
		t.Errorf("Expected 2 contracts for line, got %d", len(contracts))
	}

	// Verify we have contracts from both clients
	client1Found := false
	client2Found := false
	for _, contract := range contracts {
		if contract.ClientID == client1ID {
			client1Found = true
		}
		if contract.ClientID == client2ID {
			client2Found = true
		}
	}

	if !client1Found {
		t.Error("Contract from client 1 not found")
	}
	if !client2Found {
		t.Error("Contract from client 2 not found")
	}
}
