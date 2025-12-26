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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func insertTestDependencies(db *sql.DB) (string, string, string, string, error) {
	uniqueID := uuid.New().String()[:8]
	entityID, err := InsertTestEntity(db, "Test Entity "+uniqueID, generateUniqueCNPJ())
	if err != nil {
		return "", "", "", "", err
	}
	// Helper para inserir entidade no banco
	subEntityID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO sub_entities (id, name, entity_id) VALUES ($1, $2, $3)",
		subEntityID,
		"Test SubEntity "+uniqueID,
		entityID,
	)
	if err != nil {
		return "", "", "", "", err
	}
	categoryID, err := InsertTestCategory(db, "Test Category "+uniqueID)
	if err != nil {
		return "", "", "", "", err
	}
	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory "+uniqueID, categoryID)
	if err != nil {
		return "", "", "", "", err
	}
	return entityID, subEntityID, categoryID, subcategoryID, nil
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

	subcategoryStore := NewSubcategoryStore(db)
	line := domain.Subcategory{
		Name:       "Linha Teste",
		CategoryID: categoryID1,
	}
	subcategoryID, err := subcategoryStore.CreateSubcategory(line)
	if err != nil {
		t.Fatalf("Failed to create line: %v", err)
	}

	// Tentar mover linha para outra categoria
	lineUpdate := domain.Subcategory{
		ID:         subcategoryID,
		Name:       "Linha Teste",
		CategoryID: categoryID2,
	}
	err = subcategoryStore.UpdateSubcategory(lineUpdate)
	if err == nil {
		t.Error("Expected error when moving line between categories, got none")
	}
}

// Teste: Não pode deletar linha com contratos associadas
func TestDeleteSubcategoryWithAgreementsAssociated(t *testing.T) {
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

	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}
	categoryID, err := InsertTestCategory(db, "Categoria Teste")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	subcategoryStore := NewSubcategoryStore(db)
	line := domain.Subcategory{
		Name:       "Linha Teste",
		CategoryID: categoryID,
	}
	subcategoryID, err := subcategoryStore.CreateSubcategory(line)
	if err != nil {
		t.Fatalf("Failed to create line: %v", err)
	}

	agreementStore := NewAgreementStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	agreement := domain.Agreement{
		Model:         "Licença Teste",
		ItemKey:       "LINE-DEL-KEY-001",
		StartDate:     timePtr(startDate),
		EndDate:       timePtr(endDate),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}
	_, err = agreementStore.CreateAgreement(agreement)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	err = subcategoryStore.DeleteSubcategory(subcategoryID)
	if err == nil {
		t.Error("Expected error when deleting line with agreements associated, got none")
	}
}

func TestCreateAgreement(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := timePtr(time.Now())
	endDate := timePtr(time.Now().AddDate(1, 0, 0))

	tests := []struct {
		name        string
		agreement   domain.Agreement
		expectError bool
	}{
		{
			name: "sucesso - criação normal com unidade",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-125",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
				SubEntityID:   &subEntityID,
			},
			expectError: false,
		},
		{
			name: "sucesso - criação sem unidade",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-124",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: false,
		},
		{
			name: "erro - nome vazio",
			agreement: domain.Agreement{
				ItemKey:       "TEST-KEY-125",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - chave do produto vazia",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - data final antes da inicial",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-126",
				StartDate:     endDate,
				EndDate:       startDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - sobreposição de datas para mesma empresa/unidade/tipo",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-OVERLAP",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
				SubEntityID:   &subEntityID,
			},
			expectError: true,
		},
		{
			name: "erro - atualização com StartDate após EndDate",
			agreement: domain.Agreement{
				Model:         "Test Agreement Update",
				ItemKey:       "TEST-KEY-UPDATE",
				StartDate:     timePtr(endDate.AddDate(2, 0, 0)),
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - tipo inválido",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-127",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: "invalid-line",
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - empresa inválida",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-128",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      "invalid-client",
			},
			expectError: true,
		},
		{
			name: "erro - empresa arquivada",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-ARCHIVED",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID, // Usar entityID válido
			},
			expectError: true,
		},
		{
			name: "erro - unidade inválida",
			agreement: domain.Agreement{
				Model:         "Test Agreement",
				ItemKey:       "TEST-KEY-129",
				StartDate:     startDate,
				EndDate:       endDate,
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
				SubEntityID:   func() *string { s := "invalid-dependent"; return &s }(),
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agreementStore := NewAgreementStore(db)
			id, err := agreementStore.CreateAgreement(tt.agreement)
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

// Função de utilitário para status de licença deve estar fora do TestCreateAgreement!
func TestAgreementStatusUtil(t *testing.T) {
	now := time.Now()
	agreementActive := domain.Agreement{
		EndDate: timePtr(now.AddDate(0, 1, 0)), // expira em 1 mês
	}
	agreementExpiring := domain.Agreement{
		EndDate: timePtr(now.AddDate(0, 0, 10)), // expira em 10 dias
	}
	agreementExpired := domain.Agreement{
		EndDate: timePtr(now.AddDate(0, 0, -1)), // já expirou
	}

	statusActive := GetAgreementStatus(agreementActive)
	statusExpiring := GetAgreementStatus(agreementExpiring)
	statusExpired := GetAgreementStatus(agreementExpired)

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

func TestUpdateAgreementEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	agreementStore := NewAgreementStore(db)
	agreement := domain.Agreement{
		Model:         "Edge Agreement",
		ItemKey:       "EDGE-KEY-1",
		StartDate:     timePtr(startDate),
		EndDate:       timePtr(endDate),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
		SubEntityID:   &subEntityID,
	}
	contractID, err := agreementStore.CreateAgreement(agreement)
	if err != nil {
		t.Fatalf("Failed to create contract for update edge case: %v", err)
	}

	// Atualizar com datas invertidas
	agreement.ID = contractID
	agreement.StartDate = timePtr(endDate.AddDate(2, 0, 0))
	agreement.EndDate = timePtr(endDate)
	err = agreementStore.UpdateAgreement(agreement)
	if err == nil {
		t.Error("Expected error when updating contract with StartDate after EndDate, got none")
	}

	// Atualizar licença inexistente
	agreement.ID = uuid.New().String()
	agreement.StartDate = timePtr(startDate)
	agreement.EndDate = timePtr(endDate)
	agreementStore = NewAgreementStore(db)
	err = agreementStore.UpdateAgreement(agreement)
	if err == nil {
		t.Error("Expected error when updating non-existent contract, got none")
	}
}

func TestDeleteAgreementEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	agreementStore := NewAgreementStore(db)
	// Tentar deletar licença inexistente
	err = agreementStore.DeleteAgreement(uuid.New().String())
	if err == nil {
		t.Error("Expected error when deleting non-existent contract, got none")
	}
}

func TestDeleteEntityEdgeCases(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	entityStore := NewEntityStore(db)
	// Tentar deletar empresa inexistente
	err = entityStore.DeleteEntityPermanently(uuid.New().String())
	if err == nil {
		t.Error("Expected error when deleting non-existent client, got none")
	}
}

func TestGetAgreementByID(t *testing.T) {
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

	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contractID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO agreements (id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		contractID,
		"Test Agreement",
		"TEST-KEY-123",
		startDate,
		endDate,
		subcategoryID,
		entityID,
		subEntityID,
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
			id:          contractID,
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
			agreementStore := NewAgreementStore(db)
			contract, err := agreementStore.GetAgreementByID(tt.id)

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

func TestGetAgreementsByEntityID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	for i := 0; i < 3; i++ {
		contractID := uuid.New().String()
		_, err := db.Exec(
			"INSERT INTO agreements (id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
			contractID,
			"Test Agreement "+string(rune('A'+i)),
			"TEST-KEY-"+uuid.New().String()[:8],
			startDate,
			endDate,
			subcategoryID,
			entityID,
			subEntityID,
		)
		if err != nil {
			t.Fatalf("Failed to insert test contract: %v", err)
		}
	}

	tests := []struct {
		name        string
		entityID    string
		expectError bool
		expectCount int
	}{
		{
			name:        "sucesso - contratos encontradas",
			entityID:    entityID,
			expectError: false,
			expectCount: 3,
		},
		{
			name:        "erro - empresa vazia",
			entityID:    "",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "erro - empresa não existe",
			entityID:    "non-existent-client",
			expectError: true,
			expectCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agreementStore := NewAgreementStore(db)
			agreements, err := agreementStore.GetAgreementsByEntityID(tt.entityID)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
			if !tt.expectError && len(agreements) != tt.expectCount {
				t.Errorf("Expected %d agreements but got %d", tt.expectCount, len(agreements))
			}
		})
	}
}

func TestUpdateAgreement(t *testing.T) {
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

	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contractID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO agreements (id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		contractID,
		"Test Agreement",
		"TEST-KEY-UPDATE",
		startDate,
		endDate,
		subcategoryID,
		entityID,
		subEntityID,
	)
	if err != nil {
		t.Fatalf("Failed to insert test contract: %v", err)
	}

	tests := []struct {
		name        string
		agreement   domain.Agreement
		expectError bool
	}{
		{
			name: "sucesso - atualização normal",
			agreement: domain.Agreement{
				ID:            contractID,
				Model:         "Updated Agreement",
				ItemKey:       "TEST-KEY-123",
				StartDate:     timePtr(startDate),
				EndDate:       timePtr(endDate.AddDate(1, 0, 0)),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
				SubEntityID:   &subEntityID,
			},
			expectError: false,
		},
		{
			name: "erro - id vazio",
			agreement: domain.Agreement{
				Model:         "Updated Agreement",
				ItemKey:       "TEST-KEY-123",
				StartDate:     timePtr(startDate),
				EndDate:       timePtr(endDate),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - nome vazio",
			agreement: domain.Agreement{
				ID:            contractID,
				ItemKey:       "TEST-KEY-123",
				StartDate:     timePtr(startDate),
				EndDate:       timePtr(endDate),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
		{
			name: "erro - data final antes da inicial",
			agreement: domain.Agreement{
				ID:            contractID,
				Model:         "Updated Agreement",
				ItemKey:       "TEST-KEY-123",
				StartDate:     timePtr(endDate),
				EndDate:       timePtr(startDate),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agreementStore := NewAgreementStore(db)
			err := agreementStore.UpdateAgreement(tt.agreement)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var model string
				err = db.QueryRow("SELECT model FROM agreements WHERE id = $1", tt.agreement.ID).Scan(&model)
				if err != nil {
					t.Errorf("Failed to query updated contract: %v", err)
				}
				if model != tt.agreement.Model {
					t.Errorf("Expected model %q but got %q", tt.agreement.Model, model)
				}
			}
		})
	}
}

func TestDeleteAgreement(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer func() {
		if err := CloseDB(db); err != nil {
			t.Errorf("Failed to close test database: %v", err)
		}
	}()

	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)
	contractID := uuid.New().String()
	_, err = db.Exec(
		"INSERT INTO agreements (id, model, item_key, start_date, end_date, subcategory_id, entity_id, sub_entity_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
		contractID,
		"Test Agreement",
		"TEST-KEY-DELETE",
		startDate,
		endDate,
		subcategoryID,
		entityID,
		subEntityID,
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
			agreementStore := NewAgreementStore(db)
			err := agreementStore.DeleteAgreement(tt.id)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if !tt.expectError {
				var count int
				err = db.QueryRow("SELECT COUNT(*) FROM agreements WHERE id = $1", tt.id).Scan(&count)
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

// ============================================================================
// CRITICAL TESTS
// ============================================================================

func setupContractTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

// TestGetAgreementsExpiringSoon tests retrieving agreements expiring within a specified number of days
func TestGetAgreementsExpiringSoon(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	agreementStore := NewAgreementStore(db)

	// Insert test data
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Insert agreements with different expiration dates
	// Agreement 1: expires in 10 days (should be included in 30-day search)
	_, err = InsertTestAgreement(db, "Agreement 1", "KEY-1", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 10)), subcategoryID, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 1: %v", err)
	}

	// Agreement 2: expires in 60 days (should NOT be included in 30-day search)
	_, err = InsertTestAgreement(db, "Agreement 2", "KEY-2", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 60)), subcategoryID, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 2: %v", err)
	}

	// Agreement 3: already expired (should NOT be included)
	_, err = InsertTestAgreement(db, "Agreement 3", "KEY-3", timePtr(now.AddDate(0, 0, -30)), timePtr(now.AddDate(0, 0, -5)), subcategoryID, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 3: %v", err)
	}

	// Agreement 4: expires in 25 days (should be included in 30-day search)
	_, err = InsertTestAgreement(db, "Agreement 4", "KEY-4", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 25)), subcategoryID, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 4: %v", err)
	}

	// Get agreements expiring in 30 days
	agreements, err := agreementStore.GetAgreementsExpiringSoon(30)
	if err != nil {
		t.Fatalf("Failed to get expiring agreements: %v", err)
	}

	if len(agreements) != 2 {
		t.Errorf("Expected 2 expiring agreements, got %d", len(agreements))
	}

	// Verify correct agreements are returned
	expiredKeys := make(map[string]bool)
	for _, l := range agreements {
		expiredKeys[l.ItemKey] = true
	}

	if !expiredKeys["KEY-1"] || !expiredKeys["KEY-4"] {
		t.Error("Expected agreements KEY-1 and KEY-4 in results")
	}
}

// TestGetAgreementsBySubcategoryIDCritical tests retrieving agreements by line ID
func TestGetAgreementsBySubcategoryIDCritical(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)

	// Insert test data
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID1, err := InsertTestSubcategory(db, "Subcategory 1", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line 1: %v", err)
	}

	subcategoryID2, err := InsertTestSubcategory(db, "Subcategory 2", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line 2: %v", err)
	}

	now := time.Now()

	// Insert agreements for different subcategories
	_, err = InsertTestAgreement(db, "Agreement 1", "KEY-1", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID1, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 1: %v", err)
	}

	_, err = InsertTestAgreement(db, "Agreement 2", "KEY-2", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID1, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 2: %v", err)
	}

	_, err = InsertTestAgreement(db, "Agreement 3", "KEY-3", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID2, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 3: %v", err)
	}

	// Get agreements for subcategoryID1
	agreements, err := agreementStore.GetAgreementsBySubcategoryID(subcategoryID1)
	if err != nil {
		t.Fatalf("Failed to get agreements by line: %v", err)
	}

	if len(agreements) != 2 {
		t.Errorf("Expected 2 agreements for line 1, got %d", len(agreements))
	}

	// Verify all returned agreements belong to subcategoryID1
	for _, l := range agreements {
		if l.SubcategoryID != subcategoryID1 {
			t.Errorf("Expected line ID '%s', got '%s'", subcategoryID1, l.SubcategoryID)
		}
	}
}

// TestGetAgreementsByCategoryIDCritical tests retrieving agreements by category ID
func TestGetAgreementsByCategoryIDCritical(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)

	// Insert test data
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID1, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category 1: %v", err)
	}

	categoryID2, err := InsertTestCategory(db, "Hardware")
	if err != nil {
		t.Fatalf("Failed to insert test category 2: %v", err)
	}

	subcategoryID1, err := InsertTestSubcategory(db, "Subcategory 1", categoryID1)
	if err != nil {
		t.Fatalf("Failed to insert test line 1: %v", err)
	}

	subcategoryID2, err := InsertTestSubcategory(db, "Subcategory 2", categoryID2)
	if err != nil {
		t.Fatalf("Failed to insert test line 2: %v", err)
	}

	now := time.Now()

	// Insert agreements for different categories
	_, err = InsertTestAgreement(db, "Agreement 1", "KEY-1", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID1, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 1: %v", err)
	}

	_, err = InsertTestAgreement(db, "Agreement 2", "KEY-2", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID1, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 2: %v", err)
	}

	_, err = InsertTestAgreement(db, "Agreement 3", "KEY-3", timePtr(now.AddDate(0, 0, -10)), timePtr(now.AddDate(0, 0, 30)), subcategoryID2, entityID, nil)
	if err != nil {
		t.Fatalf("Failed to insert contract 3: %v", err)
	}

	// Get agreements for categoryID1
	agreements, err := agreementStore.GetAgreementsByCategoryID(categoryID1)
	if err != nil {
		t.Fatalf("Failed to get agreements by category: %v", err)
	}

	if len(agreements) != 2 {
		t.Errorf("Expected 2 agreements for category 1, got %d", len(agreements))
	}

	// Verify all returned agreements belong to categoryID1
	for _, l := range agreements {
		if l.SubcategoryID != subcategoryID1 {
			t.Errorf("Expected line ID '%s', got '%s'", subcategoryID1, l.SubcategoryID)
		}
	}
}

// TestCreateAgreementWithOverlap tests contract creation fails when there's a time overlap
func TestCreateAgreementWithOverlap(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)

	// Insert test data
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Create first contract
	firstContract := domain.Agreement{
		Model:         "First Agreement",
		ItemKey:       "KEY-1",
		StartDate:     timePtr(now.AddDate(0, 0, -10)),
		EndDate:       timePtr(now.AddDate(0, 0, 30)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}

	id, err := agreementStore.CreateAgreement(firstContract)
	if err != nil {
		t.Fatalf("Failed to create first contract: %v", err)
	}
	if id == "" {
		t.Error("Expected agreement ID")
	}

	// Try to create overlapping contract
	overlappingContract := domain.Agreement{
		Model:         "Overlapping Agreement",
		ItemKey:       "KEY-2",
		StartDate:     timePtr(now.AddDate(0, 0, 5)),  // Within first contract period
		EndDate:       timePtr(now.AddDate(0, 0, 20)), // Within first contract period
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}

	_, err = agreementStore.CreateAgreement(overlappingContract)
	if err == nil {
		t.Error("Expected error creating overlapping contract")
	}
}

// TestCreateAgreementNonOverlappingValid tests that non-overlapping agreements can be created
func TestCreateAgreementNonOverlappingValid(t *testing.T) {
	db := setupContractTestDB(t)
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)

	// Insert test data
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	now := time.Now()

	// Create first contract
	firstContract := domain.Agreement{
		Model:         "First Agreement",
		ItemKey:       "KEY-1",
		StartDate:     timePtr(now.AddDate(0, 0, -30)),
		EndDate:       timePtr(now.AddDate(0, 0, -5)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}

	id, err := agreementStore.CreateAgreement(firstContract)
	if err != nil {
		t.Fatalf("Failed to create first contract: %v", err)
	}
	if id == "" {
		t.Error("Expected agreement ID")
	}

	// Create non-overlapping contract (starts after first ends)
	secondContract := domain.Agreement{
		Model:         "Second Agreement",
		ItemKey:       "KEY-2",
		StartDate:     timePtr(now.AddDate(0, 0, -4)),
		EndDate:       timePtr(now.AddDate(0, 0, 30)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}

	id2, err := agreementStore.CreateAgreement(secondContract)
	if err != nil {
		t.Fatalf("Failed to create second contract: %v", err)
	}
	if id2 == "" {
		t.Error("Expected agreement ID for second contract")
	}
}

// ============================================================================
// VALIDATION & EDGE CASES
// ============================================================================

// TestCreateAgreementWithInvalidNames tests various invalid contract model names
func TestCreateAgreementWithInvalidNames(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)
	startDate := time.Now()
	var entityID, categoryID, subcategoryID string

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
			description: "Agreement model with 256 characters should be rejected",
		},
		{
			name:        "invalid - model name way too long (1000 chars)",
			model:       veryLongName,
			expectError: true,
			description: "Agreement model with 1000 characters should be rejected",
		},
		{
			name:        "invalid - model name with only spaces",
			model:       "     ",
			expectError: true,
			description: "Agreement model with only whitespace should be rejected",
		},
		{
			name:        "valid - model name at max length (255 chars)",
			model:       strings.Repeat("a", 255),
			expectError: false,
			description: "Agreement model with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - model name with special characters",
			model:       "License Pro - Enterprise Edition (2025)",
			expectError: false,
			description: "Agreement model with special characters should be allowed",
		},
		{
			name:        "valid - model name with accents",
			model:       "Licença Profissional",
			expectError: false,
			description: "Agreement model with Portuguese accents should be allowed",
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
			entityID, errInsert = InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
			if errInsert != nil {
				t.Fatalf("Failed to insert test client: %v", errInsert)
			}

			categoryID, errInsert = InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
			if errInsert != nil {
				t.Fatalf("Failed to insert test category: %v", errInsert)
			}

			subcategoryID, errInsert = InsertTestSubcategory(db, "Test Subcategory", categoryID)
			if errInsert != nil {
				t.Fatalf("Failed to insert test line: %v", errInsert)
			}

			// Use different time periods for each agreement to avoid overlap detection
			agreementStart := startDate.AddDate(0, 0, idx*30)
			agreementEnd := agreementStart.AddDate(1, 0, 0)

			agreement := domain.Agreement{
				Model:         tt.model,
				ItemKey:       "TEST-KEY-" + string(rune('A'+idx)),
				StartDate:     timePtr(agreementStart),
				EndDate:       timePtr(agreementEnd),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			}

			_, errCreate := agreementStore.CreateAgreement(agreement)

			if tt.expectError && errCreate == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && errCreate != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, errCreate)
			}
		})
	}
}

// TestCreateAgreementWithInvalidItemKeys tests various invalid product key formats
func TestCreateAgreementWithInvalidItemKeys(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)
	startDate := time.Now()
	var entityID, categoryID, subcategoryID string

	longKey := strings.Repeat("A", 256)
	veryLongKey := strings.Repeat("A", 1000)

	tests := []struct {
		name        string
		itemKey     string
		expectError bool
		description string
	}{
		{
			name:        "invalid - product key too long (256 chars)",
			itemKey:     longKey,
			expectError: true,
			description: "Product key with 256 characters should be rejected",
		},
		{
			name:        "invalid - product key way too long (1000 chars)",
			itemKey:     veryLongKey,
			expectError: true,
			description: "Product key with 1000 characters should be rejected",
		},
		{
			name:        "invalid - product key with only spaces",
			itemKey:     "     ",
			expectError: true,
			description: "Product key with only whitespace should be rejected",
		},
		{
			name:        "valid - product key at max length (255 chars)",
			itemKey:     strings.Repeat("K", 255),
			expectError: false,
			description: "Product key with exactly 255 characters should be allowed",
		},
		{
			name:        "valid - product key with special characters",
			itemKey:     "ABCD-1234-EFGH-5678",
			expectError: false,
			description: "Product key with dashes should be allowed",
		},
		{
			name:        "valid - product key with mixed case",
			itemKey:     "AbCd-1234-EfGh-5678",
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
			entityID, errInsert = InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
			if errInsert != nil {
				t.Fatalf("Failed to insert test client: %v", errInsert)
			}

			categoryID, errInsert = InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
			if errInsert != nil {
				t.Fatalf("Failed to insert test category: %v", errInsert)
			}

			subcategoryID, errInsert = InsertTestSubcategory(db, "Test Subcategory", categoryID)
			if errInsert != nil {
				t.Fatalf("Failed to insert test line: %v", errInsert)
			}

			// Use different time periods for each agreement to avoid overlap detection
			agreementStart := startDate.AddDate(0, 0, idx*30)
			agreementEnd := agreementStart.AddDate(1, 0, 0)

			agreement := domain.Agreement{
				Model:         "Test Model " + string(rune('A'+idx)),
				ItemKey:       tt.itemKey,
				StartDate:     timePtr(agreementStart),
				EndDate:       timePtr(agreementEnd),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			}

			_, errCreate := agreementStore.CreateAgreement(agreement)

			if tt.expectError && errCreate == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && errCreate != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, errCreate)
			}
		})
	}
}

// TestCreateAgreementWithDuplicateItemKey tests duplicate product key detection
func TestCreateAgreementWithDuplicateItemKey(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)
	startDate := time.Now()

	tests := []struct {
		name        string
		agreement   domain.Agreement
		expectError bool
		description string
	}{
		{
			name: "duplicate - same product key for same client/dependent",
			agreement: domain.Agreement{
				Model:     "Duplicate Agreement",
				ItemKey:   "DUPLICATE-KEY-TEST",
				StartDate: timePtr(startDate),
				EndDate:   timePtr(startDate.AddDate(1, 0, 0)),
			},
			expectError: true,
			description: "Same product key for same client/dependent should be rejected",
		},
		{
			name: "valid - same product key for different client",
			agreement: domain.Agreement{
				Model:     "Different Entity Agreement",
				ItemKey:   "DUPLICATE-KEY-TEST",
				StartDate: timePtr(startDate.AddDate(0, 0, 60)),
				EndDate:   timePtr(startDate.AddDate(1, 0, 60)),
			},
			expectError: false,
			description: "Same product key for different client should be allowed",
		},
		{
			name: "valid - same product key for same client but different dependent",
			agreement: domain.Agreement{
				Model:     "Different SubEntity Agreement",
				ItemKey:   "DUPLICATE-KEY-TEST",
				StartDate: timePtr(startDate.AddDate(0, 0, 120)),
				EndDate:   timePtr(startDate.AddDate(1, 0, 120)),
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
			client1ID, errSetup := InsertTestEntity(db, "Entity 1", generateUniqueCNPJ())
			if errSetup != nil {
				t.Fatalf("Failed to insert client 1: %v", errSetup)
			}

			client2ID, errSetup := InsertTestEntity(db, "Entity 2", "11.222.333/0001-81")
			if errSetup != nil {
				t.Fatalf("Failed to insert client 2: %v", errSetup)
			}

			categoryID, errSetup := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
			if errSetup != nil {
				t.Fatalf("Failed to insert test category: %v", errSetup)
			}

			subcategoryID, errSetup := InsertTestSubcategory(db, "Test Subcategory", categoryID)
			if errSetup != nil {
				t.Fatalf("Failed to insert test line: %v", errSetup)
			}

			// Create dependent for client 1
			dependent1ID := uuid.New().String()
			_, errSetup = db.Exec("INSERT INTO sub_entities (id, name, entity_id) VALUES ($1, $2, $3)",
				dependent1ID, "SubEntity 1", client1ID)
			if errSetup != nil {
				t.Fatalf("Failed to insert dependent 1: %v", errSetup)
			}

			// Create dependent for client 2
			dependent2ID := uuid.New().String()
			_, errSetup = db.Exec("INSERT INTO sub_entities (id, name, entity_id) VALUES ($1, $2, $3)",
				dependent2ID, "SubEntity 2", client2ID)
			if errSetup != nil {
				t.Fatalf("Failed to insert dependent 2: %v", errSetup)
			}

			// For test 0 (duplicate), create first contract and set up the contract to test
			if idx == 0 {
				_, errSetup = agreementStore.CreateAgreement(domain.Agreement{
					Model:         "First Agreement",
					ItemKey:       "DUPLICATE-KEY-TEST",
					StartDate:     tt.agreement.StartDate,
					EndDate:       tt.agreement.EndDate,
					SubcategoryID: subcategoryID,
					EntityID:      client1ID,
					SubEntityID:   &dependent1ID,
				})
				if errSetup != nil {
					t.Fatalf("Failed to create first contract: %v", errSetup)
				}
			}

			// For test 1 (different client), use client2
			agreement := tt.agreement
			if idx == 1 {
				agreement.SubcategoryID = subcategoryID
				agreement.EntityID = client2ID
			} else {
				// For tests 0 and 2, use client1
				agreement.SubcategoryID = subcategoryID
				agreement.EntityID = client1ID
				if idx == 2 {
					// Test 2 uses a dependent from client2 with client1 (should fail)
					agreement.SubEntityID = &dependent2ID
				} else {
					// Test 0 uses dependent1
					agreement.SubEntityID = &dependent1ID
				}
			}

			_, err := agreementStore.CreateAgreement(agreement)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateAgreementWithInvalidDates tests various date validation scenarios
func TestCreateAgreementWithInvalidDates(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	agreementStore := NewAgreementStore(db)
	now := time.Now()
	var entityID, categoryID, subcategoryID string

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
			description: "Agreement with start date in the past is allowed",
		},
		{
			name:        "valid - very short contract (1 day)",
			startDate:   now,
			endDate:     now.AddDate(0, 0, 1),
			expectError: false,
			description: "Agreement with 1 day duration should be allowed",
		},
		{
			name:        "valid - very long contract (10 years)",
			startDate:   now,
			endDate:     now.AddDate(10, 0, 0),
			expectError: false,
			description: "Agreement with 10 years duration should be allowed",
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
			entityID, errInsert = InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
			if errInsert != nil {
				t.Fatalf("Failed to insert test client: %v", errInsert)
			}

			categoryID, errInsert = InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
			if errInsert != nil {
				t.Fatalf("Failed to insert test category: %v", errInsert)
			}

			subcategoryID, errInsert = InsertTestSubcategory(db, "Test Subcategory", categoryID)
			if errInsert != nil {
				t.Fatalf("Failed to insert test line: %v", errInsert)
			}

			// Use different time periods for each agreement to avoid overlap detection
			agreementStart := tt.startDate.AddDate(0, 0, idx*60)
			agreementEnd := tt.endDate.AddDate(0, 0, idx*60)

			agreement := domain.Agreement{
				Model:         "Test Agreement " + string(rune('A'+idx)),
				ItemKey:       "KEY-" + string(rune('A'+idx)) + "-TEST",
				StartDate:     timePtr(agreementStart),
				EndDate:       timePtr(agreementEnd),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			}

			_, err := agreementStore.CreateAgreement(agreement)

			if tt.expectError && err == nil {
				t.Errorf("Expected error for %s, but got none", tt.description)
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error for %s, but got: %v", tt.description, err)
			}
		})
	}
}

// TestCreateAgreementWithArchivedClient tests that agreements cannot be created for archived entities
func TestCreateAgreementWithArchivedClient(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Setup dependencies
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Archive the client
	_, err = db.Exec("UPDATE entities SET archived_at = $1 WHERE id = $2", time.Now(), entityID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	agreementStore := NewAgreementStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	agreement := domain.Agreement{
		Model:         "Test Agreement",
		ItemKey:       "ARCHIVED-CLIENT-KEY",
		StartDate:     timePtr(startDate),
		EndDate:       timePtr(endDate),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}

	_, err = agreementStore.CreateAgreement(agreement)
	if err == nil {
		t.Error("Expected error when creating contract for archived client, but got none")
	}
}

// TestUpdateAgreementWithInvalidData tests update operations with invalid data
func TestUpdateAgreementWithInvalidData(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	defer CloseDB(db)

	// Setup dependencies
	entityID, err := InsertTestEntity(db, "Test Entity", generateUniqueCNPJ())
	if err != nil {
		t.Fatalf("Failed to insert test client: %v", err)
	}

	categoryID, err := InsertTestCategory(db, "Software-"+uuid.New().String()[:8])
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}

	subcategoryID, err := InsertTestSubcategory(db, "Test Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	agreementStore := NewAgreementStore(db)
	startDate := time.Now()
	endDate := startDate.AddDate(1, 0, 0)

	// Create initial contract
	contractID, err := agreementStore.CreateAgreement(domain.Agreement{
		Model:         "Original Agreement",
		ItemKey:       "ORIGINAL-KEY",
		StartDate:     timePtr(startDate),
		EndDate:       timePtr(endDate),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	})
	if err != nil {
		t.Fatalf("Failed to create initial contract: %v", err)
	}

	tests := []struct {
		name        string
		agreement   domain.Agreement
		expectError bool
		description string
	}{
		{
			name: "invalid - update with name too long",
			agreement: domain.Agreement{
				ID:            contractID,
				Model:         strings.Repeat("a", 256),
				ItemKey:       "ORIGINAL-KEY",
				StartDate:     timePtr(startDate),
				EndDate:       timePtr(endDate),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
			description: "Update with name too long should fail",
		},
		{
			name: "invalid - update with empty product key",
			agreement: domain.Agreement{
				ID:            contractID,
				Model:         "Updated Agreement",
				ItemKey:       "",
				StartDate:     timePtr(startDate),
				EndDate:       timePtr(endDate),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
			description: "Update with empty product key should fail",
		},
		{
			name: "invalid - update with end date before start date",
			agreement: domain.Agreement{
				ID:            contractID,
				Model:         "Updated Agreement",
				ItemKey:       "ORIGINAL-KEY",
				StartDate:     timePtr(endDate),
				EndDate:       timePtr(startDate),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: true,
			description: "Update with invalid dates should fail",
		},
		{
			name: "valid - update with valid data",
			agreement: domain.Agreement{
				ID:            contractID,
				Model:         "Updated Agreement Name",
				ItemKey:       "ORIGINAL-KEY",
				StartDate:     timePtr(startDate),
				EndDate:       timePtr(endDate.AddDate(0, 1, 0)),
				SubcategoryID: subcategoryID,
				EntityID:      entityID,
			},
			expectError: false,
			description: "Update with valid data should succeed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := agreementStore.UpdateAgreement(tt.agreement)

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

// TestGetAllAgreements tests the GetAllAgreements method
func TestGetAllAgreements(t *testing.T) {
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

	agreementStore := NewAgreementStore(db)

	// Setup dependencies
	entityID, subEntityID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	tests := []struct {
		name            string
		agreementsToAdd int
		expectedCount   int
	}{
		{
			name:            "empty database",
			agreementsToAdd: 0,
			expectedCount:   0,
		},
		{
			name:            "single contract",
			agreementsToAdd: 1,
			expectedCount:   1,
		},
		{
			name:            "multiple agreements",
			agreementsToAdd: 5,
			expectedCount:   5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear agreements for each test
			if _, err := db.Exec("DELETE FROM agreements"); err != nil {
				t.Fatalf("Failed to clear agreements: %v", err)
			}

			// Add agreements
			for i := 0; i < tt.agreementsToAdd; i++ {
				agreement := domain.Agreement{
					Model:         "Test Agreement",
					ItemKey:       "KEY-" + string(rune(48+i)),
					StartDate:     timePtr(time.Now().AddDate(0, 0, i*30)),
					EndDate:       timePtr(time.Now().AddDate(0, 0, (i+1)*30)),
					SubcategoryID: subcategoryID,
					EntityID:      entityID,
					SubEntityID:   &subEntityID,
				}
				_, err := agreementStore.CreateAgreement(agreement)
				if err != nil {
					t.Fatalf("Failed to create contract: %v", err)
				}
			}

			// Test GetAllAgreements
			agreements, err := agreementStore.GetAllAgreements()
			if err != nil {
				t.Errorf("GetAllAgreements failed: %v", err)
			}

			if len(agreements) != tt.expectedCount {
				t.Errorf("Expected %d agreements, got %d", tt.expectedCount, len(agreements))
			}

			// Verify all agreements have required fields
			for _, agreement := range agreements {
				if agreement.ID == "" {
					t.Error("Agreement ID is empty")
				}
				if agreement.Model == "" {
					t.Error("Agreement Model is empty")
				}
				if agreement.ItemKey == "" {
					t.Error("Agreement ItemKey is empty")
				}
			}
		})
	}
}

// TestGetAgreementsBySubcategoryID tests filtering agreements by line ID
func TestGetAgreementsBySubcategoryID(t *testing.T) {
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

	agreementStore := NewAgreementStore(db)

	// Setup dependencies
	entityID, subEntityID, categoryID, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	// Create a second line in the same category
	subcategoryID2, err := InsertTestSubcategory(db, "Test Subcategory 2", categoryID)
	if err != nil {
		t.Fatalf("Failed to create second line: %v", err)
	}

	// Create agreements for both subcategories
	contract1 := domain.Agreement{
		Model:         "Agreement Subcategory 1",
		ItemKey:       "KEY-LINE1-001",
		StartDate:     timePtr(time.Now()),
		EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
		SubEntityID:   &subEntityID,
	}
	_, err = agreementStore.CreateAgreement(contract1)
	if err != nil {
		t.Fatalf("Failed to create contract 1: %v", err)
	}

	contract2 := domain.Agreement{
		Model:         "Agreement Subcategory 2",
		ItemKey:       "KEY-LINE2-001",
		StartDate:     timePtr(time.Now()),
		EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID2,
		EntityID:      entityID,
		SubEntityID:   &subEntityID,
	}
	_, err = agreementStore.CreateAgreement(contract2)
	if err != nil {
		t.Fatalf("Failed to create contract 2: %v", err)
	}

	tests := []struct {
		name               string
		querySubcategoryID string
		expectedCount      int
		shouldError        bool
	}{
		{
			name:               "valid line with agreements",
			querySubcategoryID: subcategoryID,
			expectedCount:      1,
			shouldError:        false,
		},
		{
			name:               "valid line with different agreements",
			querySubcategoryID: subcategoryID2,
			expectedCount:      1,
			shouldError:        false,
		},
		{
			name:               "empty line ID",
			querySubcategoryID: "",
			expectedCount:      0,
			shouldError:        true,
		},
		{
			name:               "non-existent line ID",
			querySubcategoryID: uuid.New().String(),
			expectedCount:      0,
			shouldError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			agreements, err := agreementStore.GetAgreementsBySubcategoryID(tt.querySubcategoryID)

			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error: %v, got: %v", tt.shouldError, err)
			}

			if len(agreements) != tt.expectedCount {
				t.Errorf("Expected %d agreements, got %d", tt.expectedCount, len(agreements))
			}

			// Verify agreements belong to the queried line
			for _, agreement := range agreements {
				if agreement.SubcategoryID != tt.querySubcategoryID {
					t.Errorf("Agreement SubcategoryID %s doesn't match query SubcategoryID %s", agreement.SubcategoryID, tt.querySubcategoryID)
				}
			}
		})
	}
}

// TestGetAgreementsByCategoryID tests filtering agreements by category ID
func TestGetAgreementsByCategoryID(t *testing.T) {
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

	agreementStore := NewAgreementStore(db)

	// Setup dependencies
	entityID, subEntityID, categoryID, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert test dependencies: %v", err)
	}

	// Create a second category with its own line
	categoryID2, err := InsertTestCategory(db, "Test Category 2")
	if err != nil {
		t.Fatalf("Failed to create second category: %v", err)
	}

	subcategoryID2, err := InsertTestSubcategory(db, "Test Subcategory in Category 2", categoryID2)
	if err != nil {
		t.Fatalf("Failed to create line in second category: %v", err)
	}

	// Create agreements in both categories
	contract1 := domain.Agreement{
		Model:         "Agreement Category 1",
		ItemKey:       "KEY-CAT1-001",
		StartDate:     timePtr(time.Now()),
		EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
		SubEntityID:   &subEntityID,
	}
	_, err = agreementStore.CreateAgreement(contract1)
	if err != nil {
		t.Fatalf("Failed to create contract in category 1: %v", err)
	}

	contract2 := domain.Agreement{
		Model:         "Agreement Category 2",
		ItemKey:       "KEY-CAT2-001",
		StartDate:     timePtr(time.Now()),
		EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID2,
		EntityID:      entityID,
		SubEntityID:   &subEntityID,
	}
	_, err = agreementStore.CreateAgreement(contract2)
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
			name:            "valid category with agreements",
			queryCategoryID: categoryID,
			expectedCount:   1,
			shouldError:     false,
		},
		{
			name:            "valid category with different agreements",
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
			agreements, err := agreementStore.GetAgreementsByCategoryID(tt.queryCategoryID)

			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error: %v, got: %v", tt.shouldError, err)
			}

			if len(agreements) != tt.expectedCount {
				t.Errorf("Expected %d agreements, got %d", tt.expectedCount, len(agreements))
			}

			// Verify agreements belong to subcategories in the queried category
			for _, agreement := range agreements {
				var lineCategory string
				err := db.QueryRow("SELECT category_id FROM subcategories WHERE id = $1", agreement.SubcategoryID).Scan(&lineCategory)
				if err != nil {
					t.Errorf("Failed to verify contract's line category: %v", err)
				}
				if lineCategory != tt.queryCategoryID {
					t.Errorf("Agreement's line category %s doesn't match query category %s", lineCategory, tt.queryCategoryID)
				}
			}
		})
	}
}

// TestGetAllAgreementsWithMultipleClients tests GetAllAgreements with agreements from different entities
func TestGetAllAgreementsWithMultipleClients(t *testing.T) {
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

	agreementStore := NewAgreementStore(db)

	// Create two entities with their dependencies
	client1ID, entity1ID, _, line1ID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies for client 1: %v", err)
	}

	client2ID, err := InsertTestEntity(db, "Test Entity 2", "12.345.678/0001-99")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	entity2ID, err := InsertTestSubEntity(db, "SubEntity 2", client2ID)
	if err != nil {
		t.Fatalf("Failed to create dependent 2: %v", err)
	}
	category2ID, err := InsertTestCategory(db, "Category 2")
	if err != nil {
		t.Fatalf("Failed to create category 2: %v", err)
	}
	line2ID, err := InsertTestSubcategory(db, "Subcategory 2", category2ID)
	if err != nil {
		t.Fatalf("Failed to create line 2: %v", err)
	}

	// Create agreements for both entities
	for i := 0; i < 3; i++ {
		agreement := domain.Agreement{
			Model:         "Agreement Entity 1",
			ItemKey:       "KEY-C1-" + string(rune(48+i)),
			StartDate:     timePtr(time.Now().AddDate(0, 0, i*30)),
			EndDate:       timePtr(time.Now().AddDate(0, 0, (i+1)*30)),
			SubcategoryID: line1ID,
			EntityID:      client1ID,
			SubEntityID:   &entity1ID,
		}
		_, err := agreementStore.CreateAgreement(agreement)
		if err != nil {
			t.Fatalf("Failed to create contract for client 1: %v", err)
		}
	}

	for i := 0; i < 2; i++ {
		agreement := domain.Agreement{
			Model:         "Agreement Entity 2",
			ItemKey:       "KEY-C2-" + string(rune(48+i)),
			StartDate:     timePtr(time.Now().AddDate(0, 1, i*30)),
			EndDate:       timePtr(time.Now().AddDate(0, 1, (i+1)*30)),
			SubcategoryID: line2ID,
			EntityID:      client2ID,
			SubEntityID:   &entity2ID,
		}
		_, err := agreementStore.CreateAgreement(agreement)
		if err != nil {
			t.Fatalf("Failed to create contract for client 2: %v", err)
		}
	}

	// Test GetAllAgreements returns all agreements
	agreements, err := agreementStore.GetAllAgreements()
	if err != nil {
		t.Errorf("GetAllAgreements failed: %v", err)
	}

	expectedTotal := 5
	if len(agreements) != expectedTotal {
		t.Errorf("Expected %d total agreements, got %d", expectedTotal, len(agreements))
	}

	// Verify we have agreements from both entities
	client1Count := 0
	client2Count := 0
	for _, agreement := range agreements {
		if agreement.EntityID == client1ID {
			client1Count++
		} else if agreement.EntityID == client2ID {
			client2Count++
		}
	}

	if client1Count != 3 {
		t.Errorf("Expected 3 agreements for client 1, got %d", client1Count)
	}
	if client2Count != 2 {
		t.Errorf("Expected 2 agreements for client 2, got %d", client2Count)
	}
}

// TestGetAgreementsBySubcategoryIDWithMultipleClients tests that GetAgreementsBySubcategoryID returns agreements from all entities
func TestGetAgreementsBySubcategoryIDWithMultipleClients(t *testing.T) {
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

	agreementStore := NewAgreementStore(db)

	// Create two entities
	client1ID, entity1ID, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies for client 1: %v", err)
	}

	client2ID, err := InsertTestEntity(db, "Test Entity 2", "98.765.432/0001-11")
	if err != nil {
		t.Fatalf("Failed to create second client: %v", err)
	}
	entity2ID, err := InsertTestSubEntity(db, "SubEntity 2", client2ID)
	if err != nil {
		t.Fatalf("Failed to create dependent 2: %v", err)
	}

	// Create agreements for the same line but different entities
	contract1 := domain.Agreement{
		Model:         "Agreement Entity 1",
		ItemKey:       "KEY-SAME-001",
		StartDate:     timePtr(time.Now()),
		EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      client1ID,
		SubEntityID:   &entity1ID,
	}
	_, err = agreementStore.CreateAgreement(contract1)
	if err != nil {
		t.Fatalf("Failed to create contract for client 1: %v", err)
	}

	contract2 := domain.Agreement{
		Model:         "Agreement Entity 2",
		ItemKey:       "KEY-SAME-002",
		StartDate:     timePtr(time.Now()),
		EndDate:       timePtr(time.Now().AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      client2ID,
		SubEntityID:   &entity2ID,
	}
	_, err = agreementStore.CreateAgreement(contract2)
	if err != nil {
		t.Fatalf("Failed to create contract for client 2: %v", err)
	}

	// Test GetAgreementsBySubcategoryID returns agreements from both entities
	agreements, err := agreementStore.GetAgreementsBySubcategoryID(subcategoryID)
	if err != nil {
		t.Errorf("GetAgreementsBySubcategoryID failed: %v", err)
	}

	if len(agreements) != 2 {
		t.Errorf("Expected 2 agreements for line, got %d", len(agreements))
	}

	// Verify we have agreements from both entities
	client1Found := false
	client2Found := false
	for _, agreement := range agreements {
		if agreement.EntityID == client1ID {
			client1Found = true
		}
		if agreement.EntityID == client2ID {
			client2Found = true
		}
	}

	if !client1Found {
		t.Error("Agreement from client 1 not found")
	}
	if !client2Found {
		t.Error("Agreement from client 2 not found")
	}
}

func TestGetAgreementsNotStarted(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	entityID, _, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies: %v", err)
	}

	agreementStore := NewAgreementStore(db)

	// Create future agreement
	futureStart := timePtr(time.Now().AddDate(0, 1, 0))
	agreement := domain.Agreement{
		Model:         "Future Agreement",
		ItemKey:       "FUTURE-1",
		StartDate:     futureStart,
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}
	_, err = agreementStore.CreateAgreement(agreement)
	if err != nil {
		t.Fatalf("Failed to create agreement: %v", err)
	}

	// Create started agreement
	storeAgreement := domain.Agreement{
		Model:         "Started Agreement",
		ItemKey:       "STARTED-1",
		StartDate:     timePtr(time.Now().AddDate(0, -1, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}
	_, err = agreementStore.CreateAgreement(storeAgreement)
	if err != nil {
		t.Fatalf("Failed to create agreement 2: %v", err)
	}

	agreements, err := agreementStore.GetAgreementsNotStarted()
	if err != nil {
		t.Fatalf("Failed to get agreements not started: %v", err)
	}
	if len(agreements) != 1 {
		t.Errorf("Expected 1 agreement not started, got %d", len(agreements))
	}
}

func TestGetAgreementStatsByEntityID(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	entityID, _, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies: %v", err)
	}
	agreementStore := NewAgreementStore(db)

	// Active
	_, err = agreementStore.CreateAgreement(domain.Agreement{
		Model:         "Active",
		ItemKey:       "ACTIVE-1",
		StartDate:     timePtr(time.Now().AddDate(0, -1, 0)),
		EndDate:       timePtr(time.Now().AddDate(0, 1, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	})
	if err != nil {
		t.Fatalf("Failed to create active agreement: %v", err)
	}

	// Expired
	_, err = agreementStore.CreateAgreement(domain.Agreement{
		Model:         "Expired",
		ItemKey:       "EXPIRED-1",
		StartDate:     timePtr(time.Now().AddDate(0, -3, 0)),
		EndDate:       timePtr(time.Now().AddDate(0, -2, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	})
	if err != nil {
		t.Fatalf("Failed to create expired agreement: %v", err)
	}

	stats, err := agreementStore.GetAgreementStatsByEntityID(entityID)
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}
	if stats.ActiveAgreements != 1 {
		t.Errorf("Expected 1 active agreement, got %d", stats.ActiveAgreements)
	}
	if stats.ExpiredAgreements != 1 {
		t.Errorf("Expected 1 expired agreement, got %d", stats.ExpiredAgreements)
	}
}

func TestGetAgreementStatsForAllEntities(t *testing.T) {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test DB: %v", err)
	}
	defer CloseDB(db)

	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	entityID, _, _, subcategoryID, err := insertTestDependencies(db)
	if err != nil {
		t.Fatalf("Failed to insert dependencies: %v", err)
	}
	agreementStore := NewAgreementStore(db)

	// Active
	agreementStore.CreateAgreement(domain.Agreement{
		Model:         "Active Global",
		ItemKey:       "ACTIVE-GLOBAL-1",
		StartDate:     timePtr(time.Now().AddDate(0, -1, 0)),
		EndDate:       timePtr(time.Now().AddDate(0, 1, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	})

	statsList, err := agreementStore.GetAgreementStatsForAllEntities()
	if err != nil {
		t.Fatalf("Failed to get global stats: %v", err)
	}
	if len(statsList) == 0 {
		t.Error("Expected stats, got empty list")
	}

	found := false
	for _, s := range statsList {
		if s.EntityID == entityID {
			found = true
			if s.ActiveAgreements != 1 {
				t.Errorf("Expected 1 active agreement in global stats, got %d", s.ActiveAgreements)
			}
		}
	}
	if !found {
		t.Error("Entity stats not found in global list")
	}
}
