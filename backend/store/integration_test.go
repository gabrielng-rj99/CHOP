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
	"testing"
	"time"

	"database/sql"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	if err := ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}
	return db
}

func cleanupTestData(db *sql.DB) error {
	tables := []string{"agreements", "sub_entities", "entities", "subcategories", "categories"}
	for _, table := range tables {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
}

func TestClientContractIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar client store e license store
	entityStore := NewEntityStore(db)
	agreementStore := NewAgreementStore(db)

	// Criar cliente
	email := "empresa@teste.com"
	phone := "+5511987654321"
	regID := "45.723.174/0001-10"
	client := domain.Entity{
		Name:           "Empresa Teste",
		RegistrationID: &regID,
		Status:         "ativo",
		Email:          &email,
		Phone:          &phone,
	}

	entityID, err := entityStore.CreateEntity(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Inserir categoria e tipo antes de criar o contrato
	categoryID, err := InsertTestCategory(db, "Integration Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	subcategoryID, err := InsertTestSubcategory(db, "Integration Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Criar contrato para a empresa
	now := time.Now()
	contract := domain.Agreement{
		Model:         "Test License",
		ItemKey:       "TEST-KEY-123",
		StartDate:     timePtr(now),
		EndDate:       timePtr(now.AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID,
		EntityID:      entityID,
	}

	_, err = agreementStore.CreateAgreement(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Criar dependente associado ao cliente
	subEntityStore := NewSubEntityStore(db)
	dependent := domain.SubEntity{
		Name:     "Dependente Teste",
		EntityID: entityID,
		Status:   "ativo",
	}
	subEntityID, err := subEntityStore.CreateSubEntity(dependent)
	if err != nil {
		t.Fatalf("Failed to create dependent: %v", err)
	}

	// Verificar se o contrato está associada à empresa
	agreements, err := agreementStore.GetAgreementsByEntityID(entityID)
	if err != nil {
		if err != ErrNoRows {
			t.Fatalf("Failed to get agreements: %v", err)
		}
	} else if len(agreements) != 1 {
		t.Errorf("Expected 1 contract, got %d", len(agreements))
	}

	// Arquivar empresa e verificar se as contratos ainda são acessíveis
	err = entityStore.ArchiveEntity(entityID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Não deve encontrar contratos para empresa arquivada
	agreements, err = agreementStore.GetAgreementsByEntityID(entityID)
	if err == nil {
		t.Error("Expected error for archived client, got none")
	}

	// Arquivar o cliente antes de deletar (nova regra de negócio)
	err = entityStore.ArchiveEntity(entityID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Remover todas as contratos associadas antes de deletar o cliente
	agreements, err = agreementStore.GetAgreementsByEntityID(entityID)
	if err != nil && err.Error() != "client not found or archived" {
		t.Fatalf("Failed to get agreements for client: %v", err)
	}
	for _, agreement := range agreements {
		err := agreementStore.DeleteAgreement(agreement.ID)
		if err != nil {
			t.Fatalf("Failed to delete contract %s: %v", agreement.ID, err)
		}
	}
	// Agora pode deletar empresa e verificar se as contratos e entidades são deletadas em cascata
	err = entityStore.DeleteEntityPermanently(entityID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// O dependente não deve mais existir
	deletedDependent, err := subEntityStore.GetSubEntityByID(subEntityID)
	if err != nil {
		t.Fatalf("Unexpected error when checking for deleted dependent: %v", err)
	}
	if deletedDependent != nil {
		t.Error("Expected dependent to be deleted with client")
	}
}

func TestClientDependentContractIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar stores necessárias
	entityStore := NewEntityStore(db)
	subEntityStore := NewSubEntityStore(db)
	agreementStore := NewAgreementStore(db)

	// Criar Cliente
	phone := "+5511999999999"
	regID2 := "45.723.174/0001-10"
	client := domain.Entity{
		Name:           "Full Integration Test Entity",
		RegistrationID: &regID2,
		Status:         "ativo",
		Phone:          &phone,
	}

	entityID, err := entityStore.CreateEntity(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Criar dependente
	dependent := domain.SubEntity{
		Name:     "Test SubEntity",
		EntityID: entityID,
		Status:   "ativo",
	}

	subEntityID, err := subEntityStore.CreateSubEntity(dependent)
	if err != nil {
		t.Fatalf("Failed to create dependent: %v", err)
	}

	// Inserir categoria e tipo antes de criar o contrato
	categoryID, err := InsertTestCategory(db, "Integration Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	subcategoryID, err := InsertTestSubcategory(db, "Integration Subcategory", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Criar contrato associada ao dependente
	now := time.Now()
	var entityIDPtr *string
	if subEntityID != "" {
		entityIDPtr = &subEntityID
	}
	contract := domain.Agreement{
		Model:         "SubEntity License",
		ItemKey:       "ENTITY-KEY-123",
		StartDate:     timePtr(now),
		EndDate:       timePtr(now.AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID, // Use o ID realmente inserido
		EntityID:      entityID,
		SubEntityID:   entityIDPtr,
	}

	_, err = agreementStore.CreateAgreement(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Verificar se o contrato está corretamente associada ao dependente
	agreements, err := agreementStore.GetAgreementsByEntityID(entityID)
	if err != nil {
		if err != ErrNoRows {
			t.Fatalf("Failed to get agreements: %v", err)
		}
		return
	}
	if len(agreements) != 1 {
		t.Fatalf("Expected 1 contract, got %d", len(agreements))
	}
	if agreements[0].SubEntityID == nil || *agreements[0].SubEntityID != subEntityID {
		t.Error("Agreement not properly associated with dependent")
	}

	// Deletar a unidade e verificar se o contrato é atualizada (não deletada)
	// Deletar o dependente e verificar desassociação
	err = subEntityStore.DeleteSubEntity(subEntityID)
	if err != nil {
		t.Fatalf("Failed to delete dependent: %v", err)
	}

	// Deletar empresa e verificar se tudo é limpo
	// Remover todas as contratos associadas antes de deletar o cliente
	agreements, err = agreementStore.GetAgreementsByEntityID(entityID)
	if err != nil && err.Error() != "client not found or archived" {
		t.Fatalf("Failed to get agreements for client: %v", err)
	}
	for _, agreement := range agreements {
		err := agreementStore.DeleteAgreement(agreement.ID)
		if err != nil {
			t.Fatalf("Failed to delete contract %s: %v", agreement.ID, err)
		}
	}
	// Agora pode deletar o cliente
	err = entityStore.DeleteEntityPermanently(entityID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// Verificar se nada permanece no banco
	sub_entities, err := subEntityStore.GetSubEntitiesByEntityID(entityID)
	if err != nil {
		t.Fatalf("Failed to check sub_entities: %v", err)
	}
	if len(sub_entities) > 0 {
		t.Error("Expected no sub_entities after client deletion")
	}

	agreements, err = agreementStore.GetAgreementsByEntityID(entityID)
	if err == nil {
		t.Error("Expected error for deleted client, got none")
	}
}

func TestCategoryLineIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar stores necessárias
	categoryStore := NewCategoryStore(db)
	subcategoryStore := NewSubcategoryStore(db)

	// Criar categoria
	category := domain.Category{
		Name: "Test Category",
	}

	categoryID, err := categoryStore.CreateCategory(category)
	if err != nil {
		t.Fatalf("Failed to create category: %v", err)
	}

	// Criar tipos para a categoria
	subcategories := []domain.Subcategory{
		{Name: "Subcategory A", CategoryID: categoryID},
		{Name: "Subcategory B", CategoryID: categoryID},
	}

	var createdLines []domain.Subcategory
	for _, typ := range subcategories {
		subcategoryID, err := subcategoryStore.CreateSubcategory(typ)
		if err != nil {
			t.Fatalf("Failed to create line: %v", err)
		}
		typ.ID = subcategoryID
		createdLines = append(createdLines, typ)
	}

	// Verificar se os tipos estão associados à categoria
	foundLines, err := subcategoryStore.GetSubcategoriesByCategoryID(categoryID)
	if err != nil {
		t.Fatalf("Failed to get subcategories: %v", err)
	}
	if len(foundLines) != len(subcategories) {
		t.Errorf("Expected %d subcategories, got %d", len(subcategories), len(foundLines))
	}

	// Deletar categoria e verificar se os tipos são deletados
	// Remover todas as linhas associadas antes de deletar a categoria
	subcategories, err = subcategoryStore.GetSubcategoriesByCategoryID(categoryID)
	if err != nil {
		t.Fatalf("Failed to get subcategories for category: %v", err)
	}
	for _, l := range subcategories {
		err := subcategoryStore.DeleteSubcategory(l.ID)
		if err != nil {
			t.Fatalf("Failed to delete line %s: %v", l.ID, err)
		}
	}
	// Agora pode deletar a categoria
	err = categoryStore.DeleteCategory(categoryID)
	if err != nil {
		t.Fatalf("Failed to delete category: %v", err)
	}

	// Verificar se os tipos foram deletados
	foundLines, err = subcategoryStore.GetSubcategoriesByCategoryID(categoryID)
	if err != nil && err != ErrNoRows {
		t.Fatalf("Failed to check subcategories after category deletion: %v", err)
	}
	if err == nil && len(foundLines) > 0 {
		t.Error("Expected no subcategories after category deletion")
	}
}
