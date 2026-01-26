//go:build disabled
// +build disabled

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

// DISABLED: This file contains integration tests that require store constructors
// from multiple subpackages, which causes import cycles. These tests should be
// refactored into their respective subpackage test suites.
package repository

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
	tables := []string{"contracts", "affiliates", "clients", "subcategories", "categories"}
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
	clientStore := NewClientStore(db)
	contractStore := NewContractStore(db)

	// Criar cliente
	email := "empresa@teste.com"
	phone := "5511987654321"
	regID := "45.723.174/0001-10"
	client := domain.Client{
		Name:           "Empresa Teste",
		RegistrationID: &regID,
		Status:         "ativo",
		Email:          &email,
		Phone:          &phone,
	}

	clientID, err := clientStore.CreateClient(client)
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
	contract := domain.Contract{
		Model:         "Test License",
		ItemKey:       "TEST-KEY-123",
		StartDate:     timePtr(now),
		EndDate:       timePtr(now.AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID,
		ClientID:      clientID,
	}

	_, err = contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Criar afiliado associado ao cliente
	subClientStore := NewAffiliateStore(db)
	affiliate := domain.Affiliate{
		Name:     "Afiliado Teste",
		ClientID: clientID,
		Status:   "ativo",
	}
	subClientID, err := subClientStore.CreateAffiliate(affiliate)
	if err != nil {
		t.Fatalf("Failed to create affiliate: %v", err)
	}

	// Verificar se o contrato está associada à empresa
	contracts, err := contractStore.GetContractsByClientID(clientID)
	if err != nil {
		if err != ErrNoRows {
			t.Fatalf("Failed to get contracts: %v", err)
		}
	} else if len(contracts) != 1 {
		t.Errorf("Expected 1 contract, got %d", len(contracts))
	}

	// Arquivar empresa e verificar se as contratos ainda são acessíveis
	err = clientStore.ArchiveClient(clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Não deve encontrar contratos para empresa arquivada
	contracts, err = contractStore.GetContractsByClientID(clientID)
	if err == nil {
		t.Error("Expected error for archived client, got none")
	}

	// Arquivar o cliente antes de deletar (nova regra de negócio)
	err = clientStore.ArchiveClient(clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Remover todas as contratos associadas antes de deletar o cliente
	contracts, err = contractStore.GetContractsByClientID(clientID)
	if err != nil && err.Error() != "client not found or archived" {
		t.Fatalf("Failed to get contracts for client: %v", err)
	}
	for _, contract := range contracts {
		err := contractStore.DeleteContract(contract.ID)
		if err != nil {
			t.Fatalf("Failed to delete contract %s: %v", contract.ID, err)
		}
	}
	// Agora pode deletar empresa e verificar se as contratos e entidades são deletadas em cascata
	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// O afiliado não deve mais existir
	deletedAffiliate, err := subClientStore.GetAffiliateByID(subClientID)
	if err != nil {
		t.Fatalf("Unexpected error when checking for deleted affiliate: %v", err)
	}
	if deletedAffiliate != nil {
		t.Error("Expected affiliate to be deleted with client")
	}
}

func TestClientAffiliateContractIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar stores necessárias
	clientStore := NewClientStore(db)
	subClientStore := NewAffiliateStore(db)
	contractStore := NewContractStore(db)

	// Criar Cliente
	phone := "5511999999999"
	regID2 := "45.723.174/0001-10"
	client := domain.Client{
		Name:           "Full Integration Test Client",
		RegistrationID: &regID2,
		Status:         "ativo",
		Phone:          &phone,
	}

	clientID, err := clientStore.CreateClient(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Criar afiliado
	affiliate := domain.Affiliate{
		Name:     "Test Affiliate",
		ClientID: clientID,
		Status:   "ativo",
	}

	subClientID, err := subClientStore.CreateAffiliate(affiliate)
	if err != nil {
		t.Fatalf("Failed to create affiliate: %v", err)
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

	// Criar contrato associada ao afiliado
	now := time.Now()
	var clientIDPtr *string
	if subClientID != "" {
		clientIDPtr = &subClientID
	}
	contract := domain.Contract{
		Model:         "Affiliate License",
		ItemKey:       "TEST-KEY-123",
		StartDate:     timePtr(now),
		EndDate:       timePtr(now.AddDate(1, 0, 0)),
		SubcategoryID: subcategoryID, // Use o ID realmente inserido
		ClientID:      clientID,
		AffiliateID:   clientIDPtr,
	}

	_, err = contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Verificar se o contrato está corretamente associada ao afiliado
	contracts, err := contractStore.GetContractsByClientID(clientID)
	if err != nil {
		if err != ErrNoRows {
			t.Fatalf("Failed to get contracts: %v", err)
		}
		return
	}
	if len(contracts) != 1 {
		t.Fatalf("Expected 1 contract, got %d", len(contracts))
	}
	if contracts[0].AffiliateID == nil || *contracts[0].AffiliateID != subClientID {
		t.Error("Contract not properly associated with affiliate")
	}

	// Deletar a unidade e verificar se o contrato é atualizada (não deletada)
	// Deletar o afiliado e verificar desassociação
	err = subClientStore.DeleteAffiliate(subClientID)
	if err != nil {
		t.Fatalf("Failed to delete affiliate: %v", err)
	}

	// Deletar empresa e verificar se tudo é limpo
	// Remover todas as contratos associadas antes de deletar o cliente
	contracts, err = contractStore.GetContractsByClientID(clientID)
	if err != nil && err.Error() != "client not found or archived" {
		t.Fatalf("Failed to get contracts for client: %v", err)
	}
	for _, contract := range contracts {
		err := contractStore.DeleteContract(contract.ID)
		if err != nil {
			t.Fatalf("Failed to delete contract %s: %v", contract.ID, err)
		}
	}
	// Agora pode deletar o cliente
	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// Verificar se nada permanece no banco
	affiliates, err := subClientStore.GetAffiliatesByClientID(clientID)
	if err != nil {
		t.Fatalf("Failed to check affiliates: %v", err)
	}
	if len(affiliates) > 0 {
		t.Error("Expected no affiliates after client deletion")
	}

	contracts, err = contractStore.GetContractsByClientID(clientID)
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
