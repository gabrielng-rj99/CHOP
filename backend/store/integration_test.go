package store

import (
	"testing"
	"time"

	"Contracts-Manager/backend/domain"
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
	tables := []string{"contracts", "dependents", "clients", "lines", "categories"}
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
	phone := "+5511987654321"
	client := domain.Client{
		Name:           "Empresa Teste",
		RegistrationID: "45.723.174/0001-10",
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
	lineID, err := InsertTestLine(db, "Integration Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Criar contrato para a empresa
	now := time.Now()
	contract := domain.Contract{
		Model:      "Test License",
		ProductKey: "TEST-KEY-123",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0),
		LineID:     lineID,
		ClientID:   clientID,
	}

	_, err = contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Criar dependente associado ao cliente
	dependentStore := NewDependentStore(db)
	dependent := domain.Dependent{
		Name:     "Dependente Teste",
		ClientID: clientID,
	}
	dependentID, err := dependentStore.CreateDependent(dependent)
	if err != nil {
		t.Fatalf("Failed to create dependent: %v", err)
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

	// O dependente não deve mais existir
	deletedDependent, err := dependentStore.GetDependentByID(dependentID)
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
	clientStore := NewClientStore(db)
	dependentStore := NewDependentStore(db)
	contractStore := NewContractStore(db)

	// Criar Cliente
	email := "integration@test.com"
	phone := "+5511999999999"
	client := domain.Client{
		Name:           "Full Integration Test Client",
		RegistrationID: "45.723.174/0001-10",
		Email:          &email,
		Phone:          &phone,
	}

	clientID, err := clientStore.CreateClient(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Criar dependente
	dependent := domain.Dependent{
		Name:     "Test Dependent",
		ClientID: clientID,
	}

	dependentID, err := dependentStore.CreateDependent(dependent)
	if err != nil {
		t.Fatalf("Failed to create dependent: %v", err)
	}

	// Inserir categoria e tipo antes de criar o contrato
	categoryID, err := InsertTestCategory(db, "Integration Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	lineID, err := InsertTestLine(db, "Integration Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Criar contrato associada ao dependente
	now := time.Now()
	var entityIDPtr *string
	if dependentID != "" {
		entityIDPtr = &dependentID
	}
	contract := domain.Contract{
		Model:       "Dependent License",
		ProductKey:  "ENTITY-KEY-123",
		StartDate:   now,
		EndDate:     now.AddDate(1, 0, 0),
		LineID:      lineID, // Use o ID realmente inserido
		ClientID:    clientID,
		DependentID: entityIDPtr,
	}

	_, err = contractStore.CreateContract(contract)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Verificar se o contrato está corretamente associada ao dependente
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
	if contracts[0].DependentID == nil || *contracts[0].DependentID != dependentID {
		t.Error("Contract not properly associated with dependent")
	}

	// Deletar a unidade e verificar se o contrato é atualizada (não deletada)
	// Deletar o dependente e verificar desassociação
	err = dependentStore.DeleteDependent(dependentID)
	if err != nil {
		t.Fatalf("Failed to delete dependent: %v", err)
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
	dependents, err := dependentStore.GetDependentsByClientID(clientID)
	if err != nil {
		t.Fatalf("Failed to check dependents: %v", err)
	}
	if len(dependents) > 0 {
		t.Error("Expected no dependents after client deletion")
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
	lineStore := NewLineStore(db)

	// Criar categoria
	category := domain.Category{
		Name: "Test Category",
	}

	categoryID, err := categoryStore.CreateCategory(category)
	if err != nil {
		t.Fatalf("Failed to create category: %v", err)
	}

	// Criar tipos para a categoria
	lines := []domain.Line{
		{Line: "Line A", CategoryID: categoryID},
		{Line: "Line B", CategoryID: categoryID},
	}

	var createdLines []domain.Line
	for _, typ := range lines {
		lineID, err := lineStore.CreateLine(typ)
		if err != nil {
			t.Fatalf("Failed to create line: %v", err)
		}
		typ.ID = lineID
		createdLines = append(createdLines, typ)
	}

	// Verificar se os tipos estão associados à categoria
	foundLines, err := lineStore.GetLinesByCategoryID(categoryID)
	if err != nil {
		t.Fatalf("Failed to get lines: %v", err)
	}
	if len(foundLines) != len(lines) {
		t.Errorf("Expected %d lines, got %d", len(lines), len(foundLines))
	}

	// Deletar categoria e verificar se os tipos são deletados
	// Remover todas as linhas associadas antes de deletar a categoria
	lines, err = lineStore.GetLinesByCategoryID(categoryID)
	if err != nil {
		t.Fatalf("Failed to get lines for category: %v", err)
	}
	for _, l := range lines {
		err := lineStore.DeleteLine(l.ID)
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
	foundLines, err = lineStore.GetLinesByCategoryID(categoryID)
	if err != nil && err != ErrNoRows {
		t.Fatalf("Failed to check lines after category deletion: %v", err)
	}
	if err == nil && len(foundLines) > 0 {
		t.Error("Expected no lines after category deletion")
	}
}
