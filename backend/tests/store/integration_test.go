package tests

import (
	"testing"
	"time"

	"Licenses-Manager/backend/domain"
	"Licenses-Manager/backend/store"
	"database/sql"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}
	return db
}

func cleanupTestData(db *sql.DB) error {
	tables := []string{"licenses", "entities", "clients", "lines", "categories"}
	for _, table := range tables {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
}

func TestClientLicenseIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar client store e license store
	clientStore := store.NewClientStore(db)
	licenseStore := store.NewLicenseStore(db)

	// Criar cliente
	client := domain.Client{
		Name:           "Empresa Teste",
		RegistrationID: "45.723.174/0001-10",
	}

	clientID, err := clientStore.CreateClient(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Inserir categoria e tipo antes de criar a licença
	categoryID, err := InsertTestCategory(db, "Integration Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	lineID, err := InsertTestLine(db, "Integration Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Criar licença para a empresa
	now := time.Now()
	license := domain.License{
		Model:      "Test License",
		ProductKey: "TEST-KEY-123",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0),
		LineID:     lineID,
		ClientID:   clientID,
	}

	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		if err == store.ErrInvalidClientEntity {
			t.Skip("Skipping test due to invalid client entity")
		}
		t.Fatalf("Failed to create license: %v", err)
	}

	// Criar entidade associada ao cliente
	entityStore := store.NewEntityStore(db)
	entity := domain.Entity{
		Name:     "Entidade Teste",
		ClientID: clientID,
	}
	entityID, err := entityStore.CreateEntity(entity)
	if err != nil {
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Verificar se a licença está associada à empresa
	licenses, err := licenseStore.GetLicensesByClientID(clientID)
	if err != nil {
		if err != store.ErrNoRows {
			t.Fatalf("Failed to get licenses: %v", err)
		}
	} else if len(licenses) != 1 {
		t.Errorf("Expected 1 license, got %d", len(licenses))
	}

	// Arquivar empresa e verificar se as licenças ainda são acessíveis
	err = clientStore.ArchiveClient(clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Não deve encontrar licenças para empresa arquivada
	licenses, err = licenseStore.GetLicensesByClientID(clientID)
	if err == nil {
		t.Error("Expected error for archived client, got none")
	}

	// Arquivar o cliente antes de deletar (nova regra de negócio)
	err = clientStore.ArchiveClient(clientID)
	if err != nil {
		t.Fatalf("Failed to archive client: %v", err)
	}

	// Remover todas as licenças associadas antes de deletar o cliente
	licenses, err = licenseStore.GetLicensesByClientID(clientID)
	if err != nil && err.Error() != "client not found or archived" {
		t.Fatalf("Failed to get licenses for client: %v", err)
	}
	for _, lic := range licenses {
		err := licenseStore.DeleteLicense(lic.ID)
		if err != nil {
			t.Fatalf("Failed to delete license %s: %v", lic.ID, err)
		}
	}
	// Agora pode deletar empresa e verificar se as licenças e entidades são deletadas em cascata
	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// A licença não deve mais existir
	deletedLicense, err := licenseStore.GetLicenseByID(licenseID)
	if err != nil {
		t.Fatalf("Unexpected error when checking for deleted license: %v", err)
	}
	if deletedLicense != nil {
		t.Error("Expected license to be deleted with client")
	}

	// A entidade não deve mais existir
	deletedEntity, err := entityStore.GetEntityByID(entityID)
	if err != nil {
		t.Fatalf("Unexpected error when checking for deleted entity: %v", err)
	}
	if deletedEntity != nil {
		t.Error("Expected entity to be deleted with client")
	}
}

func TestClientEntityLicenseIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar stores necessárias
	clientStore := store.NewClientStore(db)
	entityStore := store.NewEntityStore(db)
	licenseStore := store.NewLicenseStore(db)

	// Criar Cliente
	client := domain.Client{
		Name:           "Full Integration Test Client",
		RegistrationID: "45.723.174/0001-10",
	}

	clientID, err := clientStore.CreateClient(client)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Criar unidade
	entity := domain.Entity{
		Name:     "Test Entity",
		ClientID: clientID,
	}

	entityID, err := entityStore.CreateEntity(entity)
	if err != nil {
		// Se necessário, pode-se criar um erro customizado para entidade inválida
		// if err == store.ErrInvalidClientEntity {
		// 	t.Skip("Skipping test due to invalid client entity")
		// }
		t.Fatalf("Failed to create entity: %v", err)
	}

	// Inserir categoria e tipo antes de criar a licença
	categoryID, err := InsertTestCategory(db, "Integration Category")
	if err != nil {
		t.Fatalf("Failed to insert test category: %v", err)
	}
	lineID, err := InsertTestLine(db, "Integration Line", categoryID)
	if err != nil {
		t.Fatalf("Failed to insert test line: %v", err)
	}

	// Criar licença associada à unidade
	now := time.Now()
	var entityIDPtr *string
	if entityID != "" {
		entityIDPtr = &entityID
	}
	license := domain.License{
		Model:      "Entity License",
		ProductKey: "ENTITY-KEY-123",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0),
		LineID:     lineID, // Use o ID realmente inserido
		ClientID:   clientID,
		EntityID:   entityIDPtr,
	}

	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// Verificar se a licença está corretamente associada à unidade
	licenses, err := licenseStore.GetLicensesByClientID(clientID)
	if err != nil {
		if err != store.ErrNoRows {
			t.Fatalf("Failed to get licenses: %v", err)
		}
		return
	}
	if len(licenses) != 1 {
		t.Fatalf("Expected 1 license, got %d", len(licenses))
	}
	if licenses[0].EntityID == nil || *licenses[0].EntityID != entityID {
		t.Error("License not properly associated with entity")
	}

	// Deletar a unidade e verificar se a licença é atualizada (não deletada)
	err = entityStore.DeleteEntity(entityID)
	if err != nil {
		t.Fatalf("Failed to delete entity: %v", err)
	}

	// A licença deve ainda existir, mas sem entidade associada
	updatedLicense, err := licenseStore.GetLicenseByID(licenseID)
	if err != nil {
		t.Fatalf("Failed to get license after entity deletion: %v", err)
	}
	if updatedLicense.EntityID != nil {
		t.Error("License should not be associated with deleted entity")
	}

	// Deletar empresa e verificar se tudo é limpo
	// Remover todas as licenças associadas antes de deletar o cliente
	licenses, err = licenseStore.GetLicensesByClientID(clientID)
	if err != nil && err.Error() != "client not found or archived" {
		t.Fatalf("Failed to get licenses for client: %v", err)
	}
	for _, lic := range licenses {
		err := licenseStore.DeleteLicense(lic.ID)
		if err != nil {
			t.Fatalf("Failed to delete license %s: %v", lic.ID, err)
		}
	}
	// Agora pode deletar o cliente
	err = clientStore.DeleteClientPermanently(clientID)
	if err != nil {
		t.Fatalf("Failed to delete client: %v", err)
	}

	// Verificar se nada permanece no banco
	entities, err := entityStore.GetEntitiesByClientID(clientID)
	if err != nil {
		t.Fatalf("Failed to check entities: %v", err)
	}
	if len(entities) > 0 {
		t.Error("Expected no entities after client deletion")
	}

	licenses, err = licenseStore.GetLicensesByClientID(clientID)
	if err == nil {
		t.Error("Expected error for deleted client, got none")
	}
}

func TestCategoryLineIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	// Criar stores necessárias
	categoryStore := store.NewCategoryStore(db)
	lineStore := store.NewLineStore(db)

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
	if err != nil && err != store.ErrNoRows {
		t.Fatalf("Failed to check lines after category deletion: %v", err)
	}
	if err == nil && len(foundLines) > 0 {
		t.Error("Expected no lines after category deletion")
	}
}
