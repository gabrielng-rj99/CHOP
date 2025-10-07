package store

import (
	"Licenses-Manager/backend/database"
	"Licenses-Manager/backend/domain"
	"database/sql"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := database.ConnectDB()
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	return db
}

func cleanupTestData(db *sql.DB) error {
	tables := []string{"licenses", "units", "companies", "types", "categories"}
	for _, table := range tables {
		if _, err := db.Exec("DELETE FROM " + table); err != nil {
			return err
		}
	}
	return nil
}

func TestCompanyLicenseIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	companyStore := NewCompanyStore(db)
	licenseStore := NewLicenseStore(db)

	// Criar empresa
	company := domain.Company{
		Name: "Integration Test Company",
		CNPJ: "12.345.678/0001-90",
	}

	companyID, err := companyStore.CreateCompany(company)
	if err != nil {
		t.Fatalf("Failed to create company: %v", err)
	}

	// Criar licença para a empresa
	now := time.Now()
	license := domain.License{
		Name:       "Test License",
		ProductKey: "TEST-KEY-123",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0),
		TypeID:     "1", // Assumindo que existe este tipo
		CompanyID:  companyID,
	}

	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// Verificar se a licença está associada à empresa
	licenses, err := licenseStore.GetLicensesByCompanyID(companyID)
	if err != nil {
		t.Fatalf("Failed to get licenses: %v", err)
	}
	if len(licenses) != 1 {
		t.Errorf("Expected 1 license, got %d", len(licenses))
	}

	// Arquivar empresa e verificar se as licenças ainda são acessíveis
	err = companyStore.ArchiveCompany(companyID)
	if err != nil {
		t.Fatalf("Failed to archive company: %v", err)
	}

	// Não deve encontrar licenças para empresa arquivada
	licenses, err = licenseStore.GetLicensesByCompanyID(companyID)
	if err != nil {
		t.Fatalf("Failed to get licenses for archived company: %v", err)
	}
	if len(licenses) > 0 {
		t.Error("Expected no licenses for archived company")
	}

	// Deletar empresa e verificar se as licenças são deletadas em cascata
	err = companyStore.DeleteCompanyPermanently(companyID)
	if err != nil {
		t.Fatalf("Failed to delete company: %v", err)
	}

	// A licença não deve mais existir
	_, err = licenseStore.GetLicenseByID(licenseID)
	if err != sql.ErrNoRows {
		t.Error("Expected license to be deleted with company")
	}
}

func TestCompanyUnitLicenseIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	companyStore := NewCompanyStore(db)
	unitStore := NewUnitStore(db)
	licenseStore := NewLicenseStore(db)

	// Criar empresa
	company := domain.Company{
		Name: "Full Integration Test Company",
		CNPJ: "98.765.432/0001-10",
	}

	companyID, err := companyStore.CreateCompany(company)
	if err != nil {
		t.Fatalf("Failed to create company: %v", err)
	}

	// Criar unidade
	unit := domain.Unit{
		Name:      "Test Unit",
		CompanyID: companyID,
	}

	unitID, err := unitStore.CreateUnit(unit)
	if err != nil {
		t.Fatalf("Failed to create unit: %v", err)
	}

	// Criar licença associada à unidade
	now := time.Now()
	license := domain.License{
		Name:       "Unit License",
		ProductKey: "UNIT-KEY-123",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0),
		TypeID:     "1",
		CompanyID:  companyID,
		UnitID:     &unitID,
	}

	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// Verificar se a licença está corretamente associada à unidade
	licenses, err := licenseStore.GetLicensesByCompanyID(companyID)
	if err != nil {
		t.Fatalf("Failed to get licenses: %v", err)
	}
	if len(licenses) != 1 {
		t.Fatalf("Expected 1 license, got %d", len(licenses))
	}
	if licenses[0].UnitID == nil || *licenses[0].UnitID != unitID {
		t.Error("License not properly associated with unit")
	}

	// Deletar a unidade e verificar se a licença é atualizada (não deletada)
	err = unitStore.DeleteUnit(unitID)
	if err != nil {
		t.Fatalf("Failed to delete unit: %v", err)
	}

	// A licença deve ainda existir, mas sem unidade associada
	updatedLicense, err := licenseStore.GetLicenseByID(licenseID)
	if err != nil {
		t.Fatalf("Failed to get license after unit deletion: %v", err)
	}
	if updatedLicense.UnitID != nil {
		t.Error("License should not be associated with deleted unit")
	}

	// Deletar empresa e verificar se tudo é limpo
	err = companyStore.DeleteCompanyPermanently(companyID)
	if err != nil {
		t.Fatalf("Failed to delete company: %v", err)
	}

	// Verificar se nada permanece no banco
	units, err := unitStore.GetUnitsByCompanyID(companyID)
	if err != nil {
		t.Fatalf("Failed to check units: %v", err)
	}
	if len(units) > 0 {
		t.Error("Expected no units after company deletion")
	}

	licenses, err = licenseStore.GetLicensesByCompanyID(companyID)
	if err != nil {
		t.Fatalf("Failed to check licenses: %v", err)
	}
	if len(licenses) > 0 {
		t.Error("Expected no licenses after company deletion")
	}
}

func TestCategoryTypeIntegration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	defer cleanupTestData(db)

	categoryStore := NewCategoryStore(db)
	typeStore := NewTypeStore(db)

	// Criar categoria
	category := domain.Category{
		Name: "Test Category",
	}

	categoryID, err := categoryStore.CreateCategory(category)
	if err != nil {
		t.Fatalf("Failed to create category: %v", err)
	}

	// Criar tipos para a categoria
	types := []domain.Type{
		{Name: "Type A", CategoryID: categoryID},
		{Name: "Type B", CategoryID: categoryID},
	}

	for _, typ := range types {
		_, err := typeStore.CreateType(typ)
		if err != nil {
			t.Fatalf("Failed to create type: %v", err)
		}
	}

	// Verificar se os tipos estão associados à categoria
	categoryTypes, err := typeStore.GetTypesByCategoryID(categoryID)
	if err != nil {
		t.Fatalf("Failed to get types: %v", err)
	}
	if len(categoryTypes) != len(types) {
		t.Errorf("Expected %d types, got %d", len(types), len(categoryTypes))
	}

	// Deletar categoria e verificar se os tipos são deletados
	err = categoryStore.DeleteCategory(categoryID)
	if err != nil {
		t.Fatalf("Failed to delete category: %v", err)
	}

	// Verificar se os tipos foram deletados
	categoryTypes, err = typeStore.GetTypesByCategoryID(categoryID)
	if err != nil {
		t.Fatalf("Failed to check types after category deletion: %v", err)
	}
	if len(categoryTypes) > 0 {
		t.Error("Expected no types after category deletion")
	}
}
