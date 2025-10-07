package store

import (
	"Licenses-Manager/backend/database"
	"Licenses-Manager/backend/domain"
	"database/sql"
	"testing"
	"time"
)

// TestLicenseLifecycle testa o ciclo de vida completo de uma licença
func TestLicenseLifecycle(t *testing.T) {
	db, err := database.ConnectDB()
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	companyStore := NewCompanyStore(db)
	licenseStore := NewLicenseStore(db)

	// Criar uma empresa para testar as licenças
	company := domain.Company{
		Name: "License Test Company",
		CNPJ: "66.666.666/0001-66",
	}

	companyID, err := companyStore.CreateCompany(company)
	if err != nil {
		t.Fatalf("Failed to create test company: %v", err)
	}

	// Limpar depois dos testes
	defer companyStore.DeleteCompanyPermanently(companyID)

	// Criar uma licença
	now := time.Now()
	license := domain.License{
		Name:       "Test License",
		ProductKey: "TEST-KEY-123",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0), // 1 ano de validade
		TypeID:     "1",                  // Assumindo que existe este tipo
		CompanyID:  companyID,
		UnitID:     nil, // Licença sem unidade específica
	}

	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// Verificar se a licença foi criada corretamente
	createdLicense, err := licenseStore.GetLicenseByID(licenseID)
	if err != nil {
		t.Fatalf("Failed to get created license: %v", err)
	}
	if createdLicense == nil {
		t.Fatal("License not found after creation")
	}
	if createdLicense.CompanyID != companyID {
		t.Errorf("Expected company ID %s, got %s", companyID, createdLicense.CompanyID)
	}
}

// TestLicenseCompanyDeletion testa o comportamento das licenças quando uma empresa é deletada
func TestLicenseCompanyDeletion(t *testing.T) {
	db, err := database.ConnectDB()
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	companyStore := NewCompanyStore(db)
	licenseStore := NewLicenseStore(db)

	// Criar empresa
	company := domain.Company{
		Name: "Delete Test Company",
		CNPJ: "77.777.777/0001-77",
	}

	companyID, err := companyStore.CreateCompany(company)
	if err != nil {
		t.Fatalf("Failed to create test company: %v", err)
	}

	// Criar licença para a empresa
	now := time.Now()
	license := domain.License{
		Name:       "Test License",
		ProductKey: "TEST-KEY-456",
		StartDate:  now,
		EndDate:    now.AddDate(1, 0, 0),
		TypeID:     "1",
		CompanyID:  companyID,
	}

	licenseID, err := licenseStore.CreateLicense(license)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// Deletar a empresa
	err = companyStore.DeleteCompanyPermanently(companyID)
	if err != nil {
		t.Fatalf("Failed to delete company: %v", err)
	}

	// Verificar se a licença foi deletada em cascata
	_, err = licenseStore.GetLicenseByID(licenseID)
	if err == nil {
		t.Error("Expected license to be deleted with company, but it still exists")
	}
	if err != sql.ErrNoRows {
		t.Errorf("Expected sql.ErrNoRows, got %v", err)
	}
}

// TestLicenseValidation testa a validação das datas das licenças
func TestLicenseValidation(t *testing.T) {
	db, err := database.ConnectDB()
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	companyStore := NewCompanyStore(db)
	licenseStore := NewLicenseStore(db)

	// Criar empresa para os testes
	company := domain.Company{
		Name: "Validation Test Company",
		CNPJ: "88.888.888/0001-88",
	}

	companyID, err := companyStore.CreateCompany(company)
	if err != nil {
		t.Fatalf("Failed to create test company: %v", err)
	}
	defer companyStore.DeleteCompanyPermanently(companyID)

	// Tentar criar licença com data final anterior à inicial
	now := time.Now()
	invalidLicense := domain.License{
		Name:       "Invalid License",
		ProductKey: "TEST-KEY-789",
		StartDate:  now,
		EndDate:    now.AddDate(0, 0, -1), // Data final um dia antes da inicial
		TypeID:     "1",
		CompanyID:  companyID,
	}

	_, err = licenseStore.CreateLicense(invalidLicense)
	if err == nil {
		t.Error("Expected error when creating license with end date before start date")
	}
}

// TestLicenseUnit testa a associação de licenças com unidades
func TestLicenseUnit(t *testing.T) {
	db, err := database.ConnectDB()
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	companyStore := NewCompanyStore(db)
	licenseStore := NewLicenseStore(db)
	unitStore := NewUnitStore(db)

	// Criar empresa
	company := domain.Company{
		Name: "Unit Test Company",
		CNPJ: "99.999.999/0001-99",
	}

	companyID, err := companyStore.CreateCompany(company)
	if err != nil {
		t.Fatalf("Failed to create test company: %v", err)
	}
	defer companyStore.DeleteCompanyPermanently(companyID)

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
		t.Fatalf("Failed to create license with unit: %v", err)
	}

	// Verificar se a licença foi associada corretamente à unidade
	createdLicense, err := licenseStore.GetLicenseByID(licenseID)
	if err != nil {
		t.Fatalf("Failed to get created license: %v", err)
	}
	if createdLicense.UnitID == nil {
		t.Error("Expected license to be associated with unit, but UnitID is nil")
	} else if *createdLicense.UnitID != unitID {
		t.Errorf("Expected unit ID %s, got %s", unitID, *createdLicense.UnitID)
	}
}

// TestLicenseQueries testa as várias formas de consultar licenças
func TestLicenseQueries(t *testing.T) {
	db, err := database.ConnectDB()
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// TODO: Implementar testes para:
	// - GetLicensesByCompanyID
	// - GetLicensesByUnitID
	// - GetActiveLicenses (licenças não expiradas)
	// - GetExpiredLicenses
	// - GetLicensesByType
}
