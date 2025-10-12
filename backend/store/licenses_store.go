// Licenses-Manager/backend/store/license_store.go

package store

import (
	"database/sql"
	"time"

	"Licenses-Manager/backend/domain" // Use o nome do seu módulo

	"github.com/google/uuid"
)

// LicenseStore é a nossa "caixa de ferramentas" para operações com a tabela licenses.
type LicenseStore struct {
	db DBInterface
}

// NewLicenseStore cria uma nova instância de LicenseStore.
func NewLicenseStore(db DBInterface) *LicenseStore {
	return &LicenseStore{
		db: db,
	}
}

// CreateLicense insere uma nova licença no banco de dados.
func (s *LicenseStore) CreateLicense(license domain.License) (string, error) {
	if license.Name == "" {
		return "", sql.ErrNoRows // Or use errors.New("license name cannot be empty")
	}
	if license.ProductKey == "" {
		return "", sql.ErrNoRows // Or use errors.New("product key cannot be empty")
	}
	if license.StartDate.IsZero() || license.EndDate.IsZero() {
		return "", sql.ErrNoRows // Or use errors.New("start and end date must be set")
	}
	if license.EndDate.Before(license.StartDate) {
		return "", sql.ErrNoRows // Or use errors.New("end date must be after start date")
	}
	if license.TypeID == "" {
		return "", sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	if license.CompanyID == "" {
		return "", sql.ErrNoRows // Or use errors.New("company ID cannot be empty")
	}
	// Check if type exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM types WHERE id = ?", license.TypeID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("type does not exist")
	}
	// Check if company exists
	err = s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", license.CompanyID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("company does not exist")
	}
	// If unitID is provided, check if unit exists
	if license.UnitID != nil && *license.UnitID != "" {
		err = s.db.QueryRow("SELECT COUNT(*) FROM units WHERE id = ?", *license.UnitID).Scan(&count)
		if err != nil {
			return "", err
		}
		if count == 0 {
			return "", sql.ErrNoRows // Or use errors.New("unit does not exist")
		}
	}
	// Check for duplicate product key
	err = s.db.QueryRow("SELECT COUNT(*) FROM licenses WHERE product_key = ?", license.ProductKey).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", sql.ErrNoRows // Or use errors.New("product key already exists")
	}
	newID := uuid.New().String()
	sqlStatement := `
		INSERT INTO licenses (id, name, product_key, start_date, end_date, type_id, company_id, unit_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err = s.db.Exec(sqlStatement,
		newID,
		license.Name,
		license.ProductKey,
		license.StartDate,
		license.EndDate,
		license.TypeID,
		license.CompanyID,
		license.UnitID, // O driver Go trata o ponteiro *string nil como NULL no banco
	)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetLicensesByCompanyID busca todas as licenças de uma empresa.
func (s *LicenseStore) GetLicensesByCompanyID(companyID string) (licenses []domain.License, err error) {
	if companyID == "" {
		return nil, sql.ErrNoRows // Or use errors.New("company ID cannot be empty")
	}
	// Check if company exists and is not archived
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ? AND archived_at IS NULL", companyID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil // No licenses for non-existent or archived company
	}
	sqlStatement := `SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id FROM licenses WHERE company_id = ?`
	rows, err := s.db.Query(sqlStatement, companyID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	licenses = []domain.License{}
	for rows.Next() {
		var l domain.License
		// Note o &l.UnitID para o campo que pode ser nulo
		if err = rows.Scan(&l.ID, &l.Name, &l.ProductKey, &l.StartDate, &l.EndDate, &l.TypeID, &l.CompanyID, &l.UnitID); err != nil {
			return nil, err
		}
		licenses = append(licenses, l)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return licenses, nil
}

// GetLicensesExpiringSoon busca licenças que expiram nos próximos 'days' dias.
func (s *LicenseStore) GetLicensesExpiringSoon(days int) (licenses []domain.License, err error) {
	now := time.Now()
	limitDate := now.AddDate(0, 0, days) // Adiciona 'days' dias à data atual

	sqlStatement := `SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id FROM licenses WHERE end_date BETWEEN ? AND ?`

	rows, err := s.db.Query(sqlStatement, now, limitDate)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	licenses = []domain.License{}
	for rows.Next() {
		var l domain.License
		if err = rows.Scan(&l.ID, &l.Name, &l.ProductKey, &l.StartDate, &l.EndDate, &l.TypeID, &l.CompanyID, &l.UnitID); err != nil {
			return nil, err
		}
		licenses = append(licenses, l)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return licenses, nil
}

func (s *LicenseStore) UpdateLicense(license domain.License) error {
	if license.ID == "" {
		return sql.ErrNoRows // Or use errors.New("license ID cannot be empty")
	}
	if license.Name == "" {
		return sql.ErrNoRows // Or use errors.New("license name cannot be empty")
	}
	if license.ProductKey == "" {
		return sql.ErrNoRows // Or use errors.New("product key cannot be empty")
	}
	if license.StartDate.IsZero() || license.EndDate.IsZero() {
		return sql.ErrNoRows // Or use errors.New("start and end date must be set")
	}
	if license.EndDate.Before(license.StartDate) {
		return sql.ErrNoRows // Or use errors.New("end date must be after start date")
	}
	// Check if license exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM licenses WHERE id = ?", license.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("license does not exist")
	}
	sqlStatement := `UPDATE licenses SET name = ?, product_key = ?, start_date = ?, end_date = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, license.Name, license.ProductKey, license.StartDate, license.EndDate, license.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows // Or use errors.New("no license updated")
	}
	return nil
}

// GetLicenseByID busca uma licença específica pelo seu ID
func (s *LicenseStore) GetLicenseByID(id string) (*domain.License, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("license ID cannot be empty")
	}
	sqlStatement := `
		SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id
		FROM licenses
		WHERE id = ?`

	var license domain.License
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&license.ID,
		&license.Name,
		&license.ProductKey,
		&license.StartDate,
		&license.EndDate,
		&license.TypeID,
		&license.CompanyID,
		&license.UnitID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &license, nil
}

func (s *LicenseStore) DeleteLicense(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("license ID cannot be empty")
	}
	// Check if license exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM licenses WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("license does not exist")
	}
	sqlStatement := `DELETE FROM licenses WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows // Or use errors.New("no license deleted")
	}
	return nil
}
