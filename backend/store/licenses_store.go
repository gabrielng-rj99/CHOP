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
	db *sql.DB
}

// NewLicenseStore cria uma nova instância de LicenseStore.
func NewLicenseStore(db *sql.DB) *LicenseStore {
	return &LicenseStore{
		db: db,
	}
}

// CreateLicense insere uma nova licença no banco de dados.
func (s *LicenseStore) CreateLicense(license domain.License) (string, error) {
	newID := uuid.New().String()
	sqlStatement := `
		INSERT INTO licenses (id, name, product_key, start_date, end_date, type_id, company_id, unit_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.Exec(sqlStatement,
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
	sqlStatement := `SELECT id, name, product_key, start_date, end_date, type_id, company_id, unit_id FROM licenses WHERE company_id = ? AND company_id IN (SELECT id FROM companies WHERE archived_at IS NULL)`
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
	sqlStatement := `UPDATE licenses SET name = ?, product_key = ?, start_date = ?, end_date = ? WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, license.Name, license.ProductKey, license.StartDate, license.EndDate, license.ID)
	return err
}

func (s *LicenseStore) DeleteLicense(id string) error {
	sqlStatement := `DELETE FROM licenses WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, id)
	return err
}
