// Licenses-Manager/backend/store/company_store.go

package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"Licenses-Manager/backend/domain"

	"github.com/google/uuid"
)

type CompanyStore struct {
	db DBInterface
}

func NewCompanyStore(db DBInterface) *CompanyStore {
	return &CompanyStore{
		db: db,
	}
}

// CreateCompany foi atualizado para incluir a nova coluna (que será NULL por padrão)
func (s *CompanyStore) CreateCompany(company domain.Company) (string, error) {
	if company.Name == "" {
		return "", errors.New("company name cannot be empty")
	}
	if company.CNPJ == "" {
		return "", errors.New("company CNPJ cannot be empty")
	}
	// Check for duplicate CNPJ
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE cnpj = ?", company.CNPJ).Scan(&count)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	if count > 0 {
		return "", errors.New("company CNPJ already exists")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO companies (id, name, cnpj) VALUES (?, ?, ?)`
	_, err = s.db.Exec(sqlStatement, newID, company.Name, company.CNPJ)
	if err != nil {
		// Handle unique constraint violation for CNPJ
		if err.Error() != "" &&
			(strings.Contains(err.Error(), "UNIQUE constraint failed: companies.cnpj") ||
				strings.Contains(err.Error(), "restrição UNIQUE falhou: companies.cnpj")) {
			return "", errors.New("company CNPJ already exists")
		}
		return "", err
	}
	return newID, nil
}

// GetCompanyByID foi atualizado para ler a nova coluna
func (s *CompanyStore) GetCompanyByID(id string) (*domain.Company, error) {
	if id == "" {
		return nil, errors.New("company ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, cnpj, archived_at FROM companies WHERE id = ?`
	row := s.db.QueryRow(sqlStatement, id)

	var company domain.Company
	err := row.Scan(&company.ID, &company.Name, &company.CNPJ, &company.ArchivedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &company, nil
}

// UpdateCompany também foi atualizado
func (s *CompanyStore) UpdateCompany(company domain.Company) error {
	if company.ID == "" {
		return errors.New("company ID cannot be empty")
	}
	if company.Name == "" {
		return errors.New("company name cannot be empty")
	}
	if company.CNPJ == "" {
		return errors.New("company CNPJ cannot be empty")
	}
	// Check if company exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", company.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("company does not exist")
	}
	sqlStatement := `UPDATE companies SET name = ?, cnpj = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, company.Name, company.CNPJ, company.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no company updated")
	}
	return nil
}

// --- NOVAS FUNÇÕES ---

// ArchiveCompany define a data de arquivamento para a data/hora atual.
func (s *CompanyStore) ArchiveCompany(id string) error {
	if id == "" {
		return errors.New("company ID cannot be empty")
	}
	// Check if company exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("company not found")
	}
	sqlStatement := `UPDATE companies SET archived_at = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, time.Now(), id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no company archived")
	}
	return nil
}

// UnarchiveCompany define a data de arquivamento de volta para NULL.
func (s *CompanyStore) UnarchiveCompany(id string) error {
	if id == "" {
		return errors.New("company ID cannot be empty")
	}
	// Check if company exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("company not found")
	}
	sqlStatement := `UPDATE companies SET archived_at = NULL WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no company unarchived")
	}
	return nil
}

// --- FUNÇÃO DE DELEÇÃO PERMANENTE ---
//
// DeleteCompanyPermanently remove permanentemente uma empresa e seus dados associados.
func (s *CompanyStore) DeleteCompanyPermanently(id string) error {
	if id == "" {
		return errors.New("company ID cannot be empty")
	}
	// Check if company exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("company not found")
	}
	sqlStatement := `DELETE FROM companies WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no company deleted")
	}
	return nil
}

// GetAllCompanies retorna todas as empresas não arquivadas
func (s *CompanyStore) GetAllCompanies() (companies []domain.Company, err error) {
	sqlStatement := `SELECT id, name, cnpj, archived_at FROM companies WHERE archived_at IS NULL`

	rows, err := s.db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	companies = []domain.Company{}
	for rows.Next() {
		var company domain.Company
		if err = rows.Scan(&company.ID, &company.Name, &company.CNPJ, &company.ArchivedAt); err != nil {
			return nil, err
		}
		companies = append(companies, company)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return companies, nil
}

// GetArchivedCompanies retorna todas as empresas arquivadas
func (s *CompanyStore) GetArchivedCompanies() (companies []domain.Company, err error) {
	sqlStatement := `SELECT id, name, cnpj, archived_at FROM companies WHERE archived_at IS NOT NULL`

	rows, err := s.db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	companies = []domain.Company{}
	for rows.Next() {
		var company domain.Company
		if err = rows.Scan(&company.ID, &company.Name, &company.CNPJ, &company.ArchivedAt); err != nil {
			return nil, err
		}
		companies = append(companies, company)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return companies, nil
}
