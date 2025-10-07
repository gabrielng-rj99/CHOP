// Licenses-Manager/backend/store/company_store.go

package store

import (
	"database/sql"
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
	newID := uuid.New().String()
	// A coluna archived_at não é inserida, então ela será NULL por padrão
	sqlStatement := `INSERT INTO companies (id, name, cnpj) VALUES (?, ?, ?)`
	_, err := s.db.Exec(sqlStatement, newID, company.Name, company.CNPJ)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetCompanyByID foi atualizado para ler a nova coluna
func (s *CompanyStore) GetCompanyByID(id string) (*domain.Company, error) {
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
	sqlStatement := `UPDATE companies SET name = ?, cnpj = ? WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, company.Name, company.CNPJ, company.ID)
	return err
}

// --- NOVAS FUNÇÕES ---

// ArchiveCompany define a data de arquivamento para a data/hora atual.
func (s *CompanyStore) ArchiveCompany(id string) error {
	sqlStatement := `UPDATE companies SET archived_at = ? WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, time.Now(), id)
	return err
}

// UnarchiveCompany define a data de arquivamento de volta para NULL.
func (s *CompanyStore) UnarchiveCompany(id string) error {
	sqlStatement := `UPDATE companies SET archived_at = NULL WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, id)
	return err
}

// --- FUNÇÃO DE DELEÇÃO PERMANENTE ---

// DeleteCompanyPermanently remove permanentemente uma empresa e seus dados associados.
func (s *CompanyStore) DeleteCompanyPermanently(id string) error {
	sqlStatement := `DELETE FROM companies WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, id)
	return err
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
