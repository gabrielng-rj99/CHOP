// Licenses-Manager/backend/store/unit_store.go

package store

import (
	"Licenses-Manager/backend/domain"
	"errors"

	"database/sql"

	"github.com/google/uuid"
)

type UnitStore struct {
	db DBInterface
}

func NewUnitStore(db DBInterface) *UnitStore {
	return &UnitStore{
		db: db,
	}
}

func (s *UnitStore) CreateUnit(unit domain.Unit) (string, error) {
	if unit.Name == "" {
		return "", sql.ErrNoRows // Or use errors.New("unit name cannot be empty")
	}
	if unit.CompanyID == "" {
		return "", sql.ErrNoRows // Or use errors.New("company ID cannot be empty")
	}
	// Check if company exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", unit.CompanyID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("company does not exist")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO units (id, name, company_id) VALUES (?, ?, ?)`
	_, err = s.db.Exec(sqlStatement, newID, unit.Name, unit.CompanyID)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetUnitsByCompanyID busca TODAS as unidades de uma empresa específica.
// MUDANÇA 1: Nomeamos os valores de retorno (units e err)
func (s *UnitStore) GetUnitsByCompanyID(companyID string) (units []domain.Unit, err error) {
	if companyID == "" {
		return nil, errors.New("company ID cannot be empty")
	}
	// Check if company exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", companyID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return []domain.Unit{}, nil // No units for non-existent company
	}

	sqlStatement := `SELECT id, name, company_id FROM units WHERE company_id = ?`

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

	units = []domain.Unit{}
	for rows.Next() {
		var unit domain.Unit
		if err = rows.Scan(&unit.ID, &unit.Name, &unit.CompanyID); err != nil {
			return nil, err
		}
		units = append(units, unit)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return units, nil
}

// UpdateUnit atualiza os dados de uma unidade existente
func (s *UnitStore) UpdateUnit(unit domain.Unit) error {
	if unit.ID == "" {
		return sql.ErrNoRows // Or use errors.New("unit ID cannot be empty")
	}
	if unit.Name == "" {
		return sql.ErrNoRows // Or use errors.New("unit name cannot be empty")
	}
	if unit.CompanyID == "" {
		return sql.ErrNoRows // Or use errors.New("company ID cannot be empty")
	}
	// Check if company exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM companies WHERE id = ?", unit.CompanyID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("company does not exist")
	}
	sqlStatement := `UPDATE units SET name = ?, company_id = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, unit.Name, unit.CompanyID, unit.ID)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// DeleteUnit remove uma unidade do banco de dados
func (s *UnitStore) DeleteUnit(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("unit ID cannot be empty")
	}
	// Check if unit exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM units WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("unit does not exist")
	}
	sqlStatement := `DELETE FROM units WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows
	}

	return nil
}

// GetUnitByID busca uma unidade específica pelo seu ID
func (s *UnitStore) GetUnitByID(id string) (*domain.Unit, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("unit ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, company_id FROM units WHERE id = ?`

	var unit domain.Unit
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&unit.ID,
		&unit.Name,
		&unit.CompanyID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &unit, nil
}
