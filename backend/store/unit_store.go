// Licenses-Manager/backend/store/unit_store.go

package store

import (
	"Licenses-Manager/backend/domain"

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
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO units (id, name, company_id) VALUES (?, ?, ?)`
	_, err := s.db.Exec(sqlStatement, newID, unit.Name, unit.CompanyID)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetUnitsByCompanyID busca TODAS as unidades de uma empresa específica.
// MUDANÇA 1: Nomeamos os valores de retorno (units e err)
func (s *UnitStore) GetUnitsByCompanyID(companyID string) (units []domain.Unit, err error) {
	sqlStatement := `SELECT id, name, company_id FROM units WHERE company_id = ?`

	rows, err := s.db.Query(sqlStatement, companyID)
	if err != nil {
		return nil, err
	}
	// MUDANÇA 2: O defer agora é uma função que verifica o erro de rows.Close()
	defer func() {
		closeErr := rows.Close()
		// Se a função principal ainda não tiver um erro, mas o Close() tiver,
		// nós atribuímos o erro do Close() ao 'err' de retorno.
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

	// MUDANÇA 3: Verificamos se houve algum erro durante a iteração (rows.Next).
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return units, nil
}

// UpdateUnit atualiza os dados de uma unidade existente
func (s *UnitStore) UpdateUnit(unit domain.Unit) error {
	sqlStatement := `UPDATE units SET name = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, unit.Name, unit.ID)
	if err != nil {
		return err
	}

	// Verifica se alguma linha foi afetada
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
	sqlStatement := `DELETE FROM units WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}

	// Verifica se alguma linha foi afetada
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
