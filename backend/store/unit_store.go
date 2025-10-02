// backend/store/unit_store.go

package store

import (
	"backend/domain"

	"database/sql"
	"github.com/google/uuid"
)

type UnitStore struct {
	db *sql.DB
}

func NewUnitStore(db *sql.DB) *UnitStore {
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
