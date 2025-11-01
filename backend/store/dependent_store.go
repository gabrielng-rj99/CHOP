// Contracts-Manager/backend/store/dependent_store.go

package store

import (
	"Contracts-Manager/backend/domain"
	"errors"

	"database/sql"

	"github.com/google/uuid"
)

type DependentStore struct {
	db DBInterface
}

func NewDependentStore(db DBInterface) *DependentStore {
	return &DependentStore{
		db: db,
	}
}

func (s *DependentStore) CreateDependent(dependent domain.Dependent) (string, error) {
	trimmedName, err := ValidateName(dependent.Name, 255)
	if err != nil {
		return "", err
	}
	if dependent.ClientID == "" {
		return "", sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", dependent.ClientID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	// NOVA REGRA: Nome único por empresa
	err = s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE client_id = ? AND name = ?", dependent.ClientID, dependent.Name).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("dependent name must be unique per client")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO dependents (id, name, client_id) VALUES (?, ?, ?)`
	_, err = s.db.Exec(sqlStatement, newID, trimmedName, dependent.ClientID)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetDependentsByClientID fetches ALL dependents for a specific client.
func (s *DependentStore) GetDependentsByClientID(clientID string) (dependents []domain.Dependent, err error) {
	if clientID == "" {
		return nil, errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", clientID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return []domain.Dependent{}, nil // No dependents for non-existent client
	}

	sqlStatement := `SELECT id, name, client_id FROM dependents WHERE client_id = ?`

	rows, err := s.db.Query(sqlStatement, clientID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	dependents = []domain.Dependent{}
	for rows.Next() {
		var dependent domain.Dependent
		if err = rows.Scan(&dependent.ID, &dependent.Name, &dependent.ClientID); err != nil {
			return nil, err
		}
		dependents = append(dependents, dependent)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return dependents, nil
}

// UpdateDependent atualiza os dados de um dependente existente
func (s *DependentStore) UpdateDependent(dependent domain.Dependent) error {
	if dependent.ID == "" {
		return sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	trimmedName, err := ValidateName(dependent.Name, 255)
	if err != nil {
		return err
	}
	if dependent.ClientID == "" {
		return sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", dependent.ClientID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	sqlStatement := `UPDATE dependents SET name = ?, client_id = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, trimmedName, dependent.ClientID, dependent.ID)
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

// DeleteDependent remove um dependente do banco de dados
func (s *DependentStore) DeleteDependent(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	// Check if dependent exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM dependents WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("dependent does not exist")
	}
	// NOVA REGRA: Desassociar contratos antes de deletar dependente
	_, err = s.db.Exec("UPDATE contracts SET dependent_id = NULL WHERE dependent_id = ?", id)
	if err != nil {
		return err
	}
	sqlStatement := `DELETE FROM dependents WHERE id = ?`
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

// GetDependentByID busca um dependente específico pelo seu ID
func (s *DependentStore) GetDependentByID(id string) (*domain.Dependent, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("dependent ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, client_id FROM dependents WHERE id = ?`

	var dependent domain.Dependent
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&dependent.ID,
		&dependent.Name,
		&dependent.ClientID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &dependent, nil
}
