// Licenses-Manager/backend/store/entity_store.go

package store

import (
	"Licenses-Manager/backend/domain"
	"errors"

	"database/sql"

	"github.com/google/uuid"
)

type EntityStore struct {
	db DBInterface
}

func NewEntityStore(db DBInterface) *EntityStore {
	return &EntityStore{
		db: db,
	}
}

func (s *EntityStore) CreateEntity(entity domain.Entity) (string, error) {
	if entity.Name == "" {
		return "", sql.ErrNoRows // Or use errors.New("entity name cannot be empty")
	}
	if entity.ClientID == "" {
		return "", sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", entity.ClientID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO entities (id, name, client_id) VALUES (?, ?, ?)`
	_, err = s.db.Exec(sqlStatement, newID, entity.Name, entity.ClientID)
	if err != nil {
		return "", err
	}
	return newID, nil
}

// GetEntitiesByClientID fetches ALL entities for a specific client.
func (s *EntityStore) GetEntitiesByClientID(clientID string) (entities []domain.Entity, err error) {
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
		return []domain.Entity{}, nil // No entities for non-existent client
	}

	sqlStatement := `SELECT id, name, client_id FROM entities WHERE client_id = ?`

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

	entities = []domain.Entity{}
	for rows.Next() {
		var entity domain.Entity
		if err = rows.Scan(&entity.ID, &entity.Name, &entity.ClientID); err != nil {
			return nil, err
		}
		entities = append(entities, entity)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return entities, nil
}

// UpdateEntity atualiza os dados de uma entidade existente
func (s *EntityStore) UpdateEntity(entity domain.Entity) error {
	if entity.ID == "" {
		return sql.ErrNoRows // Or use errors.New("entity ID cannot be empty")
	}
	if entity.Name == "" {
		return sql.ErrNoRows // Or use errors.New("entity name cannot be empty")
	}
	if entity.ClientID == "" {
		return sql.ErrNoRows // Or use errors.New("client ID cannot be empty")
	}
	// Check if client exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM clients WHERE id = ?", entity.ClientID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("client does not exist")
	}
	sqlStatement := `UPDATE entities SET name = ?, client_id = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, entity.Name, entity.ClientID, entity.ID)
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

// DeleteEntity remove uma entidade do banco de dados
func (s *EntityStore) DeleteEntity(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("entity ID cannot be empty")
	}
	// Check if entity exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM entities WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("entity does not exist")
	}
	sqlStatement := `DELETE FROM entities WHERE id = ?`
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

// GetEntityByID busca uma entidade específica pelo seu ID
func (s *EntityStore) GetEntityByID(id string) (*domain.Entity, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("entity ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, client_id FROM entities WHERE id = ?`

	var entity domain.Entity
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&entity.ID,
		&entity.Name,
		&entity.ClientID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &entity, nil
}
