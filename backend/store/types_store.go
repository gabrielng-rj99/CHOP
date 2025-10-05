// Licenses-Manager/backend/store/type_store.go

package store

import (
	"database/sql"

	"Licenses-Manager/backend/domain" // Use o nome do seu módulo
	"github.com/google/uuid"
)

// TypeStore é a nossa "caixa de ferramentas" para operações com a tabela types.
type TypeStore struct {
	db *sql.DB
}

// NewTypeStore cria uma nova instância de TypeStore.
func NewTypeStore(db *sql.DB) *TypeStore {
	return &TypeStore{
		db: db,
	}
}

// CreateType insere um novo tipo de licença no banco, associado a uma categoria.
func (s *TypeStore) CreateType(licensetype domain.Type) (string, error) {
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO types (id, name, category_id) VALUES (?, ?, ?)`

	_, err := s.db.Exec(sqlStatement, newID, licensetype.Name, licensetype.CategoryID)
	if err != nil {
		return "", err
	}

	return newID, nil
}

// GetTypesByCategoryID busca TODOS os tipos de uma categoria específica.
func (s *TypeStore) GetTypesByCategoryID(categoryID string) (types []domain.Type, err error) {
	sqlStatement := `SELECT id, name, category_id FROM types WHERE category_id = ?`

	rows, err := s.db.Query(sqlStatement, categoryID)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()

	types = []domain.Type{}
	for rows.Next() {
		var t domain.Type // 'type' é uma palavra reservada, então usamos 't'
		if err = rows.Scan(&t.ID, &t.Name, &t.CategoryID); err != nil {
			return nil, err
		}
		types = append(types, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return types, nil
}

func (s *TypeStore) UpdateType(licensetype domain.Type) error {
	sqlStatement := `UPDATE types SET name = ? WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, licensetype.Name, licensetype.ID)
	return err
}

func (s *TypeStore) DeleteType(id string) error {
	sqlStatement := `DELETE FROM types WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, id)
	return err
}
