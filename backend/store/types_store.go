// Licenses-Manager/backend/store/type_store.go

package store

import (
	"database/sql"

	"Licenses-Manager/backend/domain" // Use o nome do seu módulo

	"github.com/google/uuid"
)

// TypeStore é a nossa "caixa de ferramentas" para operações com a tabela types.
type TypeStore struct {
	db DBInterface
}

// NewTypeStore cria uma nova instância de TypeStore.
func NewTypeStore(db DBInterface) *TypeStore {
	return &TypeStore{
		db: db,
	}
}

// CreateType insere um novo tipo de licença no banco, associado a uma categoria.
func (s *TypeStore) CreateType(licensetype domain.Type) (string, error) {
	if licensetype.Name == "" {
		return "", sql.ErrNoRows // Or use errors.New("type name cannot be empty")
	}
	if licensetype.CategoryID == "" {
		return "", sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = ?", licensetype.CategoryID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("category does not exist")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO types (id, name, category_id) VALUES (?, ?, ?)`

	_, err = s.db.Exec(sqlStatement, newID, licensetype.Name, licensetype.CategoryID)
	if err != nil {
		return "", err
	}

	return newID, nil
}

// GetTypesByCategoryID busca TODOS os tipos de uma categoria específica.
func (s *TypeStore) GetTypesByCategoryID(categoryID string) (types []domain.Type, err error) {
	if categoryID == "" {
		return nil, sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = ?", categoryID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil // No types for non-existent category
	}

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

// GetTypeByID busca um tipo específico pelo seu ID
func (s *TypeStore) GetTypeByID(id string) (*domain.Type, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, category_id FROM types WHERE id = ?`

	var t domain.Type
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&t.ID,
		&t.Name,
		&t.CategoryID,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// GetAllTypes busca todos os tipos de licença
func (s *TypeStore) GetAllTypes() (types []domain.Type, err error) {
	sqlStatement := `SELECT id, name, category_id FROM types`

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

	types = []domain.Type{}
	for rows.Next() {
		var t domain.Type
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
	if licensetype.ID == "" {
		return sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	if licensetype.Name == "" {
		return sql.ErrNoRows // Or use errors.New("type name cannot be empty")
	}
	if licensetype.CategoryID == "" {
		return sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = ?", licensetype.CategoryID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("category does not exist")
	}
	sqlStatement := `UPDATE types SET name = ?, category_id = ? WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, licensetype.Name, licensetype.CategoryID, licensetype.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows // Or use errors.New("no type updated")
	}
	return nil
}

func (s *TypeStore) DeleteType(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	// Check if type exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM types WHERE id = ?", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("type does not exist")
	}
	sqlStatement := `DELETE FROM types WHERE id = ?`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return sql.ErrNoRows // Or use errors.New("no type deleted")
	}
	return nil
}
