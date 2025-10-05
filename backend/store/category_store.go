// Licenses-Manager/backend/store/category_store.go

package store

import (
	"database/sql"

	"Licenses-Manager/backend/domain" // Use o nome do seu módulo
	"github.com/google/uuid"
)

// CategoryStore é a nossa "caixa de ferramentas" para operações com a tabela categories.
type CategoryStore struct {
	db *sql.DB
}

// NewCategoryStore cria uma nova instância de CategoryStore.
func NewCategoryStore(db *sql.DB) *CategoryStore {
	return &CategoryStore{
		db: db,
	}
}

// CreateCategory insere uma nova categoria no banco de dados.
func (s *CategoryStore) CreateCategory(category domain.Category) (string, error) {
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO categories (id, name) VALUES (?, ?)`

	_, err := s.db.Exec(sqlStatement, newID, category.Name)
	if err != nil {
		return "", err
	}

	return newID, nil
}

// GetAllCategories busca TODAS as categorias do banco de dados.
// Isto será útil para preencher listas de seleção no frontend.
func (s *CategoryStore) GetAllCategories() (categories []domain.Category, err error) {
	sqlStatement := `SELECT id, name FROM categories`
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

	categories = []domain.Category{}
	for rows.Next() {
		var category domain.Category
		if err = rows.Scan(&category.ID, &category.Name); err != nil {
			return nil, err
		}
		categories = append(categories, category)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return categories, nil
}

func (s *CategoryStore) UpdateCategory(category domain.Category) error {
	sqlStatement := `UPDATE categories SET name = ? WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, category.Name, category.ID)
	return err
}

func (s *CategoryStore) DeleteCategory(id string) error {
	sqlStatement := `DELETE FROM categories WHERE id = ?`
	_, err := s.db.Exec(sqlStatement, id)
	return err
}
