// Contracts-Manager/backend/store/category_store.go

package store

import (
	"Contracts-Manager/backend/domain"
	"database/sql"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// Use o nome do seu módulo

// CategoryStore é a nossa "caixa de ferramentas" para operações com a tabela categories.
type CategoryStore struct {
	db DBInterface
}

// NewCategoryStore cria uma nova instância de CategoryStore.
func NewCategoryStore(db DBInterface) *CategoryStore {
	return &CategoryStore{
		db: db,
	}
}

// CreateCategory insere uma nova categoria no banco de dados.
func (s *CategoryStore) CreateCategory(category domain.Category) (string, error) {
	trimmedName, err := ValidateName(category.Name, 255)
	if err != nil {
		return "", err
	}

	newID := uuid.New().String()
	sqlStatement := `INSERT INTO categories (id, name) VALUES ($1, $2)`

	_, err = s.db.Exec(sqlStatement, newID, trimmedName)
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
	if rows == nil {
		return []domain.Category{}, nil
	}

	defer func() {
		if rows != nil {
			closeErr := rows.Close()
			if err == nil {
				err = closeErr
			}
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

// GetCategoriesByName busca categorias por nome (case-insensitive, parcial)
func (s *CategoryStore) GetCategoriesByName(name string) ([]domain.Category, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name FROM categories WHERE name LIKE $1`
	likePattern := "%" + name + "%"
	rows, err := s.db.Query(sqlStatement, likePattern)
	if err != nil {
		return nil, err
	}
	defer func() {
		if rows != nil {
			closeErr := rows.Close()
			if err == nil {
				err = closeErr
			}
		}
	}()
	var categories []domain.Category
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

// GetCategoryByID busca uma categoria específica pelo seu ID
func (s *CategoryStore) GetCategoryByID(id string) (*domain.Category, error) {
	if id == "" {
		return nil, errors.New("category ID cannot be empty")
	}
	sqlStatement := `SELECT id, name FROM categories WHERE id = $1`

	var category domain.Category
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&category.ID,
		&category.Name,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &category, nil
}

func (s *CategoryStore) UpdateCategory(category domain.Category) error {
	if category.ID == "" {
		return errors.New("category ID cannot be empty")
	}
	trimmedName, err := ValidateName(category.Name, 255)
	if err != nil {
		return err
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", category.ID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("category does not exist")
	}
	sqlStatement := `UPDATE categories SET name = $1 WHERE id = $2`
	result, err := s.db.Exec(sqlStatement, trimmedName, category.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no category updated")
	}
	return nil
}

func (s *CategoryStore) DeleteCategory(id string) error {
	if id == "" {
		return errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("category does not exist")
	}

	// Check if any lines are used in active contracts
	var contractsCount int
	err = s.db.QueryRow(`
		SELECT COUNT(*)
		FROM contracts c
		INNER JOIN lines l ON c.line_id = l.id
		WHERE l.category_id = $1
	`, id).Scan(&contractsCount)
	if err != nil {
		return err
	}
	if contractsCount > 0 {
		return errors.New("cannot delete category: it has lines associated with active contracts")
	}

	// Delete all lines associated with this category first
	_, err = s.db.Exec("DELETE FROM lines WHERE category_id = $1", id)
	if err != nil {
		return err
	}

	// Now delete the category
	sqlStatement := `DELETE FROM categories WHERE id = $1`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no category deleted")
	}
	return nil
}
