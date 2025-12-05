/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Open-Generic-Hub/backend/store/line_store.go

package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	domain "Open-Generic-Hub/backend/domain" // Use o nome do seu módulo

	"github.com/google/uuid"
)

// SubcategoryStore é a nossa "caixa de ferramentas" para operações com a tabela subcategories.
type SubcategoryStore struct {
	db DBInterface
}

// NewSubcategoryStore cria uma nova instância de SubcategoryStore.
func NewSubcategoryStore(db DBInterface) *SubcategoryStore {
	return &SubcategoryStore{
		db: db,
	}
}

// CreateSubcategory insere um novo tipo de licença no banco, associado a uma categoria.
func (s *SubcategoryStore) CreateSubcategory(subcategory domain.Subcategory) (string, error) {
	trimmedName, err := ValidateName(subcategory.Name, 255)
	if err != nil {
		return "", err
	}
	if subcategory.CategoryID == "" {
		return "", sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", subcategory.CategoryID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("category does not exist")
	}
	// NOVA REGRA: Nome único por categoria (case-insensitive via CITEXT)
	err = s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE category_id = $1 AND LOWER(name) = LOWER($2)", subcategory.CategoryID, trimmedName).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("line name must be unique per category")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO subcategories (id, name, category_id) VALUES ($1, $2, $3)`

	_, err = s.db.Exec(sqlStatement, newID, trimmedName, subcategory.CategoryID)
	if err != nil {
		return "", err
	}

	return newID, nil
}

// GetSubcategoriesByCategoryID busca TODOS os tipos de uma categoria específica (não arquivados).
func (s *SubcategoryStore) GetSubcategoriesByCategoryID(categoryID string) (subcategories []domain.Subcategory, err error) {
	if categoryID == "" {
		return nil, sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", categoryID).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil // No subcategories for non-existent category
	}

	sqlStatement := `SELECT id, name, category_id, archived_at FROM subcategories WHERE category_id = $1 AND archived_at IS NULL`

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

	subcategories = []domain.Subcategory{}
	for rows.Next() {
		var t domain.Subcategory // 'line' é uma palavra reservada, então usamos 't'
		if err = rows.Scan(&t.ID, &t.Name, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		subcategories = append(subcategories, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return subcategories, nil
}

// GetSubcategoryByID busca um tipo específico pelo seu ID
func (s *SubcategoryStore) GetSubcategoryByID(id string) (*domain.Subcategory, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, category_id, archived_at FROM subcategories WHERE id = $1`

	var t domain.Subcategory
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&t.ID,
		&t.Name,
		&t.CategoryID,
		&t.ArchivedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &t, nil
}

// GetAllSubcategories busca todos os tipos de licença (não arquivados)
func (s *SubcategoryStore) GetAllSubcategories() (subcategories []domain.Subcategory, err error) {
	sqlStatement := `SELECT id, name, category_id, archived_at FROM subcategories WHERE archived_at IS NULL`

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

	subcategories = []domain.Subcategory{}
	for rows.Next() {
		var t domain.Subcategory
		if err = rows.Scan(&t.ID, &t.Name, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		subcategories = append(subcategories, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return subcategories, nil
}

// GetAllSubcategoriesIncludingArchived busca todos os tipos de licença, incluindo arquivados
func (s *SubcategoryStore) GetAllSubcategoriesIncludingArchived() (subcategories []domain.Subcategory, err error) {
	sqlStatement := `SELECT id, name, category_id, archived_at FROM subcategories`

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

	subcategories = []domain.Subcategory{}
	for rows.Next() {
		var t domain.Subcategory
		if err = rows.Scan(&t.ID, &t.Name, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		subcategories = append(subcategories, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return subcategories, nil
}

// GetSubcategoriesByName busca linhas por nome (case-insensitive, parcial, não arquivados)
func (s *SubcategoryStore) GetSubcategoriesByName(name string) ([]domain.Subcategory, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, category_id, archived_at FROM subcategories WHERE name LIKE $1 AND archived_at IS NULL`
	likePattern := "%" + name + "%"
	rows, err := s.db.Query(sqlStatement, likePattern)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := rows.Close()
		if err == nil {
			err = closeErr
		}
	}()
	var subcategories []domain.Subcategory
	for rows.Next() {
		var t domain.Subcategory
		if err = rows.Scan(&t.ID, &t.Name, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		subcategories = append(subcategories, t)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return subcategories, nil
}

func (s *SubcategoryStore) UpdateSubcategory(subcategory domain.Subcategory) error {
	if subcategory.ID == "" {
		return sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	trimmedName, err := ValidateName(subcategory.Name, 255)
	if err != nil {
		return err
	}
	if subcategory.CategoryID == "" {
		return sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", subcategory.CategoryID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("category does not exist")
	}
	// NOVA REGRA: Não permitir mover linha entre categorias
	var currentCategoryID string
	err = s.db.QueryRow("SELECT category_id FROM subcategories WHERE id = $1", subcategory.ID).Scan(&currentCategoryID)
	if err != nil {
		return err
	}
	if currentCategoryID != subcategory.CategoryID {
		return errors.New("cannot move line between categories")
	}

	// NOVA REGRA: Nome único por categoria (case-insensitive via CITEXT)
	// Check if another subcategory in the same category has the same name
	var duplicateCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE category_id = $1 AND LOWER(name) = LOWER($2) AND id != $3",
		subcategory.CategoryID, trimmedName, subcategory.ID).Scan(&duplicateCount)
	if err != nil {
		return err
	}
	if duplicateCount > 0 {
		return errors.New("line name must be unique per category")
	}

	sqlStatement := `UPDATE subcategories SET name = $1 WHERE id = $2`
	result, err := s.db.Exec(sqlStatement, trimmedName, subcategory.ID)
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

// ArchiveSubcategory arquiva uma linha
func (s *SubcategoryStore) ArchiveSubcategory(id string) error {
	if id == "" {
		return sql.ErrNoRows
	}

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("line does not exist")
	}

	sqlStatement := `UPDATE subcategories SET archived_at = $1 WHERE id = $2`
	result, err := s.db.Exec(sqlStatement, time.Now(), id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no line archived")
	}

	return nil
}

// UnarchiveSubcategory desarquiva uma linha
func (s *SubcategoryStore) UnarchiveSubcategory(id string) error {
	if id == "" {
		return sql.ErrNoRows
	}

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("line does not exist")
	}

	sqlStatement := `UPDATE subcategories SET archived_at = NULL WHERE id = $1`
	result, err := s.db.Exec(sqlStatement, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("no line unarchived")
	}

	return nil
}

func (s *SubcategoryStore) DeleteSubcategory(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	// Check if type exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM subcategories WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("type does not exist")
	}
	// NOVA REGRA: Não permitir deletar linha com contratos associados
	var contractCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM agreements WHERE subcategory_id = $1", id).Scan(&contractCount)
	if err != nil {
		return err
	}
	if contractCount > 0 {
		return errors.New("cannot delete line with associated agreements")
	}
	sqlStatement := `DELETE FROM subcategories WHERE id = $1`
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
