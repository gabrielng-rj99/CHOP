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

// LineStore é a nossa "caixa de ferramentas" para operações com a tabela lines.
type LineStore struct {
	db DBInterface
}

// NewLineStore cria uma nova instância de LineStore.
func NewLineStore(db DBInterface) *LineStore {
	return &LineStore{
		db: db,
	}
}

// CreateLine insere um novo tipo de licença no banco, associado a uma categoria.
func (s *LineStore) CreateLine(licenseline domain.Line) (string, error) {
	trimmedName, err := ValidateName(licenseline.Line, 255)
	if err != nil {
		return "", err
	}
	if licenseline.CategoryID == "" {
		return "", sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", licenseline.CategoryID).Scan(&count)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "", sql.ErrNoRows // Or use errors.New("category does not exist")
	}
	// NOVA REGRA: Nome único por categoria (case-insensitive via CITEXT)
	err = s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE category_id = $1 AND name = $2", licenseline.CategoryID, trimmedName).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("line name must be unique per category")
	}
	newID := uuid.New().String()
	sqlStatement := `INSERT INTO lines (id, name, category_id) VALUES ($1, $2, $3)`

	_, err = s.db.Exec(sqlStatement, newID, trimmedName, licenseline.CategoryID)
	if err != nil {
		return "", err
	}

	return newID, nil
}

// GetLinesByCategoryID busca TODOS os tipos de uma categoria específica (não arquivados).
func (s *LineStore) GetLinesByCategoryID(categoryID string) (lines []domain.Line, err error) {
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
		return nil, nil // No lines for non-existent category
	}

	sqlStatement := `SELECT id, name, category_id, archived_at FROM lines WHERE category_id = $1 AND archived_at IS NULL`

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

	lines = []domain.Line{}
	for rows.Next() {
		var t domain.Line // 'line' é uma palavra reservada, então usamos 't'
		if err = rows.Scan(&t.ID, &t.Line, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		lines = append(lines, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// GetLineByID busca um tipo específico pelo seu ID
func (s *LineStore) GetLineByID(id string) (*domain.Line, error) {
	if id == "" {
		return nil, sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	sqlStatement := `SELECT id, name, category_id, archived_at FROM lines WHERE id = $1`

	var t domain.Line
	err := s.db.QueryRow(sqlStatement, id).Scan(
		&t.ID,
		&t.Line,
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

// GetAllLines busca todos os tipos de licença (não arquivados)
func (s *LineStore) GetAllLines() (lines []domain.Line, err error) {
	sqlStatement := `SELECT id, name, category_id, archived_at FROM lines WHERE archived_at IS NULL`

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

	lines = []domain.Line{}
	for rows.Next() {
		var t domain.Line
		if err = rows.Scan(&t.ID, &t.Line, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		lines = append(lines, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// GetAllLinesIncludingArchived busca todos os tipos de licença, incluindo arquivados
func (s *LineStore) GetAllLinesIncludingArchived() (lines []domain.Line, err error) {
	sqlStatement := `SELECT id, name, category_id, archived_at FROM lines`

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

	lines = []domain.Line{}
	for rows.Next() {
		var t domain.Line
		if err = rows.Scan(&t.ID, &t.Line, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		lines = append(lines, t)
	}

	if err = rows.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// GetLinesByName busca linhas por nome (case-insensitive, parcial, não arquivados)
func (s *LineStore) GetLinesByName(name string) ([]domain.Line, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, name, category_id, archived_at FROM lines WHERE name LIKE $1 AND archived_at IS NULL`
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
	var lines []domain.Line
	for rows.Next() {
		var t domain.Line
		if err = rows.Scan(&t.ID, &t.Line, &t.CategoryID, &t.ArchivedAt); err != nil {
			return nil, err
		}
		lines = append(lines, t)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func (s *LineStore) UpdateLine(licenseline domain.Line) error {
	if licenseline.ID == "" {
		return sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	trimmedName, err := ValidateName(licenseline.Line, 255)
	if err != nil {
		return err
	}
	if licenseline.CategoryID == "" {
		return sql.ErrNoRows // Or use errors.New("category ID cannot be empty")
	}
	// Check if category exists
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM categories WHERE id = $1", licenseline.CategoryID).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("category does not exist")
	}
	// NOVA REGRA: Não permitir mover linha entre categorias
	var currentCategoryID string
	err = s.db.QueryRow("SELECT category_id FROM lines WHERE id = $1", licenseline.ID).Scan(&currentCategoryID)
	if err != nil {
		return err
	}
	if currentCategoryID != licenseline.CategoryID {
		return errors.New("cannot move line between categories")
	}
	sqlStatement := `UPDATE lines SET name = $1 WHERE id = $2`
	result, err := s.db.Exec(sqlStatement, trimmedName, licenseline.ID)
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

// ArchiveLine arquiva uma linha
func (s *LineStore) ArchiveLine(id string) error {
	if id == "" {
		return sql.ErrNoRows
	}

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("line does not exist")
	}

	sqlStatement := `UPDATE lines SET archived_at = $1 WHERE id = $2`
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

// UnarchiveLine desarquiva uma linha
func (s *LineStore) UnarchiveLine(id string) error {
	if id == "" {
		return sql.ErrNoRows
	}

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("line does not exist")
	}

	sqlStatement := `UPDATE lines SET archived_at = NULL WHERE id = $1`
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

func (s *LineStore) DeleteLine(id string) error {
	if id == "" {
		return sql.ErrNoRows // Or use errors.New("type ID cannot be empty")
	}
	// Check if type exists
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM lines WHERE id = $1", id).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		return sql.ErrNoRows // Or use errors.New("type does not exist")
	}
	// NOVA REGRA: Não permitir deletar linha com contratos associados
	var contractCount int
	err = s.db.QueryRow("SELECT COUNT(*) FROM contracts WHERE line_id = $1", id).Scan(&contractCount)
	if err != nil {
		return err
	}
	if contractCount > 0 {
		return errors.New("cannot delete line with associated contracts")
	}
	sqlStatement := `DELETE FROM lines WHERE id = $1`
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
