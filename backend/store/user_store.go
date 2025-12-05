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

package store

import (
	domain "Open-Generic-Hub/backend/domain"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"time"


	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// UserStore gerencia operações de usuários (login/cadastro)
type UserStore struct {
	db DBInterface
}

// NewUserStore cria uma nova instância de UserStore
func NewUserStore(db DBInterface) *UserStore {
	return &UserStore{
		db: db,
	}
}

// Validação de senha forte: 16+ caracteres, 1 número, 1 minúscula, 1 maiúscula, 1 símbolo, sem espaços
func ValidateStrongPassword(password string) error {
	if len(password) < 16 {
		return errors.New("a senha deve ter pelo menos 16 caracteres")
	}
	if strings.Contains(password, " ") {
		return errors.New("a senha não pode conter espaços")
	}
	reNumber := regexp.MustCompile(`[0-9]`)
	reLower := regexp.MustCompile(`[a-z]`)
	reUpper := regexp.MustCompile(`[A-Z]`)
	reSymbol := regexp.MustCompile(`[!@#\$%\^&\*\(\)_\+\-=\[\]\{\};':",\.<>\/\?\\|]`)

	if !reNumber.MatchString(password) {
		return errors.New("a senha deve conter pelo menos um número")
	}
	if !reLower.MatchString(password) {
		return errors.New("a senha deve conter pelo menos uma letra minúscula")
	}
	if !reUpper.MatchString(password) {
		return errors.New("a senha deve conter pelo menos uma letra maiúscula")
	}
	if !reSymbol.MatchString(password) {
		return errors.New("a senha deve conter pelo menos um símbolo")
	}
	return nil
}

// HashPassword gera o hash bcrypt da senha
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CreateUser cadastra um novo usuário após validar senha forte
func (s *UserStore) CreateUser(username, displayName, password, role string) (string, error) {
	if err := ValidateUsername(username); err != nil {
		return "", err
	}
	trimmedUsername := strings.TrimSpace(username)
	trimmedDisplayName, errDisplay := ValidateName(displayName, 255)
	if errDisplay != nil {
		return "", errDisplay
	}

	// Validate role - only "user", "admin" or "root" allowed
	if role != "" && role != "user" && role != "admin" && role != "root" {
		return "", errors.New("invalid role: must be 'user', 'admin' or 'root'")
	}
	if role == "" {
		role = "user"
	}

	if err := ValidateStrongPassword(password); err != nil {
		return "", err
	}

	// Verifica se já existe usuário com esse nome (ignorando deletados)
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 AND deleted_at IS NULL", trimmedUsername).Scan(&count)
	if err != nil {
		return "", err
	}
	if count > 0 {
		return "", errors.New("nome de usuário já existe")
	}

	id := uuid.New().String()
	passwordHash, err := HashPassword(password)
	if err != nil {
		return "", err
	}
	createdAt := time.Now()
	updatedAt := createdAt

	// Gerar auth_secret como SHA256(UUID + updatedAt)
	authSecretRaw := id + updatedAt.Format(time.RFC3339Nano)
	authSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(authSecretRaw)))

	sqlStatement := `INSERT INTO users (id, username, display_name, password_hash, created_at, updated_at, role, deleted_at, auth_secret) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)`
	_, err = s.db.Exec(sqlStatement, id, trimmedUsername, trimmedDisplayName, passwordHash, createdAt, updatedAt, role, authSecret)
	if err != nil {
		return "", err
	}
	return id, nil
}

// Permite que um admin altere seu próprio username
// GetUserByID busca um usuário pelo ID
func (s *UserStore) GetUserByID(userID string) (*domain.User, error) {
	var user domain.User
	var username, displayName, role sql.NullString
	var deletedAt, lockedUntil sql.NullTime

	query := `SELECT id, username, display_name, password_hash, created_at, updated_at, deleted_at, role, failed_attempts, lock_level, locked_until, auth_secret FROM users WHERE id = $1`
	err := s.db.QueryRow(query, userID).Scan(
		&user.ID,
		&username,
		&displayName,
		&user.PasswordHash,
		&user.CreatedAt,
		&user.UpdatedAt,
		&deletedAt,
		&role,
		&user.FailedAttempts,
		&user.LockLevel,
		&lockedUntil,
		&user.AuthSecret,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("usuário não encontrado")
		}
		return nil, err
	}

	if username.Valid {
		user.Username = &username.String
	}
	if displayName.Valid {
		user.DisplayName = &displayName.String
	}
	if deletedAt.Valid {
		user.DeletedAt = &deletedAt.Time
	}
	if role.Valid {
		user.Role = &role.String
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}

	return &user, nil
}

func (s *UserStore) UpdateUsername(currentUsername, newUsername string) error {
	if newUsername == "" {
		return errors.New("novo nome de usuário não pode ser vazio")
	}
	// Verifica se já existe usuário com esse nome (ignorando deletados)
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 AND deleted_at IS NULL", newUsername).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("nome de usuário já existe")
	}
	// Verifica se o usuário existe
	err = s.db.QueryRow("SELECT 1 FROM users WHERE username = $1 AND deleted_at IS NULL", currentUsername).Scan(&count)
	if err != nil {
		return errors.New("usuário não encontrado")
	}

	// Gera novo auth_secret
	updatedAt := time.Now()
	authSecretRaw := uuid.New().String()
	authSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(authSecretRaw)))

	sqlStatement := `UPDATE users SET username = $1, updated_at = $2, auth_secret = $3 WHERE username = $4 AND deleted_at IS NULL`
	result, err := s.db.Exec(sqlStatement, newUsername, updatedAt, authSecret, currentUsername)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("usuário não encontrado")
	}
	return nil
}

// AuthenticateUser verifica se o usuário e senha estão corretos
var bruteForceLevels = []struct {
	attempts int
	duration time.Duration
}{
	{5, time.Minute},
	{3, 5 * time.Minute},
	{3, 15 * time.Minute},
	{3, 30 * time.Minute},
	{3, 60 * time.Minute},
	{3, 120 * time.Minute},
	{3, 240 * time.Minute},
	{3, 480 * time.Minute},
	{3, 1440 * time.Minute}, // 24h
}

func (s *UserStore) AuthenticateUser(username, password string) (*domain.User, error) {
	if username == "" || password == "" {
		return nil, errors.New("usuário e senha são obrigatórios")
	}

	// Busca todos os campos necessários para brute-force (ignorando usuários deletados)
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, updated_at, role, failed_attempts, lock_level, locked_until, auth_secret FROM users WHERE username = $1 AND deleted_at IS NULL`
	row := s.db.QueryRow(sqlStatement, username)

	var user domain.User
	var failedAttempts, lockLevel int
	var lockedUntil sql.NullTime
	var username_ptr sql.NullString
	var displayName sql.NullString
	var role sql.NullString

	err := row.Scan(&user.ID, &username_ptr, &displayName, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &role, &failedAttempts, &lockLevel, &lockedUntil, &user.AuthSecret)
	if err != nil {
		fmt.Println("Erro no Scan da autenticação:", err)
		return nil, errors.New("usuário não encontrado")
	}

	// Converter sql.NullString para pointer
	if username_ptr.Valid {
		user.Username = &username_ptr.String
	}
	if displayName.Valid {
		user.DisplayName = &displayName.String
	}
	if role.Valid {
		user.Role = &role.String
	}

	now := time.Now()
	if lockedUntil.Valid && now.Before(lockedUntil.Time) {
		if lockLevel >= len(bruteForceLevels) {
			return nil, errors.New("Conta bloqueada. Só pode ser desbloqueada manualmente por um admin.")
		}
		return nil, fmt.Errorf("Conta bloqueada até %s por múltiplas tentativas. Tente novamente depois.", lockedUntil.Time.Format(time.RFC1123))
	}

	// Verifica o hash bcrypt
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		// Falha: incrementa tentativas
		failedAttempts++
		// Limite do nível atual
		level := lockLevel
		if level >= len(bruteForceLevels) {
			// Bloqueio manual
			_, _ = s.db.Exec(`UPDATE users SET failed_attempts = $1, locked_until = $2, lock_level = $3 WHERE username = $4`, failedAttempts, now.Add(365*24*time.Hour), level, username)
			return nil, errors.New("Conta bloqueada. Só pode ser desbloqueada manualmente por um admin.")
		}
		limit := bruteForceLevels[level].attempts
		if failedAttempts >= limit {
			// Sobe de nível e bloqueia
			lockLevel++
			if lockLevel >= len(bruteForceLevels) {
				// Bloqueio manual (define locked_until para 1 ano no futuro)
				_, _ = s.db.Exec(`UPDATE users SET failed_attempts = 0, locked_until = $1, lock_level = $2 WHERE username = $3`, now.Add(365*24*time.Hour), lockLevel, username)
				return nil, errors.New("Conta bloqueada. Só pode ser desbloqueada manualmente por um admin.")
			} else {
				dur := bruteForceLevels[lockLevel].duration
				t := now.Add(dur)
				_, _ = s.db.Exec(`UPDATE users SET failed_attempts = 0, locked_until = $1, lock_level = $2 WHERE username = $3`, t, lockLevel, username)
				return nil, fmt.Errorf("Conta bloqueada até %s por múltiplas tentativas. Tente novamente depois.", t.Format(time.RFC1123))
			}
		} else {
			_, _ = s.db.Exec(`UPDATE users SET failed_attempts = $1, lock_level = $2 WHERE username = $3`, failedAttempts, lockLevel, username)
		}
		return nil, errors.New("usuário ou senha inválidos")
	}

	// Sucesso: reseta tudo
	_, _ = s.db.Exec(`UPDATE users SET failed_attempts = 0, lock_level = 0, locked_until = NULL WHERE username = $1`, username)
	return &user, nil
}

// Edita a senha de um usuário existente, validando e salvando hasheada
func (s *UserStore) EditUserPassword(username, newPassword string) error {
	if err := ValidateStrongPassword(newPassword); err != nil {
		return err
	}
	passwordHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}
	// Atualiza updated_at e gera novo auth_secret
	updatedAt := time.Now()
	var id string
	err = s.db.QueryRow("SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL", username).Scan(&id)
	if err != nil {
		return errors.New("usuário não encontrado")
	}
	authSecretRaw := id + updatedAt.Format(time.RFC3339Nano)
	authSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(authSecretRaw)))

	sqlStatement := `UPDATE users SET password_hash = $1, updated_at = $2, auth_secret = $3 WHERE username = $4 AND deleted_at IS NULL`
	result, err := s.db.Exec(sqlStatement, passwordHash, updatedAt, authSecret, username)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("usuário não encontrado")
	}
	return nil
}

// Edita o display name de um usuário existente
func (s *UserStore) EditUserDisplayName(username, newDisplayName string) error {
	trimmedDisplayName, err := ValidateName(newDisplayName, 255)
	if err != nil {
		return err
	}
	// Atualiza updated_at e gera novo auth_secret
	updatedAt := time.Now()
	var id string
	err = s.db.QueryRow("SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL", username).Scan(&id)
	if err != nil {
		return err
	}
	authSecretRaw := id + updatedAt.Format(time.RFC3339Nano)
	authSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(authSecretRaw)))

	sqlStatement := `UPDATE users SET display_name = $1, updated_at = $2, auth_secret = $3 WHERE username = $4 AND deleted_at IS NULL`
	result, err := s.db.Exec(sqlStatement, trimmedDisplayName, updatedAt, authSecret, username)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("usuário não encontrado")
	}
	return nil
}

// Edita o role de um usuário, só pode ser chamada por root
func (s *UserStore) EditUserRole(requesterUsername, targetUsername, newRole string) error {
	// Verifica se o requester é root
	var requesterRole sql.NullString
	err := s.db.QueryRow("SELECT role FROM users WHERE username = $1 AND deleted_at IS NULL", requesterUsername).Scan(&requesterRole)
	if err != nil {
		return errors.New("usuário solicitante não encontrado")
	}
	if !requesterRole.Valid || requesterRole.String != "root" {
		return errors.New("apenas usuários com role 'root' podem alterar o role de outros usuários")
	}
	// Atualiza role, updated_at e gera novo auth_secret
	updatedAt := time.Now()
	var userID string
	err = s.db.QueryRow("SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL", targetUsername).Scan(&userID)
	if err != nil {
		return errors.New("usuário alvo não encontrado")
	}
	authSecretRaw := userID + updatedAt.Format(time.RFC3339Nano)
	authSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(authSecretRaw)))

	sqlStatement := `UPDATE users SET role = $1, updated_at = $2, auth_secret = $3 WHERE username = $4 AND deleted_at IS NULL`
	result, err := s.db.Exec(sqlStatement, newRole, updatedAt, authSecret, targetUsername)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("usuário alvo não encontrado")
	}
	return nil
}

// ListUsers retorna todos os usuários cadastrados (exceto deletados), incluindo os hashes das senhas
func (s *UserStore) ListUsers() ([]domain.User, error) {
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role, failed_attempts, lock_level, locked_until, deleted_at FROM users WHERE deleted_at IS NULL ORDER BY created_at DESC`
	rows, err := s.db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var user domain.User
		var failedAttempts, lockLevel int
		var lockedUntil sql.NullTime
		var username_ptr sql.NullString
		var displayName sql.NullString
		var role sql.NullString
		var deletedAt sql.NullTime

		err := rows.Scan(&user.ID, &username_ptr, &displayName, &user.PasswordHash, &user.CreatedAt, &role, &failedAttempts, &lockLevel, &lockedUntil, &deletedAt)
		if err != nil {
			return nil, err
		}

		// Converter sql.NullString para pointer
		if username_ptr.Valid {
			user.Username = &username_ptr.String
		}
		if displayName.Valid {
			user.DisplayName = &displayName.String
		}
		if role.Valid {
			user.Role = &role.String
		}
		if deletedAt.Valid {
			user.DeletedAt = &deletedAt.Time
		}

		// Popular campos extras
		user.FailedAttempts = failedAttempts
		user.LockLevel = lockLevel
		if lockedUntil.Valid {
			user.LockedUntil = &lockedUntil.Time
		} else {
			user.LockedUntil = nil
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// DeleteUser realiza soft-delete de um usuário (marca como deletado, não remove dados)
func (s *UserStore) DeleteUser(adminID, adminUsername, username string) error {
	// Busca o usuário para obter seus dados antes de deletar
	var userID string
	var displayName sql.NullString
	err := s.db.QueryRow("SELECT id, display_name FROM users WHERE username = $1 AND deleted_at IS NULL", username).Scan(&userID, &displayName)
	if err != nil {
		return errors.New("usuário não encontrado")
	}

	// Marca como deletado (soft delete)
	deletedTime := time.Now()
	result, err := s.db.Exec(`
		UPDATE users
		SET deleted_at = $1, username = NULL, password_hash = NULL, role = NULL, display_name = NULL
		WHERE id = $2 AND deleted_at IS NULL
	`, deletedTime, userID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return errors.New("usuário não encontrado ou já foi deletado")
	}

	return nil
}

// GetUsersByName busca usuários por nome de usuário ou display name (case-insensitive, parcial)
func (s *UserStore) GetUsersByName(name string) ([]domain.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role, failed_attempts, lock_level, locked_until, deleted_at FROM users WHERE deleted_at IS NULL AND (LOWER(username) LIKE LOWER($1) OR LOWER(display_name) LIKE LOWER($2))`
	likePattern := "%" + name + "%"
	rows, err := s.db.Query(sqlStatement, likePattern, likePattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var user domain.User
		var failedAttempts, lockLevel int
		var lockedUntil sql.NullTime
		var username_ptr sql.NullString
		var displayName sql.NullString
		var role sql.NullString
		var deletedAt sql.NullTime

		err := rows.Scan(&user.ID, &username_ptr, &displayName, &user.PasswordHash, &user.CreatedAt, &role, &failedAttempts, &lockLevel, &lockedUntil, &deletedAt)
		if err != nil {
			return nil, err
		}

		// Converter sql.NullString para pointer
		if username_ptr.Valid {
			user.Username = &username_ptr.String
		}
		if displayName.Valid {
			user.DisplayName = &displayName.String
		}
		if role.Valid {
			user.Role = &role.String
		}
		if deletedAt.Valid {
			user.DeletedAt = &deletedAt.Time
		}

		user.FailedAttempts = failedAttempts
		user.LockLevel = lockLevel
		if lockedUntil.Valid {
			user.LockedUntil = &lockedUntil.Time
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// CreateAdminUser cria um usuário admin customizado ou admin-n com senha aleatória de 64 caracteres, onde n é o próximo número disponível
func (s *UserStore) CreateAdminUser(customUsername, displayName string, role string) (string, string, string, string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>/?"
	password := make([]byte, 64)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := range password {
		password[i] = charset[rng.Intn(len(charset))]
	}

	var username string
	if customUsername != "" {
		username = customUsername
		// Verifica se já existe usuário com esse nome (ignorando deletados)
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 AND deleted_at IS NULL", username).Scan(&count)
		if err != nil {
			return "", "", "", "", err
		}
		if count > 0 {
			return "", "", "", "", errors.New("nome de usuário já existe")
		}
	} else {
		// Descobre o próximo número disponível para adminn
		var n int
		for {
			username = fmt.Sprintf("admin%d", n)
			var count int
			err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 AND deleted_at IS NULL", username).Scan(&count)
			if err != nil {
				return "", "", "", "", err
			}
			if count == 0 {
				break
			}
			n++
		}
	}
	if role == "" {
		role = "admin"
	}
	id, err := s.CreateUser(username, displayName, string(password), role)
	return id, username, displayName, string(password), err
}

// Função para desbloquear usuário manualmente
func (s *UserStore) UnlockUser(username string) error {
	_, err := s.db.Exec(`UPDATE users SET failed_attempts = 0, lock_level = 0, locked_until = NULL WHERE username = $1 AND deleted_at IS NULL`, username)
	return err
}

// BlockUser blocks a user account permanently until unlocked
func (s *UserStore) BlockUser(username string) error {
	// Set lock_level to max (3) and locked_until to far future (100 years)
	_, err := s.db.Exec(`UPDATE users SET lock_level = 3, locked_until = NOW() + INTERVAL '100 years' WHERE username = $1 AND deleted_at IS NULL`, username)
	return err
}
