/*
 * Client Hub Open Project
 * Copyright (C) 2025 Client Hub Contributors
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

package userstore

import (
	domain "Open-Generic-Hub/backend/domain"
	"Open-Generic-Hub/backend/repository"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// UserStore gerencia operações de usuários (login/cadastro)
type UserStore struct {
	db repository.DBInterface
}

// NewUserStore cria uma nova instância de UserStore
func NewUserStore(db repository.DBInterface) *UserStore {
	return &UserStore{
		db: db,
	}
}

// Validação de senha forte com tamanho mínimo variável
func ValidateStrongPassword(password string, minLength int) error {
	if len(password) < minLength {
		return fmt.Errorf("a senha deve ter pelo menos %d caracteres", minLength)
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

// GetMinPasswordLengthForRole retorna o tamanho mínimo de senha para um role
func GetMinPasswordLengthForRole(role string) int {
	switch strings.ToLower(role) {
	case "root":
		return 24
	case "admin":
		return 20
	case "user":
		return 16
	case "viewer":
		return 12
	default:
		return 16
	}
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
	if err := repository.ValidateUsername(username); err != nil {
		return "", err
	}
	trimmedUsername := strings.TrimSpace(username)
	trimmedDisplayName, errDisplay := repository.ValidateName(displayName, 255)
	if errDisplay != nil {
		return "", errDisplay
	}

	// Validate role exists in database and is active
	if role == "" {
		role = "user"
	}

	if err := s.ValidateRoleExists(role); err != nil {
		return "", err
	}

	minLength := GetMinPasswordLengthForRole(role)
	if err := ValidateStrongPassword(password, minLength); err != nil {
		return "", err
	}

	// Verifica se já existe usuário com esse nome (ignorando deletados)
	var count int
	queryErr := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1 AND deleted_at IS NULL", trimmedUsername).Scan(&count)
	if queryErr != nil {
		return "", queryErr
	}
	if count > 0 {
		return "", errors.New("nome de usuário já existe")
	}

	id := uuid.New().String()
	passwordHash, hashErr := HashPassword(password)
	if hashErr != nil {
		return "", hashErr
	}
	createdAt := time.Now()
	updatedAt := createdAt

	// Gerar auth_secret como SHA256(UUID + updatedAt)
	authSecretRaw := id + updatedAt.Format(time.RFC3339Nano)
	authSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(authSecretRaw)))

	sqlStatement := `INSERT INTO users (id, username, display_name, password_hash, created_at, updated_at, role, deleted_at, auth_secret) VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8)`
	_, execErr := s.db.Exec(sqlStatement, id, trimmedUsername, trimmedDisplayName, passwordHash, createdAt, updatedAt, role, authSecret)
	if execErr != nil {
		return "", execErr
	}
	return id, nil
}

// ValidateRoleExists verifica se uma role existe e está ativa no banco de dados
func (s *UserStore) ValidateRoleExists(roleName string) error {
	if strings.TrimSpace(roleName) == "" {
		return errors.New("role não pode estar vazio")
	}

	query := `
		SELECT is_active FROM roles
		WHERE name = $1
	`

	var isActive bool
	err := s.db.QueryRow(query, roleName).Scan(&isActive)

	if err == sql.ErrNoRows {
		return fmt.Errorf("invalid role: role '%s' não existe", roleName)
	}
	if err != nil {
		return fmt.Errorf("erro ao validar role: %w", err)
	}

	if !isActive {
		return fmt.Errorf("invalid role: role '%s' não está ativa", roleName)
	}

	return nil
}

// Permite que um admin altere seu próprio username
// GetUserByID busca um usuário pelo ID
func (s *UserStore) GetUserByID(userID string) (*domain.User, error) {
	var user domain.User
	var username, displayName, role, passwordHash sql.NullString
	var deletedAt, lockedUntil sql.NullTime

	query := `SELECT id, username, display_name, password_hash, created_at, updated_at, deleted_at, role, failed_attempts, lock_level, locked_until, auth_secret FROM users WHERE id = $1`
	err := s.db.QueryRow(query, userID).Scan(
		&user.ID,
		&username,
		&displayName,
		&passwordHash,
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
// Removed progressive brute force levels - now using configurable single level

func (s *UserStore) AuthenticateUser(username, password string) (*domain.User, error) {
	if username == "" || password == "" {
		return nil, errors.New("usuário e senha são obrigatórios")
	}

	// Load progressive lockout levels from system settings
	level1Attempts := 3
	level1Duration := 300 // 5 min
	level2Attempts := 5
	level2Duration := 900 // 15 min
	level3Attempts := 10
	level3Duration := 3600 // 1 hour
	manualLockAttempts := 15

	rows, err := s.db.Query(`
		SELECT key, value FROM system_settings
		WHERE key IN (
			'security.lock_level_1_attempts', 'security.lock_level_1_duration',
			'security.lock_level_2_attempts', 'security.lock_level_2_duration',
			'security.lock_level_3_attempts', 'security.lock_level_3_duration',
			'security.lock_level_manual_attempts'
		)
	`)
	if err == nil && rows != nil {
		defer rows.Close()
		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err == nil {
				switch key {
				case "security.lock_level_1_attempts":
					if v, e := strconv.Atoi(value); e == nil && v >= 1 && v <= 20 {
						level1Attempts = v
					}
				case "security.lock_level_1_duration":
					if v, e := strconv.Atoi(value); e == nil && v >= 60 && v <= 3600 {
						level1Duration = v
					}
				case "security.lock_level_2_attempts":
					if v, e := strconv.Atoi(value); e == nil && v >= 1 && v <= 30 {
						level2Attempts = v
					}
				case "security.lock_level_2_duration":
					if v, e := strconv.Atoi(value); e == nil && v >= 60 && v <= 7200 {
						level2Duration = v
					}
				case "security.lock_level_3_attempts":
					if v, e := strconv.Atoi(value); e == nil && v >= 1 && v <= 50 {
						level3Attempts = v
					}
				case "security.lock_level_3_duration":
					if v, e := strconv.Atoi(value); e == nil && v >= 60 && v <= 86400 {
						level3Duration = v
					}
				case "security.lock_level_manual_attempts":
					if v, e := strconv.Atoi(value); e == nil && v >= 10 && v <= 100 {
						manualLockAttempts = v
					}
				}
			}
		}
	}

	// Busca todos os campos necessários (ignorando usuários deletados)
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, updated_at, role, failed_attempts, lock_level, locked_until, auth_secret FROM users WHERE username = $1 AND deleted_at IS NULL`
	row := s.db.QueryRow(sqlStatement, username)

	var user domain.User
	var failedAttempts, lockLevel int
	var lockedUntil sql.NullTime
	var username_ptr sql.NullString
	var displayName sql.NullString
	var role sql.NullString
	var authSecret sql.NullString

	err = row.Scan(&user.ID, &username_ptr, &displayName, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt, &role, &failedAttempts, &lockLevel, &lockedUntil, &authSecret)
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
	if authSecret.Valid {
		user.AuthSecret = authSecret.String
	}

	// ALWAYS use UTC to avoid timezone issues with database
	now := time.Now().UTC()

	// Ensure locked_until from DB is also in UTC
	var lockedUntilUTC time.Time
	if lockedUntil.Valid {
		lockedUntilUTC = lockedUntil.Time.UTC()
	}

	// DEBUG: Log all lock-related values
	fmt.Printf("🔍 DEBUG Login Check: user=%s, lockedUntil.Valid=%v, lock_level=%d, failed_attempts=%d\n",
		username, lockedUntil.Valid, lockLevel, failedAttempts)

	if lockedUntil.Valid {
		fmt.Printf("🔍 DEBUG Time Check: locked_until=%s, now=%s, isBefore=%v\n",
			lockedUntilUTC.Format(time.RFC1123), now.Format(time.RFC1123), now.Before(lockedUntilUTC))
	}

	if lockedUntil.Valid && now.Before(lockedUntilUTC) {
		fmt.Printf("🚫 Login bloqueado: user=%s, lock_level=%d, locked_until=%s, now=%s\n",
			username, lockLevel, lockedUntilUTC.Format(time.RFC1123), now.Format(time.RFC1123))
		// Check if this is a manual lock (lock_level = 3 with far future date)
		// Manual locks should show a specific message
		if lockLevel >= 3 && lockedUntilUTC.After(now.Add(30*24*time.Hour)) {
			return nil, fmt.Errorf("Conta bloqueada permanentemente por um administrador. Contate o suporte.")
		}
		return nil, fmt.Errorf("Conta bloqueada até %s por múltiplas tentativas. Tente novamente depois.", lockedUntilUTC.Format(time.RFC1123))
	}

	// Verifica o hash bcrypt
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		// Falha: incrementa tentativas e aplica bloqueio progressivo
		failedAttempts++
		newLockLevel := lockLevel
		var lockUntil time.Time

		if failedAttempts >= manualLockAttempts {
			// Bloqueio manual permanente (por 1 ano - requer admin unlock)
			newLockLevel = 4
			lockUntil = now.Add(365 * 24 * time.Hour)
			result, err := s.db.Exec(
				`UPDATE users SET failed_attempts = $1, lock_level = $2, locked_until = $3 WHERE username = $4`,
				failedAttempts, newLockLevel, lockUntil, username,
			)
			if err != nil {
				fmt.Printf("❌ ERRO ao bloquear usuário (nível 4): %v\n", err)
			} else {
				rows, _ := result.RowsAffected()
				fmt.Printf("🔒 Bloqueio nível 4 aplicado: user=%s, attempts=%d, locked_until=%s (rows affected: %d)\n",
					username, failedAttempts, lockUntil.Format(time.RFC1123), rows)
			}
			return nil, fmt.Errorf("Conta bloqueada permanentemente por segurança. Contate o administrador.")
		} else if failedAttempts >= level3Attempts {
			// Nível 3: bloqueio severo (1 hora)
			newLockLevel = 3
			lockUntil = now.Add(time.Duration(level3Duration) * time.Second)
			result, err := s.db.Exec(
				`UPDATE users SET failed_attempts = $1, lock_level = $2, locked_until = $3 WHERE username = $4`,
				failedAttempts, newLockLevel, lockUntil, username,
			)
			if err != nil {
				fmt.Printf("❌ ERRO ao bloquear usuário (nível 3): %v\n", err)
			} else {
				rows, _ := result.RowsAffected()
				fmt.Printf("🔒 Bloqueio nível 3 aplicado: user=%s, attempts=%d, locked_until=%s (rows affected: %d)\n",
					username, failedAttempts, lockUntil.Format(time.RFC1123), rows)
			}
			return nil, fmt.Errorf("Conta bloqueada até %s (Nível 3 - bloqueio severo). Tente novamente depois.", lockUntil.Format(time.RFC1123))
		} else if failedAttempts >= level2Attempts {
			// Nível 2: bloqueio médio (15 min)
			newLockLevel = 2
			lockUntil = now.Add(time.Duration(level2Duration) * time.Second)
			result, err := s.db.Exec(
				`UPDATE users SET failed_attempts = $1, lock_level = $2, locked_until = $3 WHERE username = $4`,
				failedAttempts, newLockLevel, lockUntil, username,
			)
			if err != nil {
				fmt.Printf("❌ ERRO ao bloquear usuário (nível 2): %v\n", err)
			} else {
				rows, _ := result.RowsAffected()
				fmt.Printf("🔒 Bloqueio nível 2 aplicado: user=%s, attempts=%d, locked_until=%s (rows affected: %d)\n",
					username, failedAttempts, lockUntil.Format(time.RFC1123), rows)
			}
			return nil, fmt.Errorf("Conta bloqueada até %s (Nível 2 - bloqueio médio). Tente novamente depois.", lockUntil.Format(time.RFC1123))
		} else if failedAttempts >= level1Attempts {
			// Nível 1: bloqueio inicial (5 min)
			newLockLevel = 1
			lockUntil = now.Add(time.Duration(level1Duration) * time.Second)
			result, err := s.db.Exec(
				`UPDATE users SET failed_attempts = $1, lock_level = $2, locked_until = $3 WHERE username = $4`,
				failedAttempts, newLockLevel, lockUntil, username,
			)
			if err != nil {
				fmt.Printf("❌ ERRO ao bloquear usuário (nível 1): %v\n", err)
			} else {
				rows, _ := result.RowsAffected()
				fmt.Printf("🔒 Bloqueio nível 1 aplicado: user=%s, attempts=%d, locked_until=%s (rows affected: %d)\n",
					username, failedAttempts, lockUntil.Format(time.RFC1123), rows)
			}
			return nil, fmt.Errorf("Conta bloqueada até %s (Nível 1 - bloqueio inicial). Tente novamente depois.", lockUntil.Format(time.RFC1123))
		} else {
			// Apenas incrementa tentativas, sem bloquear ainda
			result, err := s.db.Exec(`UPDATE users SET failed_attempts = $1 WHERE username = $2`, failedAttempts, username)
			if err != nil {
				fmt.Printf("❌ ERRO ao incrementar tentativas: %v\n", err)
			} else {
				rows, _ := result.RowsAffected()
				fmt.Printf("📝 Tentativas incrementadas: user=%s, attempts=%d (rows affected: %d)\n", username, failedAttempts, rows)
			}
		}
		return nil, errors.New("usuário ou senha inválidos")
	}

	// DEBUG: Log successful login attempt
	fmt.Printf("🔍 DEBUG Senha correta: user=%s, lock_level=%d, lockedUntil.Valid=%v\n", username, lockLevel, lockedUntil.Valid)

	// Sucesso: reseta APENAS bloqueios automáticos temporários
	// NÃO limpa bloqueios manuais permanentes (lock_level = 3 com data futura > 30 dias)
	if lockLevel >= 3 && lockedUntil.Valid && lockedUntilUTC.After(now.Add(30*24*time.Hour)) {
		// Este é um bloqueio MANUAL permanente - não deve ser limpo
		fmt.Printf("🚫 Bloqueio manual permanente detectado: user=%s\n", username)
		return nil, fmt.Errorf("Conta bloqueada permanentemente por um administrador. Contate o suporte.")
	}

	// IMPORTANTE: Só limpa bloqueios se o tempo já expirou ou se não há bloqueio
	if lockedUntil.Valid && now.Before(lockedUntilUTC) {
		// Usuário ainda está bloqueado - NÃO deveria chegar aqui!
		fmt.Printf("⚠️ ERRO DE LÓGICA: Login com senha correta mas usuário ainda bloqueado! user=%s, locked_until=%s, now=%s\n",
			username, lockedUntilUTC.Format(time.RFC1123), now.Format(time.RFC1123))
		return nil, fmt.Errorf("Conta bloqueada até %s. Tente novamente depois.", lockedUntilUTC.Format(time.RFC1123))
	}

	// Limpa bloqueios automáticos temporários (expirados ou inexistentes)
	result, err := s.db.Exec(`UPDATE users SET failed_attempts = 0, lock_level = 0, locked_until = NULL WHERE username = $1`, username)
	if err != nil {
		fmt.Printf("❌ ERRO ao limpar bloqueio temporário: %v\n", err)
	} else {
		rows, _ := result.RowsAffected()
		if lockedUntil.Valid {
			fmt.Printf("✅ Login bem-sucedido: user=%s, bloqueio EXPIRADO limpo (rows affected: %d)\n", username, rows)
		} else {
			fmt.Printf("✅ Login bem-sucedido: user=%s, sem bloqueio prévio (rows affected: %d)\n", username, rows)
		}
	}
	return &user, nil
}

// Edita a senha de um usuário existente, validando e salvando hasheada
func (s *UserStore) EditUserPassword(username, newPassword string) error {
	// Buscar o role do usuário para validar a senha
	var role string
	err := s.db.QueryRow("SELECT role FROM users WHERE username = $1 AND deleted_at IS NULL", username).Scan(&role)
	if err != nil {
		return errors.New("usuário não encontrado")
	}

	minLength := GetMinPasswordLengthForRole(role)
	if err := ValidateStrongPassword(newPassword, minLength); err != nil {
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
	trimmedDisplayName, err := repository.ValidateName(newDisplayName, 255)
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
	// Use TIMEZONE('UTC', NOW()) to ensure UTC timestamp
	lockedUntil := time.Now().UTC().Add(100 * 365 * 24 * time.Hour)
	_, err := s.db.Exec(`UPDATE users SET lock_level = 3, locked_until = $1 WHERE username = $2 AND deleted_at IS NULL`, lockedUntil, username)
	return err
}
