package store

import (
	"Contracts-Manager/backend/domain"
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
	trimmedUsername, err := ValidateName(username, 255)
	if err != nil {
		return "", err
	}
	trimmedDisplayName, errDisplay := ValidateName(displayName, 255)
	if errDisplay != nil {
		return "", errDisplay
	}
	if role == "" {
		role = "user"
	}
	if err := ValidateStrongPassword(password); err != nil {
		return "", err
	}

	// Verifica se já existe usuário com esse nome
	var count int
	err = s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", trimmedUsername).Scan(&count)
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

	sqlStatement := `INSERT INTO users (id, username, display_name, password_hash, created_at, role) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err = s.db.Exec(sqlStatement, id, trimmedUsername, trimmedDisplayName, passwordHash, createdAt, role)
	if err != nil {
		return "", err
	}
	return id, nil
}

// Permite que um admin altere seu próprio username
func (s *UserStore) UpdateUsername(currentUsername, newUsername string) error {
	if newUsername == "" {
		return errors.New("novo nome de usuário não pode ser vazio")
	}
	// Verifica se já existe usuário com esse nome
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", newUsername).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("nome de usuário já existe")
	}
	// Verifica se o usuário atual é admin
	var role string
	err = s.db.QueryRow("SELECT role FROM users WHERE username = $1", currentUsername).Scan(&role)
	if err != nil {
		return errors.New("usuário atual não encontrado")
	}
	if role != "admin" && role != "full_admin" {
		return errors.New("apenas usuários admin podem alterar seu próprio username")
	}
	sqlStatement := `UPDATE users SET username = $1 WHERE username = $2`
	result, err := s.db.Exec(sqlStatement, newUsername, currentUsername)
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

	// Busca todos os campos necessários para brute-force
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role, failed_attempts, lock_level, locked_until FROM users WHERE username = $1`
	row := s.db.QueryRow(sqlStatement, username)

	var user domain.User
	var failedAttempts, lockLevel int
	var lockedUntil sql.NullTime
	err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.CreatedAt, &user.Role, &failedAttempts, &lockLevel, &lockedUntil)
	if err != nil {
		fmt.Println("Erro no Scan da autenticação:", err)
		return nil, errors.New("usuário não encontrado")
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
	sqlStatement := `UPDATE users SET password_hash = $1 WHERE username = $2`
	result, err := s.db.Exec(sqlStatement, passwordHash, username)
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
	sqlStatement := `UPDATE users SET display_name = $1 WHERE username = $2`
	result, err := s.db.Exec(sqlStatement, trimmedDisplayName, username)
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

// Edita o role de um usuário, só pode ser chamada por full_admin
func (s *UserStore) EditUserRole(requesterUsername, targetUsername, newRole string) error {
	// Verifica se o requester é full_admin
	var requesterRole string
	err := s.db.QueryRow("SELECT role FROM users WHERE username = $1", requesterUsername).Scan(&requesterRole)
	if err != nil {
		return errors.New("usuário solicitante não encontrado")
	}
	if requesterRole != "full_admin" {
		return errors.New("apenas usuários com role 'full_admin' podem alterar o role de outros usuários")
	}
	sqlStatement := `UPDATE users SET role = $1 WHERE username = $2`
	result, err := s.db.Exec(sqlStatement, newRole, targetUsername)
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

// ListUsers retorna todos os usuários cadastrados, incluindo os hashes das senhas
func (s *UserStore) ListUsers() ([]domain.User, error) {
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role, failed_attempts, lock_level, locked_until FROM users`
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
		err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.CreatedAt, &user.Role, &failedAttempts, &lockLevel, &lockedUntil)
		if err != nil {
			return nil, err
		}
		// Você pode adicionar esses campos ao struct User se quiser exibir no CLI
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

// GetUsersByName busca usuários por nome de usuário ou display name (case-insensitive, parcial)
func (s *UserStore) GetUsersByName(name string) ([]domain.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("name cannot be empty")
	}
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role, failed_attempts, lock_level, locked_until FROM users WHERE LOWER(username) LIKE LOWER($1) OR LOWER(display_name) LIKE LOWER($2)`
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
		err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.CreatedAt, &user.Role, &failedAttempts, &lockLevel, &lockedUntil)
		if err != nil {
			return nil, err
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
		// Verifica se já existe usuário com esse nome
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", username).Scan(&count)
		if err != nil {
			return "", "", "", "", err
		}
		if count > 0 {
			return "", "", "", "", errors.New("nome de usuário já existe")
		}
	} else {
		// Descobre o próximo número disponível para admin-n
		var n int
		for {
			username = fmt.Sprintf("admin-%d", n)
			var count int
			err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = $1", username).Scan(&count)
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
	_, err := s.db.Exec(`UPDATE users SET failed_attempts = 0, lock_level = 0, locked_until = NULL WHERE username = $1`, username)
	return err
}
