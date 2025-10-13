package store

import (
	"Licenses-Manager/backend/domain"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
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

// Validação de senha forte: 16+ caracteres, 1 número, 1 minúscula, 1 maiúscula, 1 símbolo
func ValidateStrongPassword(password string) error {
	if len(password) < 16 {
		return errors.New("a senha deve ter pelo menos 16 caracteres")
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
	if username == "" {
		return "", errors.New("nome de usuário não pode ser vazio")
	}
	if displayName == "" {
		return "", errors.New("display name não pode ser vazio")
	}
	if role == "" {
		role = "user"
	}
	if err := ValidateStrongPassword(password); err != nil {
		return "", err
	}

	// Verifica se já existe usuário com esse nome
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
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

	sqlStatement := `INSERT INTO users (id, username, display_name, password_hash, created_at, role) VALUES (?, ?, ?, ?, ?, ?)`
	_, err = s.db.Exec(sqlStatement, id, username, displayName, passwordHash, createdAt, role)
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
	err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", newUsername).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return errors.New("nome de usuário já existe")
	}
	// Verifica se o usuário atual é admin
	var adminInt int
	err = s.db.QueryRow("SELECT admin FROM users WHERE username = ?", currentUsername).Scan(&adminInt)
	if err != nil {
		return errors.New("usuário atual não encontrado")
	}
	if adminInt != 1 {
		return errors.New("apenas usuários admin podem alterar seu próprio username")
	}
	sqlStatement := `UPDATE users SET username = ? WHERE username = ?`
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
func (s *UserStore) AuthenticateUser(username, password string) (*domain.User, error) {
	if username == "" || password == "" {
		return nil, errors.New("usuário e senha são obrigatórios")
	}

	// Não precisa gerar o hash manualmente aqui

	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role FROM users WHERE username = ?`
	row := s.db.QueryRow(sqlStatement, username)

	var user domain.User
	err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.CreatedAt, &user.Role)
	if err != nil {
		return nil, errors.New("usuário não encontrado")
	}
	// Verifica o hash bcrypt
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return nil, errors.New("senha incorreta")
	}
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
	sqlStatement := `UPDATE users SET password_hash = ? WHERE username = ?`
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
	if newDisplayName == "" {
		return errors.New("display name não pode ser vazio")
	}
	sqlStatement := `UPDATE users SET display_name = ? WHERE username = ?`
	result, err := s.db.Exec(sqlStatement, newDisplayName, username)
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
	err := s.db.QueryRow("SELECT role FROM users WHERE username = ?", requesterUsername).Scan(&requesterRole)
	if err != nil {
		return errors.New("usuário solicitante não encontrado")
	}
	if requesterRole != "full_admin" {
		return errors.New("apenas usuários com role 'full_admin' podem alterar o role de outros usuários")
	}
	sqlStatement := `UPDATE users SET role = ? WHERE username = ?`
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
	sqlStatement := `SELECT id, username, display_name, password_hash, created_at, role FROM users`
	rows, err := s.db.Query(sqlStatement)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []domain.User
	for rows.Next() {
		var user domain.User
		err := rows.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.CreatedAt, &user.Role)
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
func (s *UserStore) CreateAdminUser(customUsername, displayName string, role string) (string, string, string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>/?"
	password := make([]byte, 64)
	rand.Seed(time.Now().UnixNano())
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}

	var username string
	if customUsername != "" {
		username = customUsername
		// Verifica se já existe usuário com esse nome
		var count int
		err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
		if err != nil {
			return "", "", "", err
		}
		if count > 0 {
			return "", "", "", errors.New("nome de usuário já existe")
		}
	} else {
		// Descobre o próximo número disponível para admin-n
		var n int
		for {
			username = fmt.Sprintf("admin-%d", n)
			var count int
			err := s.db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count)
			if err != nil {
				return "", "", "", err
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
	_, err := s.CreateUser(username, displayName, string(password), role)
	return username, displayName, string(password), err
}
