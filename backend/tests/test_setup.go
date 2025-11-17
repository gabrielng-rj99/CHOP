package tests

import (
	"database/sql"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"Contracts-Manager/backend/server"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// CONFIGURAÇÃO DE TESTE COM SERVIDOR REAL
// ============================================================================

// TestConfig armazena configuração para testes com servidor real
type TestConfig struct {
	Server      *server.Server
	DB          *sql.DB
	TestUsers   map[string]*TestUser
	HTTPServer  *httptest.Server
	BaseURL     string
	CleanupFunc func()
}

// TestUser armazena dados de usuário para testes
type TestUser struct {
	ID           string
	Username     string
	DisplayName  string
	Password     string
	PasswordHash string
	Role         string
	Token        string
	RefreshToken string
	AuthSecret   string
}

// ============================================================================
// CONEXÃO COM BANCO DE TESTE
// ============================================================================

// getTestDBConnection retorna conexão com banco de teste
func getTestDBConnection(t *testing.T) *sql.DB {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://test_user:test_password@localhost:65432/contracts_test?sslmode=disable"
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Skipf("Pulando teste - banco de teste não disponível: %v", err)
		return nil
	}

	db.SetConnMaxLifetime(time.Minute * 3)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(10)

	if err := db.Ping(); err != nil {
		t.Skipf("Pulando teste - não foi possível conectar ao banco: %v", err)
		return nil
	}

	return db
}

// ============================================================================
// POPULAÇÃO DO BANCO DE TESTE
// ============================================================================

// createTestUser cria um usuário de teste no banco
func createTestUser(db *sql.DB, username, displayName, password, role string) (*TestUser, error) {
	id := uuid.New().String()
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("erro ao gerar hash: %v", err)
	}

	authSecret := uuid.New().String()
	now := time.Now()

	_, err = db.Exec(`
		INSERT INTO users (id, username, display_name, password_hash, role, auth_secret, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, id, username, displayName, string(passwordHash), role, authSecret, now, now)

	if err != nil {
		return nil, fmt.Errorf("erro ao inserir usuário: %v", err)
	}

	return &TestUser{
		ID:           id,
		Username:     username,
		DisplayName:  displayName,
		Password:     password,
		PasswordHash: string(passwordHash),
		Role:         role,
		AuthSecret:   authSecret,
	}, nil
}

// createTestClients cria clientes de teste
func createTestClients(t *testing.T, db *sql.DB) {
	clients := []struct {
		name           string
		registrationID string
		email          string
	}{
		{"Test Client 1", "12345678901", "client1@test.com"},
		{"Test Client 2", "98765432109", "client2@test.com"},
		{"Test Client 3", "", "client3@test.com"},
	}

	for _, c := range clients {
		id := uuid.New().String()
		var regID *string
		if c.registrationID != "" {
			regID = &c.registrationID
		}

		_, err := db.Exec(`
			INSERT INTO clients (id, name, registration_id, email, status, created_at)
			VALUES ($1, $2, $3, $4, 'ativo', $5)
		`, id, c.name, regID, c.email, time.Now())

		if err != nil {
			t.Logf("Aviso: erro ao criar cliente de teste %s: %v", c.name, err)
		}
	}
}

// createTestCategories cria categorias e linhas de teste
func createTestCategories(t *testing.T, db *sql.DB) {
	categories := []struct {
		name  string
		lines []string
	}{
		{"Test Category 1", []string{"Line 1A", "Line 1B"}},
		{"Test Category 2", []string{"Line 2A", "Line 2B"}},
	}

	for _, cat := range categories {
		catID := uuid.New().String()
		_, err := db.Exec(`
			INSERT INTO categories (id, name, status)
			VALUES ($1, $2, 'ativo')
		`, catID, cat.name)

		if err != nil {
			t.Logf("Aviso: erro ao criar categoria de teste %s: %v", cat.name, err)
			continue
		}

		for _, lineName := range cat.lines {
			lineID := uuid.New().String()
			_, err := db.Exec(`
				INSERT INTO lines (id, name, category_id)
				VALUES ($1, $2, $3)
			`, lineID, lineName, catID)

			if err != nil {
				t.Logf("Aviso: erro ao criar linha de teste %s: %v", lineName, err)
			}
		}
	}
}

// populateTestDatabase popula o banco de dados com dados necessários para testes
func populateTestDatabase(t *testing.T, db *sql.DB) map[string]*TestUser {
	testUsers := make(map[string]*TestUser)

	cleanupTestData(t, db)

	users := []struct {
		key         string
		username    string
		displayName string
		password    string
		role        string
	}{
		{"root", "test_root", "Test Root User", "RootPass123!@#", "root"},
		{"admin", "test_admin", "Test Admin User", "AdminPass123!@#", "admin"},
		{"admin2", "test_admin2", "Test Admin 2", "Admin2Pass123!@#", "admin"},
		{"user", "test_user", "Test Regular User", "UserPass123!@#", "user"},
		{"user2", "test_user2", "Test User 2", "User2Pass123!@#", "user"},
		{"locked", "test_locked", "Test Locked User", "LockedPass123!@#", "user"},
	}

	for _, u := range users {
		user, err := createTestUser(db, u.username, u.displayName, u.password, u.role)
		if err != nil {
			t.Fatalf("Erro ao criar usuário de teste %s: %v", u.username, err)
		}
		testUsers[u.key] = user
	}

	// Bloquear usuário "locked" para testes de bloqueio
	_, err := db.Exec(`
		UPDATE users
		SET failed_attempts = 5,
		    lock_level = 2,
		    locked_until = $1
		WHERE username = 'test_locked'
	`, time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Erro ao bloquear usuário de teste: %v", err)
	}

	createTestClients(t, db)
	createTestCategories(t, db)

	return testUsers
}

// cleanupTestData limpa dados de teste do banco
func cleanupTestData(t *testing.T, db *sql.DB) {
	tables := []string{
		"audit_logs",
		"contracts",
		"dependents",
		"clients",
		"lines",
		"categories",
	}

	for _, table := range tables {
		_, err := db.Exec(fmt.Sprintf("DELETE FROM %s WHERE true", table))
		if err != nil {
			t.Logf("Aviso: erro ao limpar tabela %s: %v", table, err)
		}
	}

	_, err := db.Exec("DELETE FROM users WHERE username LIKE 'test_%'")
	if err != nil {
		t.Logf("Aviso: erro ao limpar usuários de teste: %v", err)
	}
}

// ============================================================================
// SETUP COMPLETO DO AMBIENTE DE TESTE COM SERVIDOR REAL
// ============================================================================

// setupTestEnvironment configura o ambiente de teste completo com servidor REAL
func setupTestEnvironment(t *testing.T) *TestConfig {
	db := getTestDBConnection(t)
	if db == nil {
		return nil
	}

	testUsers := populateTestDatabase(t, db)

	// Criar servidor REAL com stores conectados ao banco de teste
	srv := server.NewServer(db)

	// Criar servidor HTTP de teste usando o servidor REAL
	// Handler() retorna um http.Handler com todas as rotas configuradas
	httpServer := httptest.NewServer(srv.Handler())

	cleanup := func() {
		httpServer.Close()
		cleanupTestData(t, db)
		db.Close()
	}

	return &TestConfig{
		Server:      srv,
		DB:          db,
		TestUsers:   testUsers,
		HTTPServer:  httpServer,
		BaseURL:     httpServer.URL,
		CleanupFunc: cleanup,
	}
}

// ============================================================================
// HELPERS PARA TESTES
// ============================================================================

// generateMaliciousPayloads retorna payloads maliciosos para testes
func generateMaliciousPayloads() []string {
	return []string{
		"' OR '1'='1",
		"'; DROP TABLE users--",
		"' UNION SELECT * FROM users--",
		"1' AND 1=1--",
		"admin'--",
		"' OR 1=1--",
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"javascript:alert('XSS')",
		"<svg/onload=alert('XSS')>",
		"; ls -la",
		"| cat /etc/passwd",
		"&& whoami",
		"../../etc/passwd",
		"..\\..\\windows\\system32",
		"*)(uid=*))(|(uid=*",
		"{'$gt':''}",
		"{'$ne':null}",
		"test\x00.txt",
		"%s%s%s%s%s",
		"test\u0000",
		"test\uFEFF",
	}
}
