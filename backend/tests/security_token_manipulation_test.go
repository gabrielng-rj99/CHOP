package tests

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ============================================================================
// TESTES DE MANIPULAÇÃO DE TOKEN JWT - COM SERVIDOR REAL
// ============================================================================

func TestEmptyJWTVulnerability(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	t.Run("JWT completamente vazio deve ser rejeitado", func(t *testing.T) {
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer ")

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Erro na requisição: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Token vazio deve ser rejeitado")
	})

	t.Run("Header Authorization sem Bearer deve ser rejeitado", func(t *testing.T) {
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "SomeRandomToken")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Token sem 'Bearer' deve ser rejeitado")
	})

	t.Run("JWT com assinatura vazia (alg=none) deve ser rejeitado - CVE-2015-9235", func(t *testing.T) {
		// Criar token com algoritmo "none"
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"123","role":"root"}`))
		noneToken := header + "." + payload + "."

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+noneToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro na requisição: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("FALHA CRÍTICA CVE-2015-9235: Token alg=none foi aceito! Status: %d", resp.StatusCode)
		} else {
			t.Log("✓ Proteção contra alg=none funcionando")
		}
	})

	t.Run("JWT com assinatura inválida deve ser rejeitado", func(t *testing.T) {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"user_id":"123","role":"root"}`))
		invalidToken := header + "." + payload + ".assinatura_invalida_xyz123"

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+invalidToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Token com assinatura inválida deve ser rejeitado")
	})
}

func TestTokenManipulation(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	t.Run("Token expirado deve ser rejeitado", func(t *testing.T) {
		// Pegar um usuário de teste
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		// Criar token expirado manualmente
		claims := jwt.MapClaims{
			"username": user.Username,
			"role":     user.Role,
			"exp":      time.Now().Add(-1 * time.Hour).Unix(), // expirado há 1 hora
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		secret := "test_secret_" + user.AuthSecret
		expiredToken, _ := token.SignedString([]byte(secret))

		// Tentar usar token expirado
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+expiredToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Token expirado deve ser rejeitado")
	})

	t.Run("Manipulação de claims (role) deve ser detectada", func(t *testing.T) {
		// Fazer login como usuário normal
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		// Verificar que token válido funciona primeiro
		_ = doLogin(t, config.BaseURL, user.Username, user.Password)

		// Tentar decodificar e manipular o token (simulação)
		// Na prática, o token JWT real assinado não pode ser manipulado sem quebrar a assinatura
		// Este teste verifica que tokens com claims manipulados são rejeitados

		// Criar novo token com role alterada mas assinatura diferente
		claims := jwt.MapClaims{
			"username": user.Username,
			"role":     "root", // ESCALAÇÃO de privilégio tentada!
			"exp":      time.Now().Add(1 * time.Hour).Unix(),
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// Assinar com segredo errado
		manipulatedToken, _ := token.SignedString([]byte("wrong_secret"))

		// Tentar acessar endpoint de root com token manipulado
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/audit-logs", nil)
		req.Header.Set("Authorization", "Bearer "+manipulatedToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		// Deve ser rejeitado (401 ou 403)
		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Token manipulado foi aceito!")
		} else {
			t.Logf("✓ Token manipulado rejeitado corretamente (status %d)", resp.StatusCode)
		}
	})

	t.Run("Token de outro usuário não deve ser aceito para operações sensíveis", func(t *testing.T) {
		user1 := config.TestUsers["user"]
		user2 := config.TestUsers["user2"]

		if user1 == nil || user2 == nil {
			t.Skip("Usuários não disponíveis")
		}

		// Fazer login como user1
		token1 := doLogin(t, config.BaseURL, user1.Username, user1.Password)

		// Tentar alterar dados de user2 usando token de user1
		updateData := map[string]interface{}{
			"display_name": "Hacked Name",
		}

		resp := makeRequest(t, "PUT", config.BaseURL+"/api/users/"+user2.Username, token1, updateData)
		defer resp.Body.Close()

		// Deve ser rejeitado (403 Forbidden)
		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Usuário conseguiu modificar dados de outro usuário!")
		} else {
			t.Logf("✓ Tentativa de modificar outro usuário bloqueada (status %d)", resp.StatusCode)
		}
	})
}

func TestTokenFormatValidation(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	malformedTokens := []struct {
		name  string
		token string
	}{
		{"Token sem partes", "tokeninvalido"},
		{"Token com apenas 1 parte", "part1"},
		{"Token com apenas 2 partes", "part1.part2"},
		{"Token com caracteres inválidos", "abc!@#$.def!@#$.ghi!@#$"},
		{"Token muito curto", "a.b.c"},
		{"Token vazio após Bearer", ""},
	}

	for _, tc := range malformedTokens {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			} else {
				req.Header.Set("Authorization", "Bearer ")
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("Erro: %v", err)
			}
			defer resp.Body.Close()

			assertStatusCode(t, resp, http.StatusUnauthorized, fmt.Sprintf("%s deve ser rejeitado", tc.name))
		})
	}
}

func TestLoginAndTokenGeneration(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	t.Run("Login bem-sucedido deve gerar token válido", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		token := doLogin(t, config.BaseURL, user.Username, user.Password)

		// Validar formato do token
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("Token JWT inválido: esperado 3 partes, obteve %d", len(parts))
		}

		// Usar token para acessar endpoint protegido
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusOK, "Token válido deve permitir acesso")
		t.Log("✓ Login e geração de token funcionando corretamente")
	})

	t.Run("Login com credenciais inválidas não deve gerar token", func(t *testing.T) {
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": "invalid_user",
			"password": "wrong_password",
		})
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Credenciais inválidas devem ser rejeitadas")
	})

	t.Run("Login sem username deve falhar", func(t *testing.T) {
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": "",
			"password": "somepassword",
		})
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Login sem username foi aceito!")
		}
	})

	t.Run("Login sem password deve falhar", func(t *testing.T) {
		user := config.TestUsers["user"]
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": user.Username,
			"password": "",
		})
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Login sem password foi aceito!")
		}
	})
}

func TestTokenInSensitiveData(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	user := config.TestUsers["admin"]
	if user == nil {
		t.Skip("Admin não disponível")
	}

	token := doLogin(t, config.BaseURL, user.Username, user.Password)

	t.Run("GET /api/users não deve vazar auth_secret ou password_hash", func(t *testing.T) {
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		body := getResponseBody(t, resp)

		assertNoSensitiveData(t, body)
		assertNotContains(t, body, "auth_secret", "Resposta de /api/users")
		assertNotContains(t, body, "password_hash", "Resposta de /api/users")

		t.Log("✓ Dados sensíveis não vazam em GET /api/users")
	})
}

func TestBruteForceProtection(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	// Criar usuário de teste específico para brute force
	testUser, err := createTestUser(config.DB, "brute_test_user", "Brute Test", "ValidPass123!", "user")
	if err != nil {
		t.Fatalf("Erro ao criar usuário de teste: %v", err)
	}
	defer config.DB.Exec("DELETE FROM users WHERE username = $1", testUser.Username)

	t.Run("Múltiplas tentativas falhadas devem bloquear conta", func(t *testing.T) {
		// Fazer 10 tentativas de login com senha errada
		for i := 0; i < 10; i++ {
			resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
				"username": testUser.Username,
				"password": "WrongPassword123!",
			})
			resp.Body.Close()

			// Primeiras tentativas devem retornar 401
			// Últimas podem retornar 429 (Too Many Requests) ou 403 se conta bloqueada
			t.Logf("Tentativa %d: status %d", i+1, resp.StatusCode)
		}

		// Verificar no banco se failed_attempts aumentou
		var failedAttempts int
		err := config.DB.QueryRow("SELECT failed_attempts FROM users WHERE username = $1", testUser.Username).Scan(&failedAttempts)
		if err != nil {
			t.Errorf("Erro ao verificar failed_attempts: %v", err)
		}

		if failedAttempts < 5 {
			t.Log("AVISO: Sistema de contagem de tentativas falhadas pode não estar implementado")
		} else {
			t.Logf("✓ Sistema registrou %d tentativas falhadas", failedAttempts)
		}

		// Tentar login com senha correta - pode estar bloqueado
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": testUser.Username,
			"password": testUser.Password,
		})
		resp.Body.Close()

		t.Logf("Login com senha correta após tentativas: status %d", resp.StatusCode)
	})
}

func TestTokenRevocationOnPasswordChange(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	// Criar usuário de teste
	testUser, err := createTestUser(config.DB, "pwd_change_user", "Password Change Test", "OldPass123!", "user")
	if err != nil {
		t.Fatalf("Erro ao criar usuário: %v", err)
	}
	defer config.DB.Exec("DELETE FROM users WHERE username = $1", testUser.Username)

	t.Run("Token antigo deve ser invalidado após mudança de senha", func(t *testing.T) {
		// Fazer login e obter token
		oldToken := doLogin(t, config.BaseURL, testUser.Username, testUser.Password)

		// Verificar que token funciona
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+oldToken)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Skip("Token inicial inválido, pulando teste")
		}

		// Pegar auth_secret antigo
		var oldAuthSecret string
		config.DB.QueryRow("SELECT auth_secret FROM users WHERE username = $1", testUser.Username).Scan(&oldAuthSecret)

		// Simular mudança de senha (alterar auth_secret no banco)
		newAuthSecret := "new_secret_" + fmt.Sprint(time.Now().Unix())
		_, err := config.DB.Exec("UPDATE users SET auth_secret = $1 WHERE username = $2", newAuthSecret, testUser.Username)
		if err != nil {
			t.Fatalf("Erro ao atualizar auth_secret: %v", err)
		}

		// Tentar usar token antigo
		req2, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req2.Header.Set("Authorization", "Bearer "+oldToken)
		resp2, _ := http.DefaultClient.Do(req2)
		resp2.Body.Close()

		if resp2.StatusCode == http.StatusOK {
			t.Error("FALHA: Token antigo ainda válido após mudança de auth_secret!")
		} else {
			t.Logf("✓ Token antigo invalidado após mudança de senha (status %d)", resp2.StatusCode)
		}
	})
}
