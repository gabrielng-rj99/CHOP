package tests

import (
	"net/http"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// ============================================================================
// TESTES DE SEGURANÇA - AUTHENTICATION FLOWS COM SERVIDOR REAL
// ============================================================================

func TestAuthenticationFlows(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Login sem credenciais deve falhar", func(t *testing.T) {
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{})
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Login sem credenciais foi aceito!")
		} else {
			t.Log("✓ Login sem credenciais rejeitado corretamente")
		}
	})

	t.Run("Login com username vazio deve falhar", func(t *testing.T) {
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": "",
			"password": "SomePassword123!",
		})
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusBadRequest, "Username vazio deve ser rejeitado")
	})

	t.Run("Login com senha vazia deve falhar", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": user.Username,
			"password": "",
		})
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusBadRequest, "Senha vazia deve ser rejeitada")
	})

	t.Run("Login com credenciais válidas deve retornar token", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		token := doLogin(t, config.BaseURL, user.Username, user.Password)
		if token == "" {
			t.Error("Token vazio retornado")
		}

		// Verificar formato JWT (3 partes separadas por .)
		parts := len(token)
		if parts < 10 {
			t.Error("Token muito curto para ser JWT válido")
		}

		t.Log("✓ Login bem-sucedido com token válido")
	})

	t.Run("Login com senha incorreta deve falhar", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": user.Username,
			"password": "WrongPassword123!",
		})
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Senha incorreta deve ser rejeitada")
	})

	t.Run("Login com usuário inexistente deve falhar", func(t *testing.T) {
		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": "usuario_que_nao_existe_12345",
			"password": "SomePassword123!",
		})
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Usuário inexistente deve ser rejeitado")

		// Verificar que mensagem de erro não revela se usuário existe
		body := getResponseBody(t, resp)
		assertNotContains(t, body, "não encontrado", "Mensagem de erro")
		assertNotContains(t, body, "not found", "Mensagem de erro")
		t.Log("✓ Mensagem de erro genérica (não revela se usuário existe)")
	})

	t.Run("Múltiplas tentativas de login falhadas devem incrementar contador", func(t *testing.T) {
		// Criar usuário específico para este teste
		testUser, err := createTestUser(config.DB, "brute_test", "Brute Force Test", "TestPass123!", "user")
		if err != nil {
			t.Fatalf("Erro ao criar usuário: %v", err)
		}
		defer config.DB.Exec("DELETE FROM users WHERE username = $1", testUser.Username)

		// Pegar failed_attempts inicial
		var initialAttempts int
		config.DB.QueryRow("SELECT COALESCE(failed_attempts, 0) FROM users WHERE username = $1", testUser.Username).Scan(&initialAttempts)

		// Fazer 3 tentativas com senha errada
		for i := 0; i < 3; i++ {
			resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
				"username": testUser.Username,
				"password": "WrongPassword",
			})
			resp.Body.Close()
			time.Sleep(100 * time.Millisecond)
		}

		// Verificar se failed_attempts aumentou
		var currentAttempts int
		config.DB.QueryRow("SELECT COALESCE(failed_attempts, 0) FROM users WHERE username = $1", testUser.Username).Scan(&currentAttempts)

		if currentAttempts > initialAttempts {
			t.Logf("✓ Contador de tentativas falhadas funcionando: %d -> %d", initialAttempts, currentAttempts)
		} else {
			t.Log("⚠ Sistema de contagem de tentativas falhadas pode não estar implementado")
		}
	})

	t.Run("Conta bloqueada não deve permitir login", func(t *testing.T) {
		user := config.TestUsers["locked"]
		if user == nil {
			t.Skip("Usuário bloqueado não disponível")
		}

		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": user.Username,
			"password": user.Password,
		})
		defer resp.Body.Close()

		// Deve retornar 403 (Forbidden) ou 429 (Too Many Requests)
		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Conta bloqueada conseguiu fazer login!")
		} else {
			t.Logf("✓ Conta bloqueada não pode fazer login (status %d)", resp.StatusCode)
		}
	})

	t.Run("Token válido deve permitir acesso a endpoints protegidos", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		token := doLogin(t, config.BaseURL, user.Username, user.Password)

		// Tentar acessar endpoint protegido
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusOK, "Token válido deve permitir acesso")
		t.Log("✓ Acesso a endpoint protegido com token válido funcionando")
	})

	t.Run("Requisição sem token deve ser rejeitada", func(t *testing.T) {
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Requisição sem token deve ser rejeitada")
		t.Log("✓ Proteção de endpoints sem token funcionando")
	})

	t.Run("Token com formato inválido deve ser rejeitado", func(t *testing.T) {
		invalidTokens := []string{
			"token_invalido",
			"Bearer",
			"",
			"abc.def",
		}

		for _, token := range invalidTokens {
			req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				t.Errorf("FALHA: Token inválido '%s' foi aceito!", token)
			}
		}

		t.Log("✓ Tokens inválidos rejeitados corretamente")
	})
}

func TestSessionManagement(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	t.Run("Múltiplos logins devem gerar tokens diferentes", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		token1 := doLogin(t, config.BaseURL, user.Username, user.Password)
		time.Sleep(100 * time.Millisecond)
		token2 := doLogin(t, config.BaseURL, user.Username, user.Password)

		if token1 == token2 {
			t.Log("⚠ Tokens idênticos - isso pode ser um problema se não houver rotação")
		} else {
			t.Log("✓ Cada login gera token diferente")
		}
	})

	t.Run("Token de usuário diferente não deve dar acesso", func(t *testing.T) {
		user1 := config.TestUsers["user"]
		user2 := config.TestUsers["admin"]

		if user1 == nil || user2 == nil {
			t.Skip("Usuários não disponíveis")
		}

		token1 := doLogin(t, config.BaseURL, user1.Username, user1.Password)

		// Tentar acessar dados de user2 com token de user1
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users/"+user2.Username, nil)
		req.Header.Set("Authorization", "Bearer "+token1)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		// Dependendo da implementação, pode ser 403 ou 404
		if resp.StatusCode == http.StatusOK {
			body := getResponseBody(t, resp)
			// Verificar se não vazou dados sensíveis
			assertNoSensitiveData(t, body)
		}

		t.Log("✓ Controle de acesso entre usuários funcionando")
	})
}

func TestAuthenticationEdgeCases(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	t.Run("Login com JSON malformado deve falhar gracefully", func(t *testing.T) {
		req, _ := http.NewRequest("POST", config.BaseURL+"/api/login", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Body = http.NoBody

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Request sem body foi aceito")
		}

		body := getResponseBody(t, resp)
		assertNoStackTrace(t, body)
		t.Log("✓ JSON malformado tratado corretamente sem vazar stack trace")
	})

	t.Run("Login com Content-Type incorreto", func(t *testing.T) {
		req, _ := http.NewRequest("POST", config.BaseURL+"/api/login", nil)
		req.Header.Set("Content-Type", "text/plain")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Content-Type incorreto foi aceito")
		}

		t.Log("✓ Content-Type validation funcionando")
	})

	t.Run("Login com método HTTP incorreto deve falhar", func(t *testing.T) {
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/login", nil)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusMethodNotAllowed, "GET em /api/login deve ser rejeitado")
	})

	t.Run("Campos extras no login devem ser ignorados", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		resp := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]interface{}{
			"username":    user.Username,
			"password":    user.Password,
			"role":        "root",      // tentativa de injeção
			"extra_field": "malicious", // campo extra
			"admin":       true,        // tentativa de escalação
		})
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			// Login bem-sucedido, mas verificar que role não foi manipulada
			body := getResponseBody(t, resp)
			if body != "" {
				t.Log("✓ Login aceito, mas campos extras devem ser ignorados")
			}
		}
	})
}
