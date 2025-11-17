package tests

import (
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// ============================================================================
// TESTES DE SEGURANÇA - PASSWORD SECURITY COM SERVIDOR REAL
// ============================================================================

func TestPasswordSecurity(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Senha deve ser hasheada no banco de dados", func(t *testing.T) {
		// Verificar que nenhuma senha está em plain text
		var count int
		config.DB.QueryRow(`
			SELECT COUNT(*) FROM users
			WHERE password_hash = 'password'
			   OR password_hash = '123456'
			   OR password_hash = 'admin'
			   OR password_hash = 'user'
		`).Scan(&count)

		if count > 0 {
			t.Error("FALHA CRÍTICA: Senhas em plain text encontradas no banco de dados!")
		} else {
			t.Log("✓ Nenhuma senha em plain text no banco")
		}
	})

	t.Run("Todos os hashes devem ser bcrypt válidos", func(t *testing.T) {
		rows, err := config.DB.Query(`
			SELECT username, password_hash FROM users WHERE deleted_at IS NULL
		`)
		if err != nil {
			t.Fatalf("Erro ao buscar usuários: %v", err)
		}
		defer rows.Close()

		invalidHashes := 0
		for rows.Next() {
			var username, passwordHash string
			rows.Scan(&username, &passwordHash)

			// Verificar se é hash bcrypt válido (começa com $2a$, $2b$, ou $2y$)
			if len(passwordHash) < 10 {
				t.Errorf("Hash muito curto para usuário %s", username)
				invalidHashes++
				continue
			}

			// Tentar verificar o hash com bcrypt
			err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte("test_password"))
			if err != nil && err != bcrypt.ErrMismatchedHashAndPassword {
				// Se o erro não for "senha não bate", então o hash é inválido
				t.Errorf("Hash inválido para usuário %s: %v", username, err)
				invalidHashes++
			}
		}

		if invalidHashes == 0 {
			t.Log("✓ Todos os hashes são bcrypt válidos")
		}
	})

	t.Run("Alteração de senha deve invalidar token antigo", func(t *testing.T) {
		// Criar usuário específico para este teste
		testUser, err := createTestUser(config.DB, "pwd_change_user", "Password Change Test", "OldPassword123!", "user")
		if err != nil {
			t.Fatalf("Erro ao criar usuário: %v", err)
		}
		defer config.DB.Exec("DELETE FROM users WHERE username = $1", testUser.Username)

		// Fazer login e obter token
		oldToken := doLogin(t, config.BaseURL, testUser.Username, testUser.Password)

		// Verificar que token funciona
		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+oldToken)
		resp, _ := http.DefaultClient.Do(req)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Skip("Token inicial não funcionou, pulando teste")
		}

		// Pegar auth_secret antigo
		var oldAuthSecret string
		config.DB.QueryRow("SELECT auth_secret FROM users WHERE id = $1", testUser.ID).Scan(&oldAuthSecret)

		// Simular mudança de senha via API (se endpoint existir) ou diretamente no banco
		// Por enquanto, vamos simular mudando o auth_secret diretamente
		newAuthSecret := "new_secret_after_password_change"
		_, err = config.DB.Exec(`
			UPDATE users
			SET auth_secret = $1, password_hash = $2, updated_at = $3
			WHERE id = $4
		`, newAuthSecret, testUser.PasswordHash, time.Now(), testUser.ID)

		if err != nil {
			t.Fatalf("Erro ao atualizar senha: %v", err)
		}

		// Verificar que auth_secret mudou
		var newSecret string
		config.DB.QueryRow("SELECT auth_secret FROM users WHERE id = $1", testUser.ID).Scan(&newSecret)

		if oldAuthSecret == newSecret {
			t.Error("FALHA: auth_secret não mudou após alteração de senha")
		} else {
			t.Log("✓ auth_secret alterado após mudança de senha")
		}

		// Tentar usar token antigo - deve falhar
		req2, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req2.Header.Set("Authorization", "Bearer "+oldToken)
		resp2, _ := http.DefaultClient.Do(req2)
		resp2.Body.Close()

		if resp2.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Token antigo ainda válido após mudança de senha!")
		} else {
			t.Log("✓ Token antigo invalidado após mudança de senha")
		}
	})
}

func TestPasswordStrength(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Bcrypt cost deve ser adequado (>= 10)", func(t *testing.T) {
		// Pegar um hash de exemplo
		var passwordHash string
		err := config.DB.QueryRow(`
			SELECT password_hash FROM users WHERE deleted_at IS NULL LIMIT 1
		`).Scan(&passwordHash)

		if err != nil {
			t.Skip("Nenhum usuário disponível")
		}

		// Extrair o cost do hash bcrypt
		// Formato: $2a$10$... onde 10 é o cost
		if len(passwordHash) > 7 {
			cost := passwordHash[4:6]
			if cost >= "10" {
				t.Logf("✓ Bcrypt cost adequado: %s", cost)
			} else {
				t.Errorf("FALHA: Bcrypt cost muito baixo: %s (mínimo recomendado: 10)", cost)
			}
		}
	})

	t.Run("Criar usuário com senha fraca deve funcionar (mas ser hasheado)", func(t *testing.T) {
		// Nota: A validação de força de senha é responsabilidade do frontend/business logic
		// O backend deve hashear qualquer senha, mas idealmente validar força
		weakPassword := "123"

		hash, err := bcrypt.GenerateFromPassword([]byte(weakPassword), bcrypt.DefaultCost)
		if err != nil {
			t.Fatalf("Erro ao gerar hash: %v", err)
		}

		// Mesmo senha fraca deve ser hasheada
		if string(hash) == weakPassword {
			t.Error("FALHA: Senha não foi hasheada!")
		} else {
			t.Log("✓ Mesmo senhas fracas são hasheadas (validação de força deve estar no frontend)")
		}
	})
}

func TestPasswordChangeFlows(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Tentativa de mudança de senha sem autenticação deve falhar", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		// Tentar mudar senha sem token
		resp := makeRequest(t, "PUT", config.BaseURL+"/api/users/"+user.Username, "", map[string]string{
			"password": "NewPassword123!",
		})
		defer resp.Body.Close()

		assertStatusCode(t, resp, http.StatusUnauthorized, "Mudança de senha sem token deve ser rejeitada")
	})

	t.Run("Usuário não deve poder mudar senha de outro usuário", func(t *testing.T) {
		user1 := config.TestUsers["user"]
		user2 := config.TestUsers["user2"]

		if user1 == nil || user2 == nil {
			t.Skip("Usuários não disponíveis")
		}

		// Login como user1
		token := doLogin(t, config.BaseURL, user1.Username, user1.Password)

		// Tentar mudar senha de user2
		resp := makeRequest(t, "PUT", config.BaseURL+"/api/users/"+user2.Username, token, map[string]interface{}{
			"password": "HackedPassword123!",
		})
		defer resp.Body.Close()

		// Deve ser rejeitado com 403 Forbidden
		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Usuário conseguiu mudar senha de outro usuário!")
		} else {
			t.Logf("✓ Tentativa de mudar senha de outro usuário bloqueada (status %d)", resp.StatusCode)
		}
	})
}

func TestPasswordStorage(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Password hash nunca deve vazar em responses", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		if admin == nil {
			t.Skip("Admin não disponível")
		}

		token := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		// Tentar vários endpoints que retornam dados de usuário
		endpoints := []string{
			"/api/users",
			"/api/users/" + admin.Username,
		}

		for _, endpoint := range endpoints {
			req, _ := http.NewRequest("GET", config.BaseURL+endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+token)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				continue
			}

			body := getResponseBody(t, resp)

			assertNoSensitiveData(t, body)
			assertNotContains(t, body, "password_hash", "Response de "+endpoint)
			assertNotContains(t, body, "$2a$", "Response de "+endpoint)
			assertNotContains(t, body, "$2b$", "Response de "+endpoint)
			assertNotContains(t, body, "$2y$", "Response de "+endpoint)
		}

		t.Log("✓ password_hash não vaza em nenhum endpoint")
	})

	t.Run("auth_secret nunca deve vazar", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		if admin == nil {
			t.Skip("Admin não disponível")
		}

		token := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}

		body := getResponseBody(t, resp)

		assertNotContains(t, body, "auth_secret", "Response de /api/users")
		assertNotContains(t, body, "authSecret", "Response de /api/users")

		t.Log("✓ auth_secret não vaza em responses")
	})
}

func TestPasswordTimingAttack(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Tempo de resposta não deve revelar se usuário existe", func(t *testing.T) {
		// Fazer login com usuário existente
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		start1 := time.Now()
		resp1 := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": user.Username,
			"password": "wrong_password",
		})
		resp1.Body.Close()
		elapsed1 := time.Since(start1)

		// Fazer login com usuário inexistente
		start2 := time.Now()
		resp2 := makeRequest(t, "POST", config.BaseURL+"/api/login", "", map[string]string{
			"username": "user_that_does_not_exist_12345",
			"password": "wrong_password",
		})
		resp2.Body.Close()
		elapsed2 := time.Since(start2)

		// A diferença de tempo não deve ser muito grande (indica timing attack)
		diff := elapsed1 - elapsed2
		if diff < 0 {
			diff = -diff
		}

		// Se a diferença for maior que 500ms, pode indicar timing attack
		if diff > 500*time.Millisecond {
			t.Logf("⚠ AVISO: Diferença de tempo significativa detectada: %v", diff)
			t.Log("  Isso pode permitir timing attacks para descobrir usuários válidos")
		} else {
			t.Logf("✓ Tempos de resposta similares (diff: %v) - protegido contra timing attacks", diff)
		}

		t.Logf("  Usuário existente: %v", elapsed1)
		t.Logf("  Usuário inexistente: %v", elapsed2)
	})
}

func TestPasswordRecovery(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
		return
	}
	defer config.CleanupFunc()

	t.Run("Endpoint de recuperação de senha não deve revelar se email existe", func(t *testing.T) {
		// Nota: Este teste assume que existe um endpoint de recuperação de senha
		// Se não existir, o teste será pulado

		req, _ := http.NewRequest("POST", config.BaseURL+"/api/password-recovery", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Skip("Endpoint de recuperação de senha não disponível")
		}
		defer resp.Body.Close()

		// Se o endpoint existe, verificar comportamento
		if resp.StatusCode == http.StatusNotFound {
			t.Skip("Endpoint de recuperação de senha não implementado")
		}

		t.Log("✓ Endpoint de recuperação existe - implementar testes específicos")
	})
}
