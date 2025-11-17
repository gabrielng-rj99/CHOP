package tests

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
)

// ============================================================================
// TESTES DE ESCALAÇÃO DE PRIVILÉGIOS - COM REQUESTS HTTP REAIS
// ============================================================================

func TestPrivilegeEscalation(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	t.Run("Usuário comum não pode alterar próprio role via API", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		token := doLogin(t, config.BaseURL, user.Username, user.Password)

		// Tentar alterar próprio role para admin
		updateData := map[string]interface{}{
			"role": "admin",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+user.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA DE SEGURANÇA: Usuário conseguiu alterar próprio role!")
		}

		// Verificar no banco que role não mudou
		var currentRole string
		config.DB.QueryRow("SELECT role FROM users WHERE id = $1", user.ID).Scan(&currentRole)
		if currentRole != "user" {
			t.Error("FALHA: Role foi alterado no banco!")
		}
	})

	t.Run("Admin não pode escalar para root", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		if admin == nil {
			t.Skip("Admin não disponível")
		}

		token := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		updateData := map[string]interface{}{
			"role": "root",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+admin.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA DE SEGURANÇA: Admin conseguiu escalar para root!")
		}

		var currentRole string
		config.DB.QueryRow("SELECT role FROM users WHERE id = $1", admin.ID).Scan(&currentRole)
		if currentRole == "root" {
			t.Error("FALHA: Role foi alterado para root!")
		}
	})

	t.Run("Usuário não pode alterar dados de outro usuário", func(t *testing.T) {
		user := config.TestUsers["user"]
		user2 := config.TestUsers["user2"]
		if user == nil || user2 == nil {
			t.Skip("Usuários não disponíveis")
		}

		token := doLogin(t, config.BaseURL, user.Username, user.Password)

		// User tentando alterar display_name de user2
		updateData := map[string]interface{}{
			"display_name": "Hackeado!",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+user2.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Usuário comum conseguiu alterar dados de outro!")
		}
	})
}

func TestRequestWithoutPassword(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	admin := config.TestUsers["admin"]
	if admin == nil {
		t.Skip("Admin não disponível")
	}
	token := doLogin(t, config.BaseURL, admin.Username, admin.Password)

	t.Run("Criar usuário sem senha deve falhar", func(t *testing.T) {
		userData := map[string]interface{}{
			"username":     "test_no_pass",
			"display_name": "No Password User",
			"role":         "user",
			// password ausente
		}
		body, _ := json.Marshal(userData)

		req, _ := http.NewRequest("POST", config.BaseURL+"/api/users", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Error("FALHA DE SEGURANÇA: Usuário sem senha foi criado!")
		}
	})

	t.Run("Criar usuário com senha vazia deve falhar", func(t *testing.T) {
		userData := map[string]interface{}{
			"username":     "test_empty_pass",
			"display_name": "Empty Password User",
			"role":         "user",
			"password":     "",
		}
		body, _ := json.Marshal(userData)

		req, _ := http.NewRequest("POST", config.BaseURL+"/api/users", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Error("FALHA: Usuário com senha vazia foi criado!")
		}
	})

	t.Run("Login sem senha deve falhar", func(t *testing.T) {
		loginData := map[string]string{
			"username": "test_user",
			// password ausente
		}
		body, _ := json.Marshal(loginData)

		resp, err := http.Post(config.BaseURL+"/api/login", "application/json", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Login sem senha foi aceito!")
		}
	})

	t.Run("Login com senha vazia deve falhar", func(t *testing.T) {
		loginData := map[string]string{
			"username": "test_user",
			"password": "",
		}
		body, _ := json.Marshal(loginData)

		resp, err := http.Post(config.BaseURL+"/api/login", "application/json", bytes.NewBuffer(body))
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Login com senha vazia foi aceito!")
		}
	})
}

func TestRoleManipulationInRequest(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	admin := config.TestUsers["admin"]
	if admin == nil {
		t.Skip("Admin não disponível")
	}
	token := doLogin(t, config.BaseURL, admin.Username, admin.Password)

	t.Run("Admin tentando criar usuário com role=root", func(t *testing.T) {
		userData := map[string]interface{}{
			"username":     "test_fake_root",
			"display_name": "Fake Root",
			"password":     "FakeRoot123!",
			"role":         "root",
		}
		body, _ := json.Marshal(userData)

		req, _ := http.NewRequest("POST", config.BaseURL+"/api/users", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Error("FALHA: Admin conseguiu criar usuário com role=root!")
		}
	})

	t.Run("Update com role manipulado no body deve ser ignorado", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		// Tentar atualizar display_name mas incluir role no body
		updateData := map[string]interface{}{
			"display_name": "New Name",
			"role":         "admin", // Tentativa de escalação
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+user.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		// Verificar que role não mudou
		var currentRole string
		config.DB.QueryRow("SELECT role FROM users WHERE id = $1", user.ID).Scan(&currentRole)
		if currentRole != "user" {
			t.Error("FALHA: Role foi alterado via mass assignment!")
		}
	})

	t.Run("Mass assignment de campos privilegiados", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		// Tentar incluir campos que não deveriam ser alteráveis
		updateData := map[string]interface{}{
			"display_name":    "New Name",
			"role":            "admin",
			"auth_secret":     "controlled_secret",
			"failed_attempts": 0,
			"lock_level":      0,
			"created_at":      "2020-01-01",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+user.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		// Verificar que campos protegidos não foram alterados
		var role, authSecret string
		var failedAttempts, lockLevel int
		config.DB.QueryRow(`
			SELECT role, auth_secret, failed_attempts, lock_level
			FROM users WHERE id = $1
		`, user.ID).Scan(&role, &authSecret, &failedAttempts, &lockLevel)

		if role != "user" {
			t.Error("FALHA: role foi alterado via mass assignment!")
		}
		if authSecret == "controlled_secret" {
			t.Error("FALHA: auth_secret foi alterado!")
		}
	})
}

func TestAdminVsRootPermissions(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	t.Run("Admin não pode alterar senha de root", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		root := config.TestUsers["root"]
		if admin == nil || root == nil {
			t.Skip("Usuários não disponíveis")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		// Admin tentando alterar senha de root
		updateData := map[string]interface{}{
			"password": "HackedPassword123!",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+root.ID+"/password", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Admin conseguiu alterar senha de root!")
		}
	})

	t.Run("Admin não pode deletar root", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		root := config.TestUsers["root"]
		if admin == nil || root == nil {
			t.Skip("Usuários não disponíveis")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		req, _ := http.NewRequest("DELETE", config.BaseURL+"/api/users/"+root.ID, nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Admin conseguiu deletar root!")
		}

		// Verificar que root ainda existe
		var exists bool
		config.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND deleted_at IS NULL)", root.ID).Scan(&exists)
		if !exists {
			t.Error("FALHA: Root foi deletado!")
		}
	})

	t.Run("Admin não pode alterar role de outro admin", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		admin2 := config.TestUsers["admin2"]
		if admin == nil || admin2 == nil {
			t.Skip("Admins não disponíveis")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		// Admin1 tentando rebaixar Admin2 para user
		updateData := map[string]interface{}{
			"role": "user",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+admin2.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Admin conseguiu alterar role de outro admin!")
		}

		var currentRole string
		config.DB.QueryRow("SELECT role FROM users WHERE id = $1", admin2.ID).Scan(&currentRole)
		if currentRole != "admin" {
			t.Error("FALHA: Role de admin foi alterado!")
		}
	})

	t.Run("Admin não pode alterar display_name de outro admin", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		admin2 := config.TestUsers["admin2"]
		if admin == nil || admin2 == nil {
			t.Skip("Admins não disponíveis")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)
		originalName := admin2.DisplayName

		updateData := map[string]interface{}{
			"display_name": "Hackeado",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+admin2.ID, bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Admin conseguiu alterar display_name de outro admin!")
		}

		var currentName string
		config.DB.QueryRow("SELECT display_name FROM users WHERE id = $1", admin2.ID).Scan(&currentName)
		if currentName != originalName {
			t.Error("FALHA: Display name foi alterado!")
		}
	})
}

func TestPasswordChangePermissions(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	t.Run("Usuário pode alterar própria senha", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		userToken := doLogin(t, config.BaseURL, user.Username, user.Password)

		updateData := map[string]interface{}{
			"old_password": user.Password,
			"new_password": "NewUserPass123!@#",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+user.ID+"/password", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		// Deve permitir (200) ou exigir re-login (202/401)
		if resp.StatusCode >= 500 {
			t.Error("FALHA: Usuário não pode alterar própria senha!")
		}
	})

	t.Run("Usuário não pode alterar senha de outro", func(t *testing.T) {
		user := config.TestUsers["user"]
		user2 := config.TestUsers["user2"]
		if user == nil || user2 == nil {
			t.Skip("Usuários não disponíveis")
		}

		userToken := doLogin(t, config.BaseURL, user.Username, user.Password)

		updateData := map[string]interface{}{
			"new_password": "HackedPassword123!",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+user2.ID+"/password", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Usuário conseguiu alterar senha de outro!")
		}
	})

	t.Run("Admin NÃO pode alterar senha de outro admin", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		admin2 := config.TestUsers["admin2"]
		if admin == nil || admin2 == nil {
			t.Skip("Admins não disponíveis")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		updateData := map[string]interface{}{
			"new_password": "HackedAdminPass123!",
		}
		body, _ := json.Marshal(updateData)

		req, _ := http.NewRequest("PUT", config.BaseURL+"/api/users/"+admin2.ID+"/password", bytes.NewBuffer(body))
		req.Header.Set("Authorization", "Bearer "+adminToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA CRÍTICA: Admin conseguiu alterar senha de outro admin!")
		}
	})
}

func TestDataAccessPermissions(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	t.Run("Usuário comum não pode ver lista de todos usuários", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		userToken := doLogin(t, config.BaseURL, user.Username, user.Password)

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Usuário comum conseguiu acessar lista de usuários!")
		}
	})

	t.Run("Admin pode ver lista de usuários", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		if admin == nil {
			t.Skip("Admin não disponível")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Error("FALHA: Admin não pode acessar lista de usuários!")
		}

		// Verificar que dados sensíveis não vazam
		body := getResponseBody(t, resp)
		assertNoSensitiveData(t, body)
	})

	t.Run("Usuário pode ver próprios dados", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		userToken := doLogin(t, config.BaseURL, user.Username, user.Password)

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/users/me", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Error("FALHA: Usuário não pode ver próprios dados!")
		}
	})
}

func TestAuditLogPermissions(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()


	t.Run("Usuário comum não pode acessar audit logs", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		userToken := doLogin(t, config.BaseURL, user.Username, user.Password)

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/audit-logs", nil)
		req.Header.Set("Authorization", "Bearer "+userToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			t.Error("FALHA: Usuário comum conseguiu acessar audit logs!")
		}
	})

	t.Run("Admin pode acessar audit logs", func(t *testing.T) {
		admin := config.TestUsers["admin"]
		if admin == nil {
			t.Skip("Admin não disponível")
		}

		adminToken := doLogin(t, config.BaseURL, admin.Username, admin.Password)

		req, _ := http.NewRequest("GET", config.BaseURL+"/api/audit-logs", nil)
		req.Header.Set("Authorization", "Bearer "+adminToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Erro: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Error("Admin deveria poder acessar audit logs")
		}
	})

	t.Run("Audit logs não contêm dados sensíveis", func(t *testing.T) {
		var hasSensitiveData bool
		err := config.DB.QueryRow(`
			SELECT EXISTS(
				SELECT 1 FROM audit_logs
				WHERE old_value LIKE '%password%'
				   OR new_value LIKE '%password%'
				   OR old_value LIKE '%auth_secret%'
				   OR new_value LIKE '%auth_secret%'
			)
		`).Scan(&hasSensitiveData)

		if err != nil {
			t.Logf("Aviso: erro ao verificar logs: %v", err)
		}

		if hasSensitiveData {
			t.Error("FALHA CRÍTICA: Dados sensíveis encontrados nos audit logs!")
		}
	})
}
