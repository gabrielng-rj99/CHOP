package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

// ============================================================================
// HTTP REQUEST HELPERS
// ============================================================================

// makeRequest helper para fazer requisições HTTP ao servidor de teste
func makeRequest(t *testing.T, method, url, token string, body interface{}) *http.Response {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("Erro ao serializar body: %v", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("Erro ao criar request: %v", err)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Erro ao fazer request: %v", err)
	}

	return resp
}

// doLogin faz login e retorna o token JWT
func doLogin(t *testing.T, baseURL, username, password string) string {
	loginData := map[string]string{
		"username": username,
		"password": password,
	}

	resp := makeRequest(t, "POST", baseURL+"/api/login", "", loginData)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Login falhou com status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Message string                 `json:"message"`
		Data    map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("Erro ao decodificar resposta de login: %v", err)
	}

	// Token está dentro de data
	token, ok := result.Data["token"].(string)
	if !ok || token == "" {
		t.Fatalf("Token não retornado no login. Response: %+v", result)
	}

	return token
}

// ============================================================================
// RESPONSE PARSING HELPERS
// ============================================================================

// parseJSONResponse helper para fazer parse de resposta JSON
func parseJSONResponse(t *testing.T, resp *http.Response, target interface{}) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Erro ao ler body da resposta: %v", err)
	}

	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("Erro ao fazer parse de JSON: %v\nBody: %s", err, string(body))
	}
}

// getResponseBody retorna o body da resposta como string
func getResponseBody(t *testing.T, resp *http.Response) string {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Erro ao ler body: %v", err)
	}
	return string(body)
}

// readResponseBody lê o body sem fechar a resposta (para reutilização)
func readResponseBody(t *testing.T, resp *http.Response) []byte {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Erro ao ler body: %v", err)
	}
	return body
}

// ============================================================================
// SECURITY VALIDATION HELPERS
// ============================================================================

// assertNoSensitiveData verifica se não há dados sensíveis na resposta
func assertNoSensitiveData(t *testing.T, responseBody string) {
	sensitiveFields := []string{
		"password",
		"password_hash",
		"auth_secret",
		"authSecret",
		"passwordHash",
	}

	for _, field := range sensitiveFields {
		if bytes.Contains([]byte(responseBody), []byte(field)) {
			t.Errorf("FALHA DE SEGURANÇA: Campo sensível '%s' encontrado na resposta", field)
		}
	}
}

// assertNoStackTrace verifica se não há stack trace na resposta
func assertNoStackTrace(t *testing.T, responseBody string) {
	stackIndicators := []string{
		"goroutine",
		"panic:",
		".go:",
		"runtime/",
		"src/",
	}

	for _, indicator := range stackIndicators {
		if bytes.Contains([]byte(responseBody), []byte(indicator)) {
			t.Errorf("FALHA DE SEGURANÇA: Stack trace vazando informação: '%s' encontrado", indicator)
		}
	}
}

// assertStatusCode verifica se o status code é o esperado
func assertStatusCode(t *testing.T, resp *http.Response, expected int, context string) {
	if resp.StatusCode != expected {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("%s: Esperado status %d, obteve %d. Body: %s",
			context, expected, resp.StatusCode, string(body))
	}
}

// assertContains verifica se a string contém o substring esperado
func assertContains(t *testing.T, s, substr, context string) {
	if !bytes.Contains([]byte(s), []byte(substr)) {
		t.Errorf("%s: Esperado conter '%s', mas não encontrado em: %s", context, substr, s)
	}
}

// assertNotContains verifica se a string NÃO contém o substring
func assertNotContains(t *testing.T, s, substr, context string) {
	if bytes.Contains([]byte(s), []byte(substr)) {
		t.Errorf("%s: NÃO deveria conter '%s', mas foi encontrado", context, substr)
	}
}

// ============================================================================
// VALIDATION TESTS
// ============================================================================

func TestDatabaseConnection(t *testing.T) {
	db := getTestDBConnection(t)
	if db == nil {
		t.Skip("Banco não disponível")
	}
	defer db.Close()

	// Verificar se schema foi aplicado
	tables := []string{"users", "clients", "categories", "lines", "contracts", "audit_logs", "dependents"}
	for _, table := range tables {
		var exists bool
		err := db.QueryRow(`
			SELECT EXISTS (
				SELECT FROM information_schema.tables
				WHERE table_schema = 'public'
				AND table_name = $1
			)
		`, table).Scan(&exists)

		if err != nil {
			t.Errorf("Erro ao verificar tabela %s: %v", table, err)
		}
		if !exists {
			t.Errorf("Tabela %s não existe! Schema não foi aplicado corretamente.", table)
		}
	}

	t.Log("✓ Todas as tabelas do schema existem")
}

func TestDatabasePopulation(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	// Verificar se usuários foram criados
	if len(config.TestUsers) < 5 {
		t.Errorf("Esperado pelo menos 5 usuários de teste, obteve %d", len(config.TestUsers))
	}

	// Verificar cada tipo de usuário
	requiredRoles := []string{"root", "admin", "user"}
	for _, role := range requiredRoles {
		found := false
		for _, user := range config.TestUsers {
			if user.Role == role {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Nenhum usuário com role '%s' foi criado", role)
		}
	}

	// Verificar se clientes foram criados
	var clientCount int
	err := config.DB.QueryRow("SELECT COUNT(*) FROM clients").Scan(&clientCount)
	if err != nil {
		t.Errorf("Erro ao contar clientes: %v", err)
	}
	if clientCount < 1 {
		t.Errorf("Nenhum cliente de teste foi criado")
	}

	// Verificar se categorias foram criadas
	var categoryCount int
	err = config.DB.QueryRow("SELECT COUNT(*) FROM categories").Scan(&categoryCount)
	if err != nil {
		t.Errorf("Erro ao contar categorias: %v", err)
	}
	if categoryCount < 1 {
		t.Errorf("Nenhuma categoria de teste foi criada")
	}

	t.Logf("✓ Banco populado: %d usuários, %d clientes, %d categorias",
		len(config.TestUsers), clientCount, categoryCount)
}

func TestRealServerIntegration(t *testing.T) {
	config := setupTestEnvironment(t)
	if config == nil {
		t.Skip("Ambiente de teste não disponível")
	}
	defer config.CleanupFunc()

	t.Run("Health endpoint deve responder", func(t *testing.T) {
		resp, err := http.Get(config.BaseURL + "/health")
		if err != nil {
			t.Fatalf("Erro ao acessar /health: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Health check falhou: status %d", resp.StatusCode)
		}

		var result map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		if result["status"] != "healthy" {
			t.Errorf("Health status não é 'healthy': %v", result)
		}

		t.Log("✓ Servidor real respondendo corretamente")
	})

	t.Run("Login com servidor real deve funcionar", func(t *testing.T) {
		user := config.TestUsers["user"]
		if user == nil {
			t.Skip("Usuário não disponível")
		}

		token := doLogin(t, config.BaseURL, user.Username, user.Password)
		if token == "" {
			t.Error("Token vazio retornado")
		}

		t.Logf("✓ Login com servidor real funcionando, token: %s...", token[:20])
	})
}
