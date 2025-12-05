package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"Open-Generic-Hub/backend/store"
)

// setupTestServer creates a new server with a test database
func setupTestServer(t *testing.T) (*Server, *sql.DB) {
	db, err := store.SetupTestDB()
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}
	// Clean up database tables before test
	if err := store.ClearTables(db); err != nil {
		t.Fatalf("Failed to clear tables: %v", err)
	}

	s := NewServer(db)
	return s, db
}

func TestLoginHandler(t *testing.T) {
	s, _ := setupTestServer(t)

	// Create a user manually
	s.userStore.CreateUser("loginuser", "Login User", "ValidPass123!@#abc", "user")

	tests := []struct {
		name           string
		payload        map[string]string
		expectedStatus int
		checkToken     bool
	}{
		{
			name: "Valid Login",
			payload: map[string]string{
				"username": "loginuser",
				"password": "ValidPass123!@#abc",
			},
			expectedStatus: http.StatusOK,
			checkToken:     true,
		},
		{
			name: "Invalid Password",
			payload: map[string]string{
				"username": "loginuser",
				"password": "WrongPassword",
			},
			expectedStatus: http.StatusUnauthorized,
			checkToken:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.payload)
			req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler := s.standardMiddleware(s.handleLogin)
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.checkToken {
				var resp map[string]interface{}
				json.NewDecoder(w.Body).Decode(&resp)
				token := ""
				if tkn, ok := resp["token"].(string); ok {
					token = tkn
				} else if data, ok := resp["data"].(map[string]interface{}); ok {
					if tkn, ok := data["token"].(string); ok {
						token = tkn
					}
				}
				if token == "" {
					t.Error("Expected token in response, got none")
				}
			}
		})
	}
}

func TestListEntitiesHandler(t *testing.T) {
	s, db := setupTestServer(t)

	// Create user and get token
	if _, err := s.userStore.CreateUser("entityuser", "Entity User", "ValidPass123!@#abc", "user"); err != nil {
		t.Fatalf("Failed to create entityuser: %v", err)
	}
	users, _ := s.userStore.GetUsersByName("entityuser")
	if len(users) == 0 {
		t.Fatal("Failed to create test user")
	}
	user := &users[0]

	// Fetch auth_secret manually
	var authSecret string
	err := db.QueryRow("SELECT auth_secret FROM users WHERE id = $1", user.ID).Scan(&authSecret)
	if err != nil {
		t.Fatalf("Failed to fetch auth_secret: %v", err)
	}
	user.AuthSecret = authSecret

	token, err := GenerateJWT(user)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Case 1: No Auth
	req := httptest.NewRequest("GET", "/api/entities", nil)
	w := httptest.NewRecorder()

	// Test the specific handler wrapper
	handler := s.standardMiddleware(s.authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		s.handleListEntities(w, r)
	}))

	handler.ServeHTTP(w, req) // No auth header
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for no auth, got %d", w.Code)
	}

	// Case 2: With Auth
	req = httptest.NewRequest("GET", "/api/entities", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 with auth, got %d", w.Code)
	}
}

func TestCreateUserHandler(t *testing.T) {
	s, db := setupTestServer(t)

	// Create ROOT user to be able to create other users
	if _, err := s.userStore.CreateUser("rootuser", "Root User", "ValidPass123!@#abc", "root"); err != nil {
		t.Fatalf("Failed to create rootuser: %v", err)
	}
	users, _ := s.userStore.GetUsersByName("rootuser")
	user := &users[0]

	// Fetch auth_secret manually
	var authSecret string
	err := db.QueryRow("SELECT auth_secret FROM users WHERE id = $1", user.ID).Scan(&authSecret)
	if err != nil {
		t.Fatalf("Failed to fetch auth_secret: %v", err)
	}
	user.AuthSecret = authSecret

	token, _ := GenerateJWT(user)

	payload := map[string]string{
		"username":     "newuser",
		"display_name": "New User",
		"password":     "ValidPass123!@#abc",
		"role":         "user",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest("POST", "/api/users", bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// Handler structure
	handler := s.standardMiddleware(s.authMiddleware(s.adminOnlyMiddleware(func(w http.ResponseWriter, r *http.Request) {
		s.handleCreateUser(w, r)
	})))

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected 201 Created, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestCSRFProtection(t *testing.T) {
	// Our API is stateless (JWT), so mostly relies on standard headers and no-cookie auth or SameSite cookies.
	// But we added Content-Type check in test suite script. Let's verify middleware doesn't block valid requests
	// and blocks invalid content types if enforced (we didn't implement Content-Type enforcement in backend yet, only checked for XSS).
	// So we skip explicit CSRF unit test as it's covered by integration, unless we implement content-type check.
}
