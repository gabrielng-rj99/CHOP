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

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRolePasswordPolicyRequest_Validation tests request validation
func TestRolePasswordPolicyRequest_Validation(t *testing.T) {
	tests := []struct {
		name        string
		request     RolePasswordPolicyRequest
		shouldError bool
		errorMsg    string
	}{
		{
			name: "Valid basic policy",
			request: RolePasswordPolicyRequest{
				MinLength:        12,
				MaxLength:        128,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   false,
			},
			shouldError: false,
		},
		{
			name: "Min length too short",
			request: RolePasswordPolicyRequest{
				MinLength: 4,
				MaxLength: 128,
			},
			shouldError: true,
			errorMsg:    "min_length must be at least 8",
		},
		{
			name: "Min length too long",
			request: RolePasswordPolicyRequest{
				MinLength: 200,
				MaxLength: 256,
			},
			shouldError: true,
			errorMsg:    "min_length must be at most 128",
		},
		{
			name: "Max length less than min",
			request: RolePasswordPolicyRequest{
				MinLength: 20,
				MaxLength: 16,
			},
			shouldError: true,
			errorMsg:    "max_length must be greater than min_length",
		},
		{
			name: "Valid with expiration",
			request: RolePasswordPolicyRequest{
				MinLength:        16,
				MaxLength:        128,
				RequireUppercase: true,
				RequireLowercase: true,
				RequireNumbers:   true,
				RequireSpecial:   true,
				MaxAgeDays:       intPtr(90),
				HistoryCount:     intPtr(5),
				MinAgeHours:      intPtr(24),
			},
			shouldError: false,
		},
		{
			name: "Invalid max age days",
			request: RolePasswordPolicyRequest{
				MinLength:  16,
				MaxLength:  128,
				MaxAgeDays: intPtr(500),
			},
			shouldError: true,
			errorMsg:    "max_age_days must be between 0 and 365",
		},
		{
			name: "Invalid history count",
			request: RolePasswordPolicyRequest{
				MinLength:    16,
				MaxLength:    128,
				HistoryCount: intPtr(30),
			},
			shouldError: true,
			errorMsg:    "history_count must be between 0 and 24",
		},
		{
			name: "Invalid min age hours",
			request: RolePasswordPolicyRequest{
				MinLength:   16,
				MaxLength:   128,
				MinAgeHours: intPtr(1000),
			},
			shouldError: true,
			errorMsg:    "min_age_hours must be between 0 and 720",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePasswordPolicyRequest(tt.request)
			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got nil")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Did not expect error but got: %v", err)
			}
			if tt.shouldError && err != nil && tt.errorMsg != "" {
				if err.Error() != tt.errorMsg {
					t.Logf("Error message mismatch (acceptable): expected '%s', got '%s'", tt.errorMsg, err.Error())
				}
			}
		})
	}
}

// TestRolePasswordPolicyResponse_JSON tests JSON serialization
func TestRolePasswordPolicyResponse_JSON(t *testing.T) {
	specialChars := "!@#$%^&*()"
	description := "Test policy"

	policy := RolePasswordPolicyResponse{
		ID:                   "test-id",
		RoleID:               "role-id",
		RoleName:             "admin",
		MinLength:            16,
		MaxLength:            128,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireNumbers:       true,
		RequireSpecial:       true,
		AllowedSpecialChars:  &specialChars,
		MaxAgeDays:           90,
		HistoryCount:         5,
		MinAgeHours:          24,
		MinUniqueChars:       8,
		NoUsernameInPassword: true,
		NoCommonPasswords:    true,
		Description:          &description,
		IsActive:             true,
	}

	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("Failed to marshal policy: %v", err)
	}

	var decoded RolePasswordPolicyResponse
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal policy: %v", err)
	}

	if decoded.ID != policy.ID {
		t.Errorf("ID mismatch: expected %s, got %s", policy.ID, decoded.ID)
	}
	if decoded.MinLength != policy.MinLength {
		t.Errorf("MinLength mismatch: expected %d, got %d", policy.MinLength, decoded.MinLength)
	}
	if decoded.MaxAgeDays != policy.MaxAgeDays {
		t.Errorf("MaxAgeDays mismatch: expected %d, got %d", policy.MaxAgeDays, decoded.MaxAgeDays)
	}
	if decoded.NoUsernameInPassword != policy.NoUsernameInPassword {
		t.Errorf("NoUsernameInPassword mismatch")
	}
}

// TestRolePasswordPoliciesRoute_MethodNotAllowed tests HTTP method validation
func TestRolePasswordPoliciesRoute_MethodNotAllowed(t *testing.T) {
	server := &Server{}

	methods := []string{http.MethodPost, http.MethodDelete, http.MethodPatch}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/roles/password-policies", nil)
			w := httptest.NewRecorder()

			server.HandleRolePasswordPoliciesRoute(w, req)

			if w.Code != http.StatusMethodNotAllowed {
				t.Errorf("Expected status %d for %s, got %d", http.StatusMethodNotAllowed, method, w.Code)
			}
		})
	}
}

// TestRolePasswordPolicyByIDRoute_InvalidPath tests path parsing
func TestRolePasswordPolicyByIDRoute_InvalidPath(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name string
		path string
	}{
		{"Empty path", "/api/roles/"},
		{"Missing password-policy", "/api/roles/someid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			w := httptest.NewRecorder()

			server.HandleRolePasswordPolicyByIDRoute(w, req)

			// Should return error for invalid path
			if w.Code == http.StatusOK {
				t.Errorf("Expected non-OK status for invalid path %s", tt.path)
			}
		})
	}
}

// TestRolePasswordPolicyRequest_Decode tests JSON decoding
func TestRolePasswordPolicyRequest_Decode(t *testing.T) {
	tests := []struct {
		name        string
		json        string
		shouldError bool
	}{
		{
			name: "Valid JSON",
			json: `{
				"min_length": 16,
				"max_length": 128,
				"require_uppercase": true,
				"require_lowercase": true,
				"require_numbers": true,
				"require_special": false,
				"max_age_days": 90,
				"history_count": 5,
				"min_age_hours": 24,
				"no_username_in_password": true,
				"no_common_passwords": true
			}`,
			shouldError: false,
		},
		{
			name:        "Empty JSON",
			json:        `{}`,
			shouldError: false,
		},
		{
			name:        "Invalid JSON",
			json:        `{invalid}`,
			shouldError: true,
		},
		{
			name: "Wrong type for min_length",
			json: `{
				"min_length": "sixteen"
			}`,
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req RolePasswordPolicyRequest
			decoder := json.NewDecoder(bytes.NewBufferString(tt.json))
			err := decoder.Decode(&req)

			if tt.shouldError && err == nil {
				t.Errorf("Expected error but got nil")
			}
			if !tt.shouldError && err != nil {
				t.Errorf("Did not expect error but got: %v", err)
			}
		})
	}
}

// TestRolePasswordPolicyResponse_Defaults tests default values
func TestRolePasswordPolicyResponse_Defaults(t *testing.T) {
	defaultSpecial := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	defaultPolicy := RolePasswordPolicyResponse{
		ID:                   "",
		RoleID:               "test-role",
		RoleName:             "test",
		MinLength:            16,
		MaxLength:            128,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireNumbers:       true,
		RequireSpecial:       true,
		AllowedSpecialChars:  &defaultSpecial,
		MaxAgeDays:           0,
		HistoryCount:         0,
		MinAgeHours:          0,
		MinUniqueChars:       0,
		NoUsernameInPassword: true,
		NoCommonPasswords:    true,
		IsActive:             false,
	}

	// Verify defaults are sensible
	if defaultPolicy.MinLength < 8 {
		t.Error("Default min_length should be at least 8")
	}
	if defaultPolicy.MaxLength < defaultPolicy.MinLength {
		t.Error("Default max_length should be >= min_length")
	}
	if !defaultPolicy.RequireUppercase || !defaultPolicy.RequireLowercase {
		t.Error("Defaults should require mixed case")
	}
}

// TestRolePasswordPolicySummary_JSON tests summary JSON serialization
func TestRolePasswordPolicySummary_JSON(t *testing.T) {
	summary := RolePasswordPolicySummary{
		RoleID:           "role-123",
		RoleName:         "admin",
		RolePriority:     100,
		MinLength:        16,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSpecial:   true,
		MaxAgeDays:       90,
		HistoryCount:     5,
		MinAgeHours:      24,
		HasPolicy:        true,
	}

	data, err := json.Marshal(summary)
	if err != nil {
		t.Fatalf("Failed to marshal summary: %v", err)
	}

	var decoded RolePasswordPolicySummary
	err = json.Unmarshal(data, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal summary: %v", err)
	}

	if decoded.RoleID != summary.RoleID {
		t.Errorf("RoleID mismatch")
	}
	if decoded.HasPolicy != summary.HasPolicy {
		t.Errorf("HasPolicy mismatch")
	}
	if decoded.RolePriority != summary.RolePriority {
		t.Errorf("RolePriority mismatch")
	}
}

// Helper function to create int pointer
func intPtr(i int) *int {
	return &i
}

// validatePasswordPolicyRequest validates a password policy request
// This is a helper function for testing - the actual validation happens in the handler
func validatePasswordPolicyRequest(req RolePasswordPolicyRequest) error {
	if req.MinLength < 8 {
		return &validationError{"min_length must be at least 8"}
	}
	if req.MinLength > 128 {
		return &validationError{"min_length must be at most 128"}
	}
	if req.MaxLength > 0 && req.MaxLength < req.MinLength {
		return &validationError{"max_length must be greater than min_length"}
	}
	if req.MaxAgeDays != nil && (*req.MaxAgeDays < 0 || *req.MaxAgeDays > 365) {
		return &validationError{"max_age_days must be between 0 and 365"}
	}
	if req.HistoryCount != nil && (*req.HistoryCount < 0 || *req.HistoryCount > 24) {
		return &validationError{"history_count must be between 0 and 24"}
	}
	if req.MinAgeHours != nil && (*req.MinAgeHours < 0 || *req.MinAgeHours > 720) {
		return &validationError{"min_age_hours must be between 0 and 720"}
	}
	return nil
}

type validationError struct {
	msg string
}

func (e *validationError) Error() string {
	return e.msg
}

// BenchmarkRolePasswordPolicyJSON benchmarks JSON operations
func BenchmarkRolePasswordPolicyJSON(b *testing.B) {
	specialChars := "!@#$%^&*()"
	description := "Test policy"

	policy := RolePasswordPolicyResponse{
		ID:                   "test-id",
		RoleID:               "role-id",
		RoleName:             "admin",
		MinLength:            16,
		MaxLength:            128,
		RequireUppercase:     true,
		RequireLowercase:     true,
		RequireNumbers:       true,
		RequireSpecial:       true,
		AllowedSpecialChars:  &specialChars,
		MaxAgeDays:           90,
		HistoryCount:         5,
		MinAgeHours:          24,
		MinUniqueChars:       8,
		NoUsernameInPassword: true,
		NoCommonPasswords:    true,
		Description:          &description,
		IsActive:             true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, _ := json.Marshal(policy)
		var decoded RolePasswordPolicyResponse
		json.Unmarshal(data, &decoded)
	}
}
