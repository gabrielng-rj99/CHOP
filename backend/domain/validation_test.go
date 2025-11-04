package domain

import (
	"testing"
)

// Helper function para criar ponteiros de string
func stringPtr(s string) *string {
	return &s
}

// TestValidateClientEmailNil testa validação de email nulo (opcional)
func TestValidateClientEmailNil(t *testing.T) {
	result := ValidateClientEmail(nil)
	if result != nil {
		t.Errorf("expected nil email to be valid (optional), but got error: %v", result)
	}
}

// TestValidateClientEmailEmpty testa validação de email vazio (opcional)
func TestValidateClientEmailEmpty(t *testing.T) {
	emptyEmail := ""
	result := ValidateClientEmail(&emptyEmail)
	if result != nil {
		t.Errorf("expected empty email to be valid (optional), but got error: %v", result)
	}
}

// TestValidateClientPhone testa validação de telefone internacional
func TestValidateClientPhone(t *testing.T) {
	tests := []struct {
		name      string
		phone     *string
		wantError bool
	}{
		// Brasil
		{
			name:      "Brasil - celular com +55",
			phone:     stringPtr("+5511987654321"),
			wantError: false,
		},
		{
			name:      "Brasil - fixo com +55",
			phone:     stringPtr("+551133334444"),
			wantError: false,
		},
		{
			name:      "Brasil - sem +55 (assume BR)",
			phone:     stringPtr("11987654321"),
			wantError: false,
		},
		// EUA
		{
			name:      "EUA - formato +1",
			phone:     stringPtr("+12125552368"),
			wantError: false,
		},
		// China
		{
			name:      "China - formato +86",
			phone:     stringPtr("+8613912345678"),
			wantError: false,
		},
		// Espanha
		{
			name:      "Espanha - formato +34",
			phone:     stringPtr("+34912345678"),
			wantError: false,
		},
		// Suécia
		{
			name:      "Suécia - formato +46",
			phone:     stringPtr("+46812345678"),
			wantError: false,
		},
		// Mongólia
		{
			name:      "Mongólia - formato +976",
			phone:     stringPtr("+97611123456"),
			wantError: false,
		},
		// Egito
		{
			name:      "Egito - formato +20",
			phone:     stringPtr("+201001234567"),
			wantError: false,
		},
		// Sudão
		{
			name:      "Sudão - formato +249",
			phone:     stringPtr("+249912345678"),
			wantError: false,
		},
		// Irã
		{
			name:      "Irã - formato +98",
			phone:     stringPtr("+989121234567"),
			wantError: false,
		},
		// Moçambique
		{
			name:      "Moçambique - formato +258",
			phone:     stringPtr("+258821234567"),
			wantError: false,
		},
		// Inválidos
		{
			name:      "inválido - muito poucos dígitos",
			phone:     stringPtr("+123"),
			wantError: true,
		},
		{
			name:      "inválido - formato errado",
			phone:     stringPtr("abc123def"),
			wantError: true,
		},
		// Opcionais
		{
			name:      "nil é válido",
			phone:     nil,
			wantError: false,
		},
		{
			name:      "vazio é válido",
			phone:     stringPtr(""),
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientPhone(tt.phone)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateClientPhone() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestNormalizePhone testa normalização de telefone para E.164
func TestNormalizePhone(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		hasValue bool // Verifica se resultado é não-nil
	}{
		{
			name:     "Brasil sem +55",
			input:    stringPtr("11987654321"),
			hasValue: true,
		},
		{
			name:     "Brasil com +55",
			input:    stringPtr("+5511987654321"),
			hasValue: true,
		},
		{
			name:     "China",
			input:    stringPtr("+8613912345678"),
			hasValue: true,
		},
		{
			name:     "nil",
			input:    nil,
			hasValue: false,
		},
		{
			name:     "vazio",
			input:    stringPtr(""),
			hasValue: false,
		},
		{
			name:     "espaços",
			input:    stringPtr("   "),
			hasValue: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizePhone(tt.input)
			if tt.hasValue && result == nil {
				t.Errorf("expected non-nil result, got nil")
			}
			if !tt.hasValue && result != nil {
				t.Errorf("expected nil result, got %v", *result)
			}
		})
	}
}

// TestValidateClientEmailValid testa emails válidos
func TestValidateClientEmailValid(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"simple", "user@example.com"},
		{"com ponto", "john.doe@example.com"},
		{"com número", "user123@example.com"},
		{"subdomínio", "user@mail.example.com"},
		{"brasil", "contato@empresa.com.br"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientEmail(&tt.email)
			if err != nil {
				t.Errorf("expected valid email, got error: %v", err)
			}
		})
	}
}

// TestValidateClientEmailInvalid testa emails inválidos
func TestValidateClientEmailInvalid(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{"sem @", "userexample.com"},
		{"múltiplos @", "user@@example.com"},
		{"sem domínio", "user@"},
		{"sem local", "@example.com"},
		{"pontos consecutivos", "user..name@example.com"},
		{"começa com ponto", ".user@example.com"},
		{"termina com ponto", "user.@example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientEmail(&tt.email)
			if err == nil {
				t.Errorf("expected invalid email, but validation passed")
			}
		})
	}
}

// TestValidateClient testa validação completa de cliente
func TestValidateClient(t *testing.T) {
	validEmail := "contact@example.com"
	validPhone := "+5511987654321"
	invalidEmail := "not-an-email"
	invalidPhone := "123"

	tests := []struct {
		name          string
		client        *Client
		expectsErrors bool
	}{
		{
			name: "cliente válido com email e telefone",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: "12345678000180",
				Email:          &validEmail,
				Phone:          &validPhone,
			},
			expectsErrors: false,
		},
		{
			name: "cliente válido sem comunicação",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: "12345678000180",
			},
			expectsErrors: false,
		},
		{
			name: "cliente inválido - name vazio",
			client: &Client{
				Name:           "",
				RegistrationID: "12345678000180",
			},
			expectsErrors: true,
		},
		{
			name: "cliente inválido - registration_id vazio",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: "",
			},
			expectsErrors: true,
		},
		{
			name: "cliente inválido - email inválido",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: "12345678000180",
				Email:          &invalidEmail,
			},
			expectsErrors: true,
		},
		{
			name: "cliente inválido - telefone inválido",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: "12345678000180",
				Phone:          &invalidPhone,
			},
			expectsErrors: true,
		},
		{
			name:          "cliente nil",
			client:        nil,
			expectsErrors: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateClient(tt.client)
			if tt.expectsErrors && errors.IsValid() {
				t.Errorf("expected validation errors, but got none")
			}
			if !tt.expectsErrors && !errors.IsValid() {
				t.Errorf("expected no validation errors, but got: %v", errors.Error())
			}
		})
	}
}

// TestNormalizeEmail testa normalização de email
func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name     string
		input    *string
		expected *string
	}{
		{
			name:     "uppercase",
			input:    stringPtr("USER@EXAMPLE.COM"),
			expected: stringPtr("user@example.com"),
		},
		{
			name:     "com espaços",
			input:    stringPtr("  user@example.com  "),
			expected: stringPtr("user@example.com"),
		},
		{
			name:     "nil",
			input:    nil,
			expected: nil,
		},
		{
			name:     "vazio",
			input:    stringPtr(""),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeEmail(tt.input)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
			} else {
				if result == nil {
					t.Errorf("expected %v, got nil", *tt.expected)
				} else if *result != *tt.expected {
					t.Errorf("expected %v, got %v", *tt.expected, *result)
				}
			}
		})
	}
}

// TestValidationErrorsIsValid testa o método IsValid
func TestValidationErrorsIsValid(t *testing.T) {
	tests := []struct {
		name     string
		errors   ValidationErrors
		expected bool
	}{
		{
			name:     "sem erros",
			errors:   ValidationErrors{},
			expected: true,
		},
		{
			name:     "nil",
			errors:   nil,
			expected: true,
		},
		{
			name: "com erros",
			errors: ValidationErrors{
				{Field: "name", Message: "obrigatório"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.errors.IsValid()
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
