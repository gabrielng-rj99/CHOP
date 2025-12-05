/*
 * Entity Hub Open Project
 * Copyright (C) 2025 Entity Hub Contributors
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

package domain

import (
	"strings"
	"testing"
	"time"
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
		{"simple", "user@gmail.com"},
		{"com ponto", "john.doe@gmail.com"},
		{"com número", "user123@gmail.com"},
		{"brasil", "contato@gmail.com"},
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
		{"sem local", "@gmail.com"},
		{"pontos consecutivos", "user..name@gmail.com"},
		{"começa com ponto", ".user@gmail.com"},
		{"termina com ponto", "user.@gmail.com"},
		{"domínio sem MX", "user@nonexistent-domain-12345-xyz.invalid"},
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
	validPhone := "+5511987654321"
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
				RegistrationID: stringPtr("12345678000180"),
				Status:         "ativo",
				Email:          stringPtr("user@gmail.com"),
				Phone:          &validPhone,
			},
			expectsErrors: false,
		},
		{
			name: "cliente válido sem comunicação",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: stringPtr("12345678000180"),
				Status:         "ativo",
			},
			expectsErrors: false,
		},
		{
			name: "cliente inválido - name vazio",
			client: &Client{
				Name:           "",
				RegistrationID: stringPtr("12345678000180"),
				Status:         "ativo",
			},
			expectsErrors: true,
		},
		{
			name: "cliente sem status",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: stringPtr("12345678000180"),
				Status:         "",
			},
			expectsErrors: true,
		},
		{
			name: "cliente inválido - email inválido",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: stringPtr("12345678000180"),
				Status:         "ativo",
				Email:          stringPtr("user@nonexistent-domain-12345-xyz.invalid"),
			},
			expectsErrors: true,
		},
		{
			name: "cliente inválido - telefone inválido",
			client: &Client{
				Name:           "Test Company",
				RegistrationID: stringPtr("12345678000180"),
				Status:         "ativo",
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

func TestValidateDependent(t *testing.T) {
	validPhone := "+5511987654321"
	invalidPhone := "invalid"

	tests := []struct {
		name          string
		dependent     *Dependent
		expectsErrors bool
	}{
		{
			name: "dependente válido com todos os campos",
			dependent: &Dependent{
				Name:              "Test Dependent",
				ClientID:          "client-123",
				Status:            "ativo",
				Description:       stringPtr("Test description"),
				Email:             stringPtr("dep@example.com"),
				Phone:             &validPhone,
				ContactPreference: stringPtr("whatsapp"),
			},
			expectsErrors: false,
		},
		{
			name: "dependente válido apenas campos obrigatórios",
			dependent: &Dependent{
				Name:     "Test Dependent",
				ClientID: "client-123",
				Status:   "ativo",
			},
			expectsErrors: false,
		},
		{
			name: "dependente inválido - nome vazio",
			dependent: &Dependent{
				Name:     "",
				ClientID: "client-123",
				Status:   "ativo",
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - nome muito longo",
			dependent: &Dependent{
				Name:     string(make([]byte, 256)),
				ClientID: "client-123",
				Status:   "ativo",
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - client_id vazio",
			dependent: &Dependent{
				Name:     "Test Dependent",
				ClientID: "",
				Status:   "ativo",
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - status vazio",
			dependent: &Dependent{
				Name:     "Test Dependent",
				ClientID: "client-123",
				Status:   "",
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - descrição muito longa",
			dependent: &Dependent{
				Name:        "Test Dependent",
				ClientID:    "client-123",
				Status:      "ativo",
				Description: stringPtr(string(make([]byte, 1001))),
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - endereço muito longo",
			dependent: &Dependent{
				Name:     "Test Dependent",
				ClientID: "client-123",
				Status:   "ativo",
				Address:  stringPtr(string(make([]byte, 1001))),
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - contact_preference inválido",
			dependent: &Dependent{
				Name:              "Test Dependent",
				ClientID:          "client-123",
				Status:            "ativo",
				ContactPreference: stringPtr("invalid-preference"),
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - email inválido",
			dependent: &Dependent{
				Name:     "Test Dependent",
				ClientID: "client-123",
				Status:   "ativo",
				Email:    stringPtr("invalid-email-format"),
			},
			expectsErrors: true,
		},
		{
			name: "dependente inválido - telefone inválido",
			dependent: &Dependent{
				Name:     "Test Dependent",
				ClientID: "client-123",
				Status:   "ativo",
				Phone:    &invalidPhone,
			},
			expectsErrors: true,
		},
		{
			name:          "dependente nil",
			dependent:     nil,
			expectsErrors: true,
		},
		{
			name: "dependente válido - contact_preference email",
			dependent: &Dependent{
				Name:              "Test Dependent",
				ClientID:          "client-123",
				Status:            "ativo",
				ContactPreference: stringPtr("email"),
			},
			expectsErrors: false,
		},
		{
			name: "dependente válido - contact_preference phone",
			dependent: &Dependent{
				Name:              "Test Dependent",
				ClientID:          "client-123",
				Status:            "ativo",
				ContactPreference: stringPtr("phone"),
			},
			expectsErrors: false,
		},
		{
			name: "dependente válido - contact_preference sms",
			dependent: &Dependent{
				Name:              "Test Dependent",
				ClientID:          "client-123",
				Status:            "ativo",
				ContactPreference: stringPtr("sms"),
			},
			expectsErrors: false,
		},
		{
			name: "dependente válido - contact_preference outros",
			dependent: &Dependent{
				Name:              "Test Dependent",
				ClientID:          "client-123",
				Status:            "ativo",
				ContactPreference: stringPtr("outros"),
			},
			expectsErrors: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errors := ValidateDependent(tt.dependent)

			if tt.expectsErrors && errors.IsValid() {
				t.Error("Expected validation errors but got none")
			}
			if !tt.expectsErrors && !errors.IsValid() {
				t.Errorf("Expected no validation errors but got: %v", errors)
			}
		})
	}
}

// TestValidationErrorMethods testa os métodos de erro
func TestValidationErrorMethods(t *testing.T) {
	t.Run("ValidationError.Error()", func(t *testing.T) {
		err := ValidationError{
			Field:   "test_field",
			Message: "test message",
		}
		expected := "test_field: test message"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
	})

	t.Run("ValidationErrors.Error() with multiple errors", func(t *testing.T) {
		errors := ValidationErrors{
			ValidationError{Field: "field1", Message: "message1"},
			ValidationError{Field: "field2", Message: "message2"},
		}
		result := errors.Error()
		if !strings.Contains(result, "field1: message1") {
			t.Error("Expected error string to contain first error")
		}
		if !strings.Contains(result, "field2: message2") {
			t.Error("Expected error string to contain second error")
		}
		if !strings.Contains(result, "; ") {
			t.Error("Expected errors to be separated by '; '")
		}
	})

	t.Run("ValidationErrors.Error() with empty errors", func(t *testing.T) {
		errors := ValidationErrors{}
		if errors.Error() != "" {
			t.Errorf("Expected empty string, got '%s'", errors.Error())
		}
	})

	t.Run("ValidationErrors.IsValid() with errors", func(t *testing.T) {
		errors := ValidationErrors{
			ValidationError{Field: "test", Message: "error"},
		}
		if errors.IsValid() {
			t.Error("Expected IsValid to return false when there are errors")
		}
	})

	t.Run("ValidationErrors.IsValid() without errors", func(t *testing.T) {
		errors := ValidationErrors{}
		if !errors.IsValid() {
			t.Error("Expected IsValid to return true when there are no errors")
		}
	})
}

// TestValidateClientEdgeCases testa casos extremos de ValidateClient
func TestValidateClientEdgeCases(t *testing.T) {
	t.Run("cliente com nome no limite de caracteres", func(t *testing.T) {
		client := &Client{
			Name:   string(make([]byte, 255)),
			Status: "ativo",
		}
		for i := range client.Name {
			client.Name = client.Name[:i] + "a" + client.Name[i+1:]
		}
		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Expected no errors for name with exactly 255 chars, got: %v", errors)
		}
	})

	t.Run("cliente com registration_id no limite", func(t *testing.T) {
		regID := string(make([]byte, 20))
		for i := range regID {
			regID = regID[:i] + "1" + regID[i+1:]
		}
		client := &Client{
			Name:           "Test",
			Status:         "ativo",
			RegistrationID: &regID,
		}
		errors := ValidateClient(client)
		// Deve ter erro porque não é CPF/CNPJ válido, mas não deve ser por tamanho
		hasLengthError := false
		for _, err := range errors {
			if strings.Contains(err.Message, "mais de 20") {
				hasLengthError = true
			}
		}
		if hasLengthError {
			t.Error("Should not have length error for exactly 20 characters")
		}
	})

	t.Run("cliente com nickname no limite", func(t *testing.T) {
		nickname := string(make([]byte, 255))
		for i := range nickname {
			nickname = nickname[:i] + "a" + nickname[i+1:]
		}
		client := &Client{
			Name:     "Test",
			Status:   "ativo",
			Nickname: &nickname,
		}
		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Expected no errors for nickname with exactly 255 chars, got: %v", errors)
		}
	})

	t.Run("cliente com address no limite", func(t *testing.T) {
		address := string(make([]byte, 1000))
		for i := range address {
			address = address[:i] + "a" + address[i+1:]
		}
		client := &Client{
			Name:    "Test",
			Status:  "ativo",
			Address: &address,
		}
		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Expected no errors for address with exactly 1000 chars, got: %v", errors)
		}
	})

	t.Run("cliente com contact_preference válidos em diferentes cases", func(t *testing.T) {
		preferences := []string{"WhatsApp", "EMAIL", "Phone", "SMS", "OUTROS"}
		for _, pref := range preferences {
			client := &Client{
				Name:              "Test",
				Status:            "ativo",
				ContactPreference: &pref,
			}
			errors := ValidateClient(client)
			if !errors.IsValid() {
				t.Errorf("Expected no errors for contact preference '%s', got: %v", pref, errors)
			}
		}
	})

	t.Run("cliente com contact_preference com espaços", func(t *testing.T) {
		pref := "  whatsapp  "
		client := &Client{
			Name:              "Test",
			Status:            "ativo",
			ContactPreference: &pref,
		}
		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Expected no errors for contact preference with spaces, got: %v", errors)
		}
	})
}

// TestNormalizeEmailEdgeCases testa casos extremos de normalização
func TestNormalizeEmailEdgeCases(t *testing.T) {
	t.Run("email apenas com espaços", func(t *testing.T) {
		email := "   "
		result := NormalizeEmail(&email)
		if result != nil {
			t.Errorf("Expected nil for whitespace-only email, got '%v'", result)
		}
	})

	t.Run("email com maiúsculas e espaços", func(t *testing.T) {
		email := "  TEST@EXAMPLE.COM  "
		result := NormalizeEmail(&email)
		if result == nil || *result != "test@example.com" {
			t.Errorf("Expected 'test@example.com', got '%v'", result)
		}
	})
}

// TestNormalizePhoneEdgeCases testa casos extremos de normalização de telefone
func TestNormalizePhoneEdgeCases(t *testing.T) {
	t.Run("telefone apenas com espaços", func(t *testing.T) {
		phone := "   "
		result := NormalizePhone(&phone)
		if result != nil {
			t.Errorf("Expected nil for whitespace-only phone, got '%v'", result)
		}
	})

	t.Run("telefone inválido retorna valor parseado (biblioteca tenta parsear)", func(t *testing.T) {
		phone := "invalid-phone-123"
		result := NormalizePhone(&phone)
		if result == nil {
			t.Error("Expected non-nil result")
		}
		// A biblioteca phonenumbers tenta parsear mesmo valores inválidos
		// então apenas verificamos que retornou algo
	})

	t.Run("telefone com espaços extras", func(t *testing.T) {
		phone := "  +5511987654321  "
		result := NormalizePhone(&phone)
		if result == nil || *result != "+5511987654321" {
			t.Errorf("Expected '+5511987654321', got '%v'", result)
		}
	})
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
			input:    stringPtr("USER@GMAIL.COM"),
			expected: stringPtr("user@gmail.com"),
		},
		{
			name:     "com espaços",
			input:    stringPtr("  user@gmail.com  "),
			expected: stringPtr("user@gmail.com"),
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

// TestValidateClientEmailMaxLength testa email com exatamente 254 e 255+ caracteres
func TestValidateClientEmailMaxLength(t *testing.T) {
	t.Run("email com exatamente 254 caracteres deve ser válido", func(t *testing.T) {
		// Construir email com 254 caracteres: local@domain.com
		// local: 64 chars, @ = 1, domain = 189 chars (185 + ".com") = 254 total
		local := strings.Repeat("a", 64)
		domain := strings.Repeat("b", 185) + ".com"
		email := local + "@" + domain

		if len(email) != 254 {
			t.Fatalf("Email deveria ter 254 chars, tem %d", len(email))
		}

		// Nota: Este teste pode falhar na validação MX, mas não deve falhar no tamanho
		err := ValidateClientEmail(&email)
		if err != nil {
			valErr, ok := err.(ValidationError)
			if ok && strings.Contains(valErr.Message, "mais de 254 caracteres") {
				t.Errorf("Não deveria ter erro de tamanho para 254 caracteres")
			}
		}
	})

	t.Run("email com 255 caracteres deve falhar", func(t *testing.T) {
		local := strings.Repeat("a", 64)
		domain := strings.Repeat("b", 186) + ".com"
		email := local + "@" + domain

		if len(email) != 255 {
			t.Fatalf("Email deveria ter 255 chars, tem %d", len(email))
		}

		err := ValidateClientEmail(&email)
		if err == nil {
			t.Error("Esperava erro para email com 255 caracteres")
		}

		valErr, ok := err.(ValidationError)
		if !ok {
			t.Error("Erro deveria ser ValidationError")
		}

		if !strings.Contains(valErr.Message, "mais de 254 caracteres") {
			t.Errorf("Mensagem de erro incorreta: %s", valErr.Message)
		}
	})

	t.Run("email com 300 caracteres deve falhar", func(t *testing.T) {
		email := strings.Repeat("a", 300) + "@example.com"

		err := ValidateClientEmail(&email)
		if err == nil {
			t.Error("Esperava erro para email com 300 caracteres")
		}

		valErr, ok := err.(ValidationError)
		if !ok {
			t.Error("Erro deveria ser ValidationError")
		}

		if !strings.Contains(valErr.Message, "mais de 254 caracteres") {
			t.Errorf("Mensagem de erro incorreta: %s", valErr.Message)
		}
	})
}

// TestValidateClientEmailDomainWithoutDot testa domínios sem ponto
func TestValidateClientEmailDomainWithoutDot(t *testing.T) {
	testCases := []struct {
		name  string
		email string
	}{
		{"domínio sem ponto", "user@localhost"},
		{"domínio single level", "admin@server"},
		{"domínio sem TLD", "contact@domain"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClientEmail(&tc.email)
			if err == nil {
				t.Errorf("Esperava erro para email '%s' com domínio sem ponto", tc.email)
			}

			valErr, ok := err.(ValidationError)
			if !ok {
				t.Error("Erro deveria ser ValidationError")
			}

			// Aceita tanto erro de formato quanto erro específico de ponto
			if !strings.Contains(valErr.Message, "ponto") && !strings.Contains(valErr.Message, "formato") {
				t.Errorf("Mensagem de erro inesperada: %s", valErr.Message)
			}
		})
	}
}

// TestValidateClientBirthDateEdgeCases testa datas de nascimento inválidas
func TestValidateClientBirthDateEdgeCases(t *testing.T) {
	t.Run("data de nascimento no futuro", func(t *testing.T) {
		futureDate := time.Now().AddDate(1, 0, 0) // 1 ano no futuro
		client := &Client{
			Name:      "Test",
			Status:    "ativo",
			BirthDate: &futureDate,
		}

		errors := ValidateClient(client)
		if errors.IsValid() {
			t.Error("Esperava erro para data de nascimento no futuro")
		}

		found := false
		for _, err := range errors {
			if err.Field == "birth_date" && strings.Contains(err.Message, "futuro") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Erro esperado não encontrado. Erros: %v", errors)
		}
	})

	t.Run("data de nascimento muito antiga", func(t *testing.T) {
		ancientDate := time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
		client := &Client{
			Name:      "Test",
			Status:    "ativo",
			BirthDate: &ancientDate,
		}

		errors := ValidateClient(client)
		if errors.IsValid() {
			t.Error("Esperava erro para data de nascimento muito antiga")
		}

		found := false
		for _, err := range errors {
			if err.Field == "birth_date" && strings.Contains(err.Message, "1900") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Erro esperado não encontrado. Erros: %v", errors)
		}
	})

	t.Run("data de nascimento válida em 1900", func(t *testing.T) {
		validDate := time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)
		client := &Client{
			Name:      "Test",
			Status:    "ativo",
			BirthDate: &validDate,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para data de 1900, mas obteve: %v", errors)
		}
	})

	t.Run("data de nascimento válida hoje", func(t *testing.T) {
		today := time.Now()
		client := &Client{
			Name:      "Test",
			Status:    "ativo",
			BirthDate: &today,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para data de hoje, mas obteve: %v", errors)
		}
	})
}

// TestValidateClientUnicodeAndEmojis testa campos com Unicode e emojis
func TestValidateClientUnicodeAndEmojis(t *testing.T) {
	t.Run("nome com emojis", func(t *testing.T) {
		name := "Empresa 🚀 Tecnologia"
		client := &Client{
			Name:   name,
			Status: "ativo",
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Cliente com nome contendo emojis deveria ser válido, erros: %v", errors)
		}
	})

	t.Run("nome com caracteres unicode variados", func(t *testing.T) {
		name := "Empresa Açúcar é Ñoño 日本語"
		client := &Client{
			Name:   name,
			Status: "ativo",
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Cliente com nome unicode deveria ser válido, erros: %v", errors)
		}
	})

	t.Run("notas com emojis e unicode", func(t *testing.T) {
		notes := "Cliente importante! 💼 Contato preferencial 📞 日本語対応可能"
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Notes:  &notes,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Notas com emojis e unicode deveriam ser válidas, erros: %v", errors)
		}
	})

	t.Run("endereço com caracteres especiais", func(t *testing.T) {
		address := "Rua José da Silva, 123 - Apto 45-B (Edifício São João)"
		client := &Client{
			Name:    "Test",
			Status:  "ativo",
			Address: &address,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Endereço com caracteres especiais deveria ser válido, erros: %v", errors)
		}
	})

	t.Run("nome com limite de caracteres unicode", func(t *testing.T) {
		// Emojis podem ocupar múltiplos bytes
		// Testar se a validação usa bytes ou runes
		emoji := "🚀"
		// Um emoji pode ter 4 bytes em UTF-8
		name := strings.Repeat(emoji, 63) + "Test" // ~252 bytes + 4 = 256

		client := &Client{
			Name:   name,
			Status: "ativo",
		}

		errors := ValidateClient(client)
		// Verificar se a validação é por bytes ou por caracteres
		if len(name) > 255 && errors.IsValid() {
			t.Errorf("Nome com mais de 255 bytes deveria ser inválido")
		}
	})
}

// TestValidateClientTagsWithSpecialCharacters testa tags com caracteres especiais
func TestValidateClientTagsWithSpecialCharacters(t *testing.T) {
	t.Run("tags com vírgulas", func(t *testing.T) {
		tags := "cliente,vip,importante,prioritário"
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Tags:   &tags,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Tags com vírgulas deveriam ser válidas, erros: %v", errors)
		}
	})

	t.Run("tags com ponto e vírgula", func(t *testing.T) {
		tags := "cliente;vip;importante"
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Tags:   &tags,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Tags com ponto-e-vírgula deveriam ser válidas, erros: %v", errors)
		}
	})

	t.Run("tags com quebras de linha", func(t *testing.T) {
		tags := "cliente\nvip\nimportante"
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Tags:   &tags,
		}

		errors := ValidateClient(client)
		// Atualmente não há validação específica para quebras de linha
		// Este teste documenta o comportamento
		_ = errors
	})

	t.Run("tags com caracteres especiais SQL", func(t *testing.T) {
		tags := "'; DROP TABLE clients; --"
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Tags:   &tags,
		}

		errors := ValidateClient(client)
		// Validar que caracteres SQL não causam problemas
		if !errors.IsValid() {
			t.Errorf("Tags com caracteres SQL deveriam ser válidas (proteção deve ser no DB), erros: %v", errors)
		}
	})
}

// TestValidateDependentUnicodeAndEmojis testa dependentes com Unicode
func TestValidateDependentUnicodeAndEmojis(t *testing.T) {
	t.Run("dependente com nome contendo emojis", func(t *testing.T) {
		name := "Filial São Paulo 🏢"
		dependent := &Dependent{
			Name:     name,
			ClientID: "client-123",
			Status:   "ativo",
		}

		errors := ValidateDependent(dependent)
		if !errors.IsValid() {
			t.Errorf("Dependente com nome contendo emojis deveria ser válido, erros: %v", errors)
		}
	})

	t.Run("dependente com descrição multilíngue", func(t *testing.T) {
		description := "Escritório principal - Main Office - 本社 - Oficina Principal"
		dependent := &Dependent{
			Name:        "Test",
			ClientID:    "client-123",
			Status:      "ativo",
			Description: &description,
		}

		errors := ValidateDependent(dependent)
		if !errors.IsValid() {
			t.Errorf("Dependente com descrição multilíngue deveria ser válido, erros: %v", errors)
		}
	})
}

// TestValidateClientNextActionDatePast testa NextActionDate no passado
func TestValidateClientNextActionDatePast(t *testing.T) {
	t.Run("next action date no passado recente deve ser válido", func(t *testing.T) {
		pastDate := time.Now().AddDate(0, -6, 0) // 6 meses atrás
		client := &Client{
			Name:           "Test",
			Status:         "ativo",
			NextActionDate: &pastDate,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para data 6 meses no passado, mas obteve: %v", errors)
		}
	})

	t.Run("next action date mais de 1 ano no passado deve falhar", func(t *testing.T) {
		pastDate := time.Now().AddDate(-2, 0, 0) // 2 anos atrás
		client := &Client{
			Name:           "Test",
			Status:         "ativo",
			NextActionDate: &pastDate,
		}

		errors := ValidateClient(client)
		if errors.IsValid() {
			t.Error("Esperava erro para NextActionDate mais de 1 ano no passado")
		}

		found := false
		for _, err := range errors {
			if err.Field == "next_action_date" && strings.Contains(err.Message, "1 ano no passado") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Erro esperado não encontrado. Erros: %v", errors)
		}
	})

	t.Run("next action date muito no futuro", func(t *testing.T) {
		futureDate := time.Now().AddDate(20, 0, 0) // 20 anos no futuro
		client := &Client{
			Name:           "Test",
			Status:         "ativo",
			NextActionDate: &futureDate,
		}

		errors := ValidateClient(client)
		if errors.IsValid() {
			t.Error("Esperava erro para NextActionDate mais de 10 anos no futuro")
		}

		found := false
		for _, err := range errors {
			if err.Field == "next_action_date" && strings.Contains(err.Message, "10 anos no futuro") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Erro esperado não encontrado. Erros: %v", errors)
		}
	})

	t.Run("next action date válido - 5 anos no futuro", func(t *testing.T) {
		futureDate := time.Now().AddDate(5, 0, 0) // 5 anos no futuro
		client := &Client{
			Name:           "Test",
			Status:         "ativo",
			NextActionDate: &futureDate,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para data 5 anos no futuro, mas obteve: %v", errors)
		}
	})
}

// TestValidateClientNotesOverflow testa overflow em campos de texto
func TestValidateClientNotesOverflow(t *testing.T) {
	t.Run("notes com exatamente 50000 caracteres deve ser válido", func(t *testing.T) {
		notes := strings.Repeat("a", 50000)
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Notes:  &notes,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para notes com 50000 chars, mas obteve: %v", errors)
		}
	})

	t.Run("notes com mais de 50000 caracteres deve falhar", func(t *testing.T) {
		notes := strings.Repeat("a", 50001)
		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Notes:  &notes,
		}

		errors := ValidateClient(client)
		if errors.IsValid() {
			t.Error("Esperava erro para notes com mais de 50000 caracteres")
		}

		found := false
		for _, err := range errors {
			if err.Field == "notes" && strings.Contains(err.Message, "50.000") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Erro esperado não encontrado. Erros: %v", errors)
		}
	})

	t.Run("notes com caracteres unicode ocupando múltiplos bytes", func(t *testing.T) {
		// Caractere que ocupa 3 bytes em UTF-8
		char := "本"
		// Criar string com 16666 caracteres = ~50k bytes
		notes := strings.Repeat(char, 16666)

		client := &Client{
			Name:   "Test",
			Status: "ativo",
			Notes:  &notes,
		}

		errors := ValidateClient(client)
		// Validação é por caracteres, não bytes, então deve ser válido
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para notes com unicode < 50k chars, mas obteve: %v", errors)
		}
	})

	t.Run("documents com exatamente 10000 caracteres deve ser válido", func(t *testing.T) {
		docs := strings.Repeat("a", 10000)
		client := &Client{
			Name:      "Test",
			Status:    "ativo",
			Documents: &docs,
		}

		errors := ValidateClient(client)
		if !errors.IsValid() {
			t.Errorf("Não esperava erro para documents com 10000 chars, mas obteve: %v", errors)
		}
	})

	t.Run("documents com mais de 10000 caracteres deve falhar", func(t *testing.T) {
		longURL := "https://example.com/" + strings.Repeat("a", 10000)
		client := &Client{
			Name:      "Test",
			Status:    "ativo",
			Documents: &longURL,
		}

		errors := ValidateClient(client)
		if errors.IsValid() {
			t.Error("Esperava erro para documents com mais de 10000 caracteres")
		}

		found := false
		for _, err := range errors {
			if err.Field == "documents" && strings.Contains(err.Message, "10.000") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Erro esperado não encontrado. Erros: %v", errors)
		}
	})
}

// TestValidateClientNullVsEmpty testa diferença entre null e vazio
func TestValidateClientNullVsEmpty(t *testing.T) {
	t.Run("email null vs string vazia", func(t *testing.T) {
		empty := ""

		client1 := &Client{
			Name:   "Test 1",
			Status: "ativo",
			Email:  nil,
		}

		client2 := &Client{
			Name:   "Test 2",
			Status: "ativo",
			Email:  &empty,
		}

		errors1 := ValidateClient(client1)
		errors2 := ValidateClient(client2)

		if !errors1.IsValid() {
			t.Errorf("Cliente com email nil deveria ser válido, erros: %v", errors1)
		}

		if !errors2.IsValid() {
			t.Errorf("Cliente com email vazio deveria ser válido, erros: %v", errors2)
		}
	})

	t.Run("phone null vs string vazia vs apenas espaços", func(t *testing.T) {
		empty := ""
		spaces := "   "

		clients := []*Client{
			{Name: "Test 1", Status: "ativo", Phone: nil},
			{Name: "Test 2", Status: "ativo", Phone: &empty},
			{Name: "Test 3", Status: "ativo", Phone: &spaces},
		}

		for i, client := range clients {
			errors := ValidateClient(client)
			if !errors.IsValid() {
				t.Errorf("Cliente %d deveria ser válido, erros: %v", i+1, errors)
			}
		}
	})
}
